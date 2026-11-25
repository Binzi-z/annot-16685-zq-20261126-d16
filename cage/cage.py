"""本地防泄露采集区核心。

目录布局（root 之下）::

    keys/<tenant>/<device>.key          每设备 HMAC 密钥（本地合成，非真实机密）
    tenants/<tenant>/devices/<device>/
        ledger.log                      该设备追加日志（权威顺序记录）
        staging/<batch>/pack.zlb        暂存的封签分段 pack（按代隔离）
        public/<batch>/pack.zlb         已公开 pack
        public/<batch>/manifest.json    公开批次清单（末段摘要/批准代/目录承诺）
    public/index/<entry>.json           公开索引条目（一提交批次一条）
    public/root.json                    根承诺（全部索引条目的共同承诺）
    tmp/                                原子写临时目录

安全不变量：
1. 未完成（缺最后一段/摘要链断/封签坏）或权限被撤销的批次，绝不进入公开索引。
2. 公开索引只由 commit 日志事件与 public/ 下实际文件对账产生，可整体重建。
3. 暂存字节计入设备持有额；提交或中止后立即释放，水位单调推高。
4. 同一段重投按整段字节去重，序号/前摘要冲突显式报错，不覆盖旧段。

提交协议分三阶段，阶段 B 在设备锁外执行，给“撤销抢先”留下真实竞态窗口：
  A 持锁：封板、流式验封签链与末段、确认权限、登记提交窗口；
  B 锁外：屏障挂钩、流式拷贝、原子改名（撤销可在此窗口抢先落日志）；
  C 重持锁：复核权限，再写清单/索引/日志并释放暂存。

性能/内存：设备状态在内存里随日志事件增量维护（_states），不按分段重放；
权威事实仍在磁盘日志中，独立检查器只认文件、不认这份内存缓存。
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path

from . import fsutil, seal
from .ledger import DeviceLedger, DeviceState, apply_event, replay_ledger

INDEX_DIRNAME = "index"
ROOT_COMMIT_NAME = "root.json"
PACK_NAME = "pack.zlb"
MANIFEST_NAME = "manifest.json"


class CageError(RuntimeError):
    """采集区操作被拒绝（权限、容量、封签、批次状态等）。"""


def _canonical_json(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class _ActiveBatch:
    """进行中的暂存批次：只保留 pack 句柄与很小的链上状态。"""

    batch: str
    generation: int
    fh: object
    staged_bytes: int
    seq: int
    last_digest: str
    final: bool
    seen_frames: dict          # 段键 (代,序号,载荷摘要,末段) -> seq，重投去重
    tenant: str = ""           # 归属租户
    device: str = ""           # 归属设备，供 approve/revoke 精确清理


class Cage:
    """采集区。所有公开操作线程安全；每设备一把可重入锁，租户之间互不阻塞。"""

    def __init__(self, root, *, durable: bool = True):
        self.root = Path(root)
        self.durable = durable
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "tmp").mkdir(exist_ok=True)
        self._dev_locks: dict[str, threading.RLock] = {}
        self._locks_guard = threading.Lock()
        self._active: dict[str, _ActiveBatch] = {}
        self._commit_windows: set[str] = set()
        self._ledgers: dict[str, DeviceLedger] = {}
        self._states: dict[str, DeviceState] = {}
        self._index_lock = threading.Lock()
        self._index_entries: dict[str, dict] = {}
        self._root_commit = ""
        seal.set_key_resolver(self._resolve_key)
        self._recover()

    # ---------- 路径与密钥 ----------

    def _device_dir(self, tenant: str, device: str) -> Path:
        return self.root / "tenants" / tenant / "devices" / device

    def _staging_dir(self, tenant: str, device: str, batch: str) -> Path:
        return self._device_dir(tenant, device) / "staging" / batch

    def _public_dir(self, tenant: str, device: str, batch: str) -> Path:
        return self._device_dir(tenant, device) / "public" / batch

    def _index_dir(self) -> Path:
        return self.root / "public" / INDEX_DIRNAME

    def _key_path(self, tenant: str, device: str) -> Path:
        return self.root / "keys" / tenant / f"{device}.key"

    def _resolve_key(self, header: dict) -> bytes:
        # seal 验签回调：只按头部里的租户/设备取本地密钥。
        return self.load_key(header["t"], header["d"])

    def load_key(self, tenant: str, device: str) -> bytes:
        path = self._key_path(tenant, device)
        if not path.exists():
            raise CageError(f"设备 {tenant}/{device} 未注册（缺少密钥）")
        return path.read_bytes()

    def register_device(self, tenant: str, device: str) -> bytes:
        """注册虚构设备并生成本地 HMAC 密钥（幂等）。"""
        path = self._key_path(tenant, device)
        if path.exists():
            return path.read_bytes()
        path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        fsutil.atomic_write(path, key, durable=self.durable)
        return key

    def _dev_key(self, tenant: str, device: str) -> str:
        """跨租户隔离的设备键：同名设备在不同租户下绝不共享锁/日志/状态。"""
        return f"{tenant}/{device}"

    @staticmethod
    def _segment_key(generation: int, seq: int, payload: bytes, final: bool) -> tuple:
        """逻辑段去重键：同代、同序号、同载荷、同末段标志即视为重投。

        不能用链上 frame 摘要：重投时上一摘要上下文可能已经变化，重算出的
        frame 摘要会不同，但它仍是同一个逻辑分段。
        """
        return generation, seq, hashlib.sha256(payload).hexdigest(), bool(final)

    def _bkey(self, tenant: str, batch: str) -> str:
        """活动批次/提交窗口的租户限定键，杜绝跨租户同名批次碰撞。"""
        return f"{tenant}/{batch}"

    def _owned_active(self, tenant: str, device: str):
        """当前 (租户, 设备) 名下的活动批次 (batch, active)。"""
        for bkey, active in list(self._active.items()):
            if active.tenant == tenant and active.device == device:
                yield active.batch, active

    def _lock_for(self, tenant: str, device: str) -> threading.RLock:
        key = self._dev_key(tenant, device)
        with self._locks_guard:
            lock = self._dev_locks.get(key)
            if lock is None:
                lock = threading.RLock()
                self._dev_locks[key] = lock
            return lock

    def _ledger(self, tenant: str, device: str) -> DeviceLedger:
        key = self._dev_key(tenant, device)
        ledger = self._ledgers.get(key)
        if ledger is None:
            path = self._device_dir(tenant, device) / "ledger.log"
            ledger = DeviceLedger(path, durable=self.durable).open()
            self._ledgers[key] = ledger
        return ledger

    def _record(self, tenant: str, device: str, event: dict) -> dict:
        """落一条日志事件并增量应用到内存状态（唯一的事件写入口）。"""
        recorded = self._ledger(tenant, device).append(event)
        state = self._states.setdefault(self._dev_key(tenant, device),
                                        DeviceState())
        if not state.device:
            state.device, state.tenant = device, tenant
        apply_event(state, recorded)
        return recorded

    def _load_state(self, tenant: str, device: str) -> DeviceState:
        """取内存权威状态；缺失时从磁盘日志重放并缓存。"""
        key = self._dev_key(tenant, device)
        state = self._states.get(key)
        if state is None:
            state = replay_ledger(self._device_dir(tenant, device) / "ledger.log")
            state.device, state.tenant = device, tenant
            self._states[key] = state
        return state

    def close(self) -> None:
        for active in list(self._active.values()):
            active.fh.close()
        self._active.clear()
        for ledger in self._ledgers.values():
            ledger.close()
        self._ledgers.clear()

    def __enter__(self) -> "Cage":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------- 签批与撤销 ----------

    def _abort_all_pending_locked(self, tenant: str, device: str,
                                  reason: str) -> None:
        """中止该设备全部未决批次：既包括内存活动句柄，也覆盖重开后只在
        日志里仍是 staged、磁盘上仍有暂存文件的批次（修复重开后持有与磁盘分叉）。"""
        for _batch, active in self._owned_active(tenant, device):
            self._abort_locked(tenant, device, active.batch, active, reason)
        state = self._load_state(tenant, device)
        for batch, bv in list(state.batches.items()):
            if bv.state != "staged":
                continue
            sdir = self._staging_dir(tenant, device, batch)
            if (sdir / PACK_NAME).exists():
                self._safe_abort_files(tenant, device, batch)
                self._log_abort(tenant, device, batch, reason)

    def approve(self, tenant: str, device: str, approved_bytes: int,
                generation: int | None = None) -> int:
        """按设备签批容量并返回批准代；重签得到新一代，旧代未决批次全部中止。"""
        with self._lock_for(tenant, device):
            self.load_key(tenant, device)  # 未注册直接拒绝
            state = self._load_state(tenant, device)
            new_gen = state.generation + 1 if generation is None else generation
            self._abort_all_pending_locked(tenant, device,
                                           "重新签批，旧代未决批次中止")
            self._record(tenant, device, {
                "etype": "approve", "tenant": tenant, "device": device,
                "generation": new_gen, "approved_bytes": approved_bytes,
            })
            self._append_watermark_locked(tenant, device)
            return new_gen

    def revoke(self, tenant: str, device: str) -> None:
        """撤销当前批准代：进行中批次立即中止并释放暂存，公开过的不受影响。"""
        with self._lock_for(tenant, device):
            state = self._load_state(tenant, device)
            if state.revoked:
                return
            self._abort_all_pending_locked(tenant, device, "权限撤销")
            self._record(tenant, device, {
                "etype": "revoke", "tenant": tenant, "device": device,
                "generation": state.generation,
            })
            self._append_watermark_locked(tenant, device)

    # ---------- 暂存（含重投去重） ----------

    def ingest(self, tenant: str, device: str, batch: str, seq: int, final: bool,
               payload: bytes, *, auto_commit: bool = False,
               hooks: dict | None = None) -> dict:
        """暂存一个封签分段。返回 {status: duplicate|staged|committed, ...}。

        首段必须 seq=0；每段可能重投，同 frame 重投返回 duplicate。
        auto_commit=True 时，收到最后一段即按提交协议公开，工作内存有界。
        """
        key = self.load_key(tenant, device)
        bkey = self._bkey(tenant, batch)
        if not batch.startswith(f"{device}#"):
            raise CageError(
                f"批次名必须以 '{device}#' 开头以保证设备归属，收到：{batch}"
            )
        need_commit = False
        with self._lock_for(tenant, device):
            if bkey in self._commit_windows:
                raise CageError(f"批次 {batch} 正在提交窗口中，暂拒新分段")
            state = self._load_state(tenant, device)
            if state.revoked:
                raise CageError(f"设备 {device} 当前批准代已撤销，拒绝写入")
            active = self._active.get(bkey)
            if active is None:
                if seq != 0:
                    raise CageError(f"批次 {batch} 首段必须是 seq=0")
                active = self._open_batch(tenant, device, batch, state.generation)
            elif active.final:
                raise CageError(
                    f"批次 {batch} 已写入最后一段并封板，拒绝续写（请新建批次）"
                )
            if active.generation != state.generation:
                raise CageError(
                    f"批次 {batch} 属于旧批准代 {active.generation}，"
                    f"当前代为 {state.generation}"
                )

            seg_key = self._segment_key(active.generation, seq, payload, final)
            if seg_key in active.seen_frames:
                return {"status": "duplicate", "batch": batch, "seq": seq,
                        "staged_bytes": active.staged_bytes}
            if seq != active.seq:
                raise CageError(
                    f"批次 {batch} 序号冲突：期望 {active.seq}，收到 {seq}（重投需与原段一致）"
                )

            prev_hex = active.last_digest
            frame, header = seal.make_segment(
                tenant=tenant, device=device, batch=batch,
                generation=active.generation, seq=seq, final=final,
                prev_digest_hex=prev_hex, payload=payload, key=key,
            )
            if header["p"] != active.last_digest:
                raise CageError(f"批次 {batch} 序号 {seq} 上一段摘要不符")

            # 容量校验：按设备全部进行中批次合计，不得超过签批容量。
            # 未到末段的批次尚未写 stage 日志，其字节只在各 _ActiveBatch 里，
            # 因此这里汇总活动暂存而不是只看 state.held_bytes。
            other_held = sum(
                a.staged_bytes
                for bk, a in self._active.items()
                if a.tenant == tenant and a.device == device and bk != bkey
            )
            projected_device = other_held + active.staged_bytes + len(frame)
            if projected_device > state.approved_bytes:
                raise CageError(
                    f"设备 {device} 容量超限：合计暂存 {projected_device} "
                    f"> 签批 {state.approved_bytes}"
                )

            new_total = active.staged_bytes + len(frame)
            active.fh.write(frame)
            if self.durable:
                fsutil.fsync_file(active.fh)
            active.staged_bytes = new_total
            active.seq = seq + 1
            active.last_digest = header["digest"]
            active.final = final
            active.seen_frames[seg_key] = seq

            result = {"status": "staged", "batch": batch, "seq": seq,
                      "digest": header["digest"], "staged_bytes": new_total,
                      "compressed_bytes": len(frame),
                      "input_bytes": len(payload)}
            if final:
                self._flush_batch_locked(tenant, device, active)
            need_commit = final and auto_commit
        # 末段已封板；在设备锁外进入提交协议，与显式 commit 走同一条路径，
        # 阶段 B 的撤销抢先窗口对 auto_commit 同样真实存在。
        if need_commit:
            self.commit(tenant, device, batch, hooks or {})
            result["status"] = "committed"
        return result

    def _open_batch(self, tenant: str, device: str, batch: str,
                    generation: int) -> _ActiveBatch:
        sdir = self._staging_dir(tenant, device, batch)
        sdir.mkdir(parents=True, exist_ok=True)
        pack = sdir / PACK_NAME
        if pack.exists():
            # 崩溃后重新打开：流式重放已暂存帧，重建链上状态与去重集合。
            seen: dict[str, int] = {}
            staged = pack.stat().st_size
            last = seal.ZERO_PREV
            next_seq = 0
            final = False
            for header, payload in seal.parse_pack(pack):
                if header["g"] != generation:
                    raise CageError(f"暂存 {batch} 批准代不一致，拒绝续写")
                seen[self._segment_key(header["g"], header["s"], payload,
                                       header["f"])] = header["s"]
                last = header["digest"]
                next_seq = header["s"] + 1
                final = header["f"]
            fh = open(pack, "ab")
        else:
            seen, staged, last, next_seq, final = {}, 0, seal.ZERO_PREV, 0, False
            fh = open(pack, "wb")
        active = _ActiveBatch(batch, generation, fh, staged, next_seq,
                              last, final, seen, tenant=tenant, device=device)
        self._active[self._bkey(tenant, batch)] = active
        return active

    def _flush_batch_locked(self, tenant: str, device: str,
                            active: _ActiveBatch) -> None:
        """末段落盘后写 stage 日志并推高水位（此时仍只是暂存，未公开）。"""
        active.fh.flush()
        if self.durable:
            fsutil.fsync_file(active.fh)
            fsutil.sync_dir(Path(active.fh.name).parent)
        self._record(tenant, device, {
            "etype": "stage", "tenant": tenant, "device": device,
            "batch": active.batch, "generation": active.generation,
            "staged_bytes": active.staged_bytes,
            "last_digest": active.last_digest, "final": active.final,
        })
        self._append_watermark_locked(tenant, device)

    # ---------- 提交协议（公开承诺，三阶段） ----------

    def commit(self, tenant: str, device: str, batch: str,
               hooks: dict | None = None) -> dict:
        """分阶段公开一个完整批次，详见模块 docstring。"""
        hooks = hooks or {}
        lock = self._lock_for(tenant, device)
        bkey = self._bkey(tenant, batch)

        # ---- 阶段 A：持锁验证并封板 ----
        with lock:
            if bkey in self._commit_windows:
                raise CageError(f"批次 {batch} 已在提交窗口中")
            state = self._load_state(tenant, device)
            active = self._active.pop(bkey, None)
            if active is not None:
                active.fh.close()
            staged_pack = self._staging_dir(tenant, device, batch) / PACK_NAME
            if not staged_pack.exists():
                raise CageError(f"批次 {batch} 没有可提交的暂存内容")

            # 挂钩点 1（锁内）：验证前，测试用它损坏末段制造摘要不符
            self._invoke_hook(hooks, "on_verify", tenant, device, batch, staged_pack)

            if state.revoked or (active is not None
                                 and active.generation != state.generation):
                self._safe_abort_files(tenant, device, batch)
                self._log_abort(tenant, device, batch, "提交时权限已撤销/批准代失效")
                raise CageError(f"批次 {batch} 权限被撤销，拒绝公开")

            try:
                last_header, count = self._verify_pack(
                    staged_pack, tenant, device, batch, state.generation
                )
            except seal.SealError as exc:
                self._safe_abort_files(tenant, device, batch)
                self._log_abort(tenant, device, batch, f"封签/摘要核验失败：{exc}")
                raise CageError(f"批次 {batch} 核验失败：{exc}") from exc
            if last_header is None or not last_header["f"]:
                self._safe_abort_files(tenant, device, batch)
                self._log_abort(tenant, device, batch, "批次未完成（缺最后一段）")
                raise CageError(f"批次 {batch} 未完成，不得公开")

            pdir = self._public_dir(tenant, device, batch)
            pdir.mkdir(parents=True, exist_ok=True)
            public_pack = pdir / PACK_NAME
            # 临时名带租户限定键，避免跨租户同名设备/批次在 tmp/ 碰撞
            tmp_pack = self.root / "tmp" / f"{bkey.replace('/', '_')}.pack.tmp"
            generation = state.generation
            self._commit_windows.add(bkey)

        # ---- 阶段 B：锁外。屏障挂钩与撤销可在此窗口真实抢先 ----
        try:
            # 挂钩点 2（锁外）：拷贝前，测试在此与撤销线程屏障同步
            self._invoke_hook(hooks, "on_before_copy", tenant, device, batch, staged_pack)
            if not staged_pack.exists():
                # 撤销线程已在窗口内清掉暂存：转成受控的 CageError 而非裸 OSError
                with lock:
                    self._commit_windows.discard(bkey)
                self._discard_public_dir(pdir)
                raise CageError(f"批次 {batch} 暂存已被撤销清理，提交中止")
            with open(staged_pack, "rb") as src, open(tmp_pack, "wb") as dst:
                for chunk in iter(lambda: src.read(64 * 1024), b""):
                    dst.write(chunk)
                if self.durable:
                    fsutil.fsync_file(dst)
            fsutil.durable_rename(tmp_pack, public_pack, durable=self.durable)

            # 挂钩点 3（锁外）：公开 pack 已落盘、清单未写
            self._invoke_hook(hooks, "on_after_copy", tenant, device, batch, public_pack)
        except BaseException:
            # 崩溃/挂钩异常：清掉可能残留的 tmp 与公开目录，避免空壳进入检查
            fsutil.durable_unlink(tmp_pack, durable=False)
            self._discard_public_dir(pdir)
            with lock:
                self._commit_windows.discard(bkey)
            raise

        # ---- 阶段 C：重持锁，复核权限后落盘承诺 ----
        with lock:
            try:
                state = self._load_state(tenant, device)
                if state.revoked or generation != state.generation:
                    # 撤销抢先成功：撤下已拷贝的公开文件，整批中止，绝不进索引
                    fsutil.durable_unlink(public_pack, durable=self.durable)
                    self._discard_public_dir(pdir)
                    self._safe_abort_files(tenant, device, batch)
                    self._log_abort(tenant, device, batch,
                                    "拷贝后复核发现权限被撤销/批准代失效")
                    raise CageError(f"批次 {batch} 权限被撤销，拒绝公开")

                manifest_body = self._manifest_body(
                    tenant, device, batch, generation, count,
                    last_header["digest"], public_pack,
                )
                dir_commit = self._directory_commit(pdir, manifest_body)
                manifest = dict(manifest_body)
                manifest["dir_commit"] = dir_commit
                fsutil.atomic_write(pdir / MANIFEST_NAME,
                                    _canonical_json(manifest), durable=self.durable)
                fsutil.sync_dir(pdir)

                # 挂钩点 4（锁内、目录已落盘）：模拟回执丢失——抛异常即崩溃语义
                self._invoke_hook(hooks, "on_after_dir_sync",
                                  tenant, device, batch, pdir)

                staged_bytes = staged_pack.stat().st_size
                entry = {
                    "tenant": tenant, "device": device, "batch": batch,
                    "generation": generation,
                    "last_digest": last_header["digest"],
                    "dir_commit": dir_commit,
                    "pack_sha256": manifest["pack_sha256"],
                    "public_bytes": manifest["pack_bytes"],
                }
                with self._index_lock:
                    if bkey not in self._index_entries:
                        self._index_entries[bkey] = entry
                        self._write_index_entry(entry)
                        self._refresh_root_commit()
                self._record(tenant, device, {
                    "etype": "commit", "tenant": tenant, "device": device,
                    "batch": batch, "generation": generation,
                    "staged_bytes": staged_bytes,
                    "public_bytes": manifest["pack_bytes"],
                    "dir_commit": dir_commit,
                    "last_digest": last_header["digest"],
                })
                fsutil.durable_unlink(staged_pack, durable=self.durable)
                try:
                    staged_pack.parent.rmdir()
                except OSError:
                    pass
                self._append_watermark_locked(tenant, device)
                return {"status": "committed", "batch": batch, "segments": count,
                        "public_bytes": manifest["pack_bytes"],
                        "staged_bytes_freed": staged_bytes,
                        "dir_commit": dir_commit,
                        "last_digest": last_header["digest"]}
            finally:
                self._commit_windows.discard(bkey)

    def _verify_pack(self, staged_pack: Path, tenant: str, device: str,
                     batch: str, generation: int):
        """流式核验整个 pack：封签、摘要链、序号、归属、末段标志。"""
        last_header = None
        count = 0
        with open(staged_pack, "rb") as fh:
            for header, _payload in seal.iter_frames(fh):
                if (header["t"], header["d"], header["b"]) != (tenant, device, batch):
                    raise CageError(f"批次 {batch} 内含归属不符的分段")
                if header["g"] != generation:
                    raise CageError(f"批次 {batch} 批准代 {header['g']} 已失效")
                last_header, count = header, count + 1
        return last_header, count

    def _manifest_body(self, tenant: str, device: str, batch: str,
                       generation: int, count: int, last_digest: str,
                       public_pack: Path) -> dict:
        """清单主体（不含 dir_commit）：目录承诺对其规范字节求摘要。"""
        return {
            "tenant": tenant,
            "device": device,
            "batch": batch,
            "generation": generation,
            "segments": count,
            "last_digest": last_digest,
            "pack_sha256": _sha256_file(public_pack),
            "pack_bytes": public_pack.stat().st_size,
        }

    def _directory_commit(self, pdir: Path, manifest_body: dict) -> str:
        """目录承诺 = sha256( 目录下每个文件名:文件摘要 的规范 JSON )。

        manifest 此时尚未写入，先把其（不含 dir_commit 的）主体摘要纳入，
        保证清单与目录承诺自洽且无循环引用。
        """
        listing = {}
        for name in sorted(os.listdir(pdir)):
            fp = pdir / name
            if fp.is_file():
                listing[name] = _sha256_file(fp)
        listing[MANIFEST_NAME] = hashlib.sha256(
            _canonical_json(manifest_body)
        ).hexdigest()
        return hashlib.sha256(_canonical_json(listing)).hexdigest()

    def _index_file_name(self, entry: dict) -> str:
        """索引文件名含租户与 bkey 哈希，可读且杜绝清洗后跨租户碰撞。"""
        bkey = f"{entry['tenant']}/{entry['batch']}"
        safe_tenant = entry["tenant"].replace("/", "_")
        safe_batch = entry["batch"].replace("/", "_")
        suffix = hashlib.sha256(bkey.encode("utf-8")).hexdigest()[:8]
        return f"{safe_tenant}__{safe_batch}__{suffix}.json"

    def _write_index_entry(self, entry: dict) -> None:
        self._index_dir().mkdir(parents=True, exist_ok=True)
        fsutil.atomic_write(
            self._index_dir() / self._index_file_name(entry),
            _canonical_json(entry), durable=self.durable,
        )

    def _refresh_root_commit(self) -> None:
        """根承诺：对全部索引条目（按批次排序）的规范字节求摘要。"""
        ordered = [self._index_entries[k] for k in sorted(self._index_entries)]
        root = {
            "entries": ordered,
            "root_commit": hashlib.sha256(_canonical_json(ordered)).hexdigest(),
        }
        self._root_commit = root["root_commit"]
        fsutil.atomic_write(self.root / "public" / ROOT_COMMIT_NAME,
                            _canonical_json(root), durable=self.durable)

    def abort(self, tenant: str, device: str, batch: str,
              reason: str = "显式中止") -> None:
        """中止未完成批次：丢弃暂存、释放持有额，绝不写公开索引。"""
        bkey = self._bkey(tenant, batch)
        with self._lock_for(tenant, device):
            active = self._active.pop(bkey, None)
            if active is not None:
                self._abort_locked(tenant, device, batch, active, reason)
            elif (self._staging_dir(tenant, device, batch) / PACK_NAME).exists():
                self._safe_abort_files(tenant, device, batch)
                self._log_abort(tenant, device, batch, reason)

    def _abort_locked(self, tenant: str, device: str, batch: str,
                      active: _ActiveBatch, reason: str) -> None:
        active.fh.close()
        self._safe_abort_files(tenant, device, batch)
        self._log_abort(tenant, device, batch, reason)

    def _safe_abort_files(self, tenant: str, device: str, batch: str) -> None:
        sdir = self._staging_dir(tenant, device, batch)
        pack = sdir / PACK_NAME
        fsutil.durable_unlink(pack, durable=self.durable)
        try:
            sdir.rmdir()
        except OSError:
            pass

    def _discard_public_dir(self, pdir: Path) -> None:
        """删除未完成公开的空壳目录（pack 已先行 unlink）。"""
        for child in list(pdir.glob("*")):
            if child.is_file():
                fsutil.durable_unlink(child, durable=self.durable)
        try:
            pdir.rmdir()
        except OSError:
            pass

    def _log_abort(self, tenant: str, device: str, batch: str, reason: str) -> None:
        self._record(tenant, device, {
            "etype": "abort", "tenant": tenant, "device": device,
            "batch": batch, "reason": reason,
        })
        self._append_watermark_locked(tenant, device)

    def _append_watermark_locked(self, tenant: str, device: str) -> None:
        state = self._load_state(tenant, device)
        self._record(tenant, device, {
            "etype": "watermark", "tenant": tenant, "device": device,
            "watermark_bytes": max(state.watermark_bytes, state.held_bytes),
        })

    @staticmethod
    def _invoke_hook(hooks: dict, name: str, *args) -> None:
        hook = hooks.get(name)
        if hook is not None:
            hook(*args)

    # ---------- 状态读取 ----------

    def stats(self, tenant: str, device: str) -> dict:
        """从内存权威状态读取：容量、释放余额、水位、公开字节。"""
        with self._lock_for(tenant, device):
            state = self._load_state(tenant, device)
            return {
                "tenant": tenant, "device": device,
                "generation": state.generation,
                "approved_bytes": state.approved_bytes,
                "revoked": state.revoked,
                "held_bytes": state.held_bytes,
                "releasable_balance": state.releasable_balance,
                "watermark_bytes": state.watermark_bytes,
                "public_bytes": state.public_bytes,
                "batches": {b: v.state for b, v in state.batches.items()},
            }

    def root_commit(self) -> str:
        with self._index_lock:
            return self._root_commit

    def index_snapshot(self) -> list[dict]:
        with self._index_lock:
            return [self._index_entries[k] for k in sorted(self._index_entries)]

    def index_batch_names(self) -> set[str]:
        """返回已公开批次名集合（值即批次名，跨租户由条目内 tenant 区分）。"""
        with self._index_lock:
            return {entry["batch"] for entry in self._index_entries.values()}

    # ---------- 崩溃恢复与对账 ----------

    def _recover(self) -> None:
        """打开即恢复：以日志为权威，扫描实际文件对账，重建索引与根承诺。

        - public 有 pack 但无索引/清单：补写（回执丢失场景），并清掉对应暂存；
        - staging 有 pack 但日志显示撤销/失效/损坏：中止且不公开；
        - tmp 残留：直接清除。
        """
        tmp = self.root / "tmp"
        if tmp.exists():
            for fp in tmp.iterdir():
                fp.unlink()

        entries: dict[str, dict] = {}
        tenants_dir = self.root / "tenants"
        if not tenants_dir.exists():
            self._refresh_root_commit()
            return

        for tenant_dir in sorted(tenants_dir.iterdir()):
            if not tenant_dir.is_dir():
                continue
            dev_root = tenant_dir / "devices"
            if not dev_root.exists():
                continue
            for dev_dir in sorted(dev_root.iterdir()):
                if not dev_dir.is_dir():
                    continue
                tenant, device = tenant_dir.name, dev_dir.name
                state = replay_ledger(dev_dir / "ledger.log")
                state.device, state.tenant = device, tenant
                self._states[self._dev_key(tenant, device)] = state
                self._recover_device(tenant, device, dev_dir, state, entries)

        self._index_entries = entries
        if entries:
            self._index_dir().mkdir(parents=True, exist_ok=True)
            for entry in entries.values():
                self._write_index_entry(entry)
        self._refresh_root_commit()

    def _recover_device(self, tenant: str, device: str, dev_dir: Path,
                        state: DeviceState, entries: dict) -> None:
        staging_root = dev_dir / "staging"
        public_root = dev_dir / "public"

        # 打开时的权威快照：恢复中补 commit 会改变 state，故先固定撤销态/代/中止集
        open_revoked = state.revoked
        open_generation = state.generation
        aborted_batches = {b for b, v in state.batches.items()
                           if v.state == "aborted"}

        # 1) 公开目录对账：有 pack 就必须能补出 manifest 与索引；
        #    但撤销/失效代/已中止批次的公开残留必须删除，绝不复活进索引。
        if public_root.exists():
            for pdir in sorted(public_root.iterdir()):
                pack = pdir / PACK_NAME
                if not pdir.is_dir() or not pack.exists():
                    continue
                batch = pdir.name
                try:
                    with open(pack, "rb") as fh:
                        frames = list(seal.iter_frames(fh))
                    if not frames:
                        raise seal.SealError("空公开 pack")
                    last_header = frames[-1][0]
                except seal.SealError:
                    self._discard_public_dir(pdir)
                    self._log_abort(tenant, device, batch,
                                    "恢复时发现封签损坏的公开残留，已删除")
                    continue

                forbidden = (
                    open_revoked
                    or last_header["g"] != open_generation
                    or batch in aborted_batches
                )
                if forbidden:
                    # 头号不变量：撤销/旧代/已中止批次绝不进入公开索引
                    self._discard_public_dir(pdir)
                    bv = self._load_state(tenant, device).batches.get(batch)
                    if bv is not None and bv.state == "staged":
                        self._safe_abort_files(tenant, device, batch)
                        self._log_abort(tenant, device, batch,
                                        "恢复时拒绝复活撤销/失效/已中止批次")
                    continue

                bv = self._load_state(tenant, device).batches.get(batch)
                manifest_body = self._manifest_body(
                    tenant, device, batch, last_header["g"], len(frames),
                    last_header["digest"], pack,
                )
                dir_commit = self._recompute_dir_commit(pdir, manifest_body)
                manifest = dict(manifest_body)
                manifest["dir_commit"] = dir_commit
                manifest_path = pdir / MANIFEST_NAME
                if not manifest_path.exists() or json.loads(
                    manifest_path.read_text("utf-8")
                ).get("dir_commit") != dir_commit:
                    fsutil.atomic_write(manifest_path, _canonical_json(manifest),
                                        durable=self.durable)
                if bv is None or bv.state != "committed":
                    # 回执丢失：补 commit 日志并移除对应暂存，状态机随之释放持有。
                    self._record(tenant, device, {
                        "etype": "commit", "tenant": tenant, "device": device,
                        "batch": batch, "generation": last_header["g"],
                        "staged_bytes": pack.stat().st_size,
                        "public_bytes": manifest["pack_bytes"],
                        "dir_commit": dir_commit,
                        "last_digest": last_header["digest"],
                    })
                    self._safe_abort_files(tenant, device, batch)
                entries[self._bkey(tenant, batch)] = {
                    "tenant": tenant, "device": device, "batch": batch,
                    "generation": last_header["g"],
                    "last_digest": last_header["digest"],
                    "dir_commit": dir_commit,
                    "pack_sha256": manifest["pack_sha256"],
                    "public_bytes": manifest["pack_bytes"],
                }

        # 2) 暂存目录对账：撤销/失效代/损坏的批次一律中止；完好的保留可续写
        if staging_root.exists():
            for sdir in sorted(staging_root.iterdir()):
                pack = sdir / PACK_NAME
                if not sdir.is_dir() or not pack.exists():
                    continue
                batch = sdir.name
                state = self._load_state(tenant, device)
                bv = state.batches.get(batch)
                bad = state.revoked
                if not bad:
                    try:
                        frames = seal.parse_pack(pack)
                        if not frames:
                            bad = True
                        elif frames[-1][0]["g"] != state.generation:
                            bad = True  # 失效批准代的残留
                        elif not frames[-1][0]["f"]:
                            bad = True  # 中断时未写完末段的批次：恢复即中止
                    except seal.SealError:
                        bad = True       # 封签/摘要链损坏，绝不允许公开
                if bad:
                    self._safe_abort_files(tenant, device, batch)
                    if bv is not None and bv.state == "staged":
                        self._log_abort(tenant, device, batch,
                                        "恢复时发现撤销/失效/损坏/未完成的暂存批次")
                    else:
                        self._log_abort(tenant, device, batch,
                                        "恢复时清理无日志暂存批次")
                # 完好且属于当前代、末段已齐的暂存保留：可显式 commit 或续写
        self._append_watermark_locked(tenant, device)

    def _recompute_dir_commit(self, pdir: Path, manifest_body: dict) -> str:
        """恢复路径：清单主体已确定，直接按实际文件重算目录承诺。"""
        listing = {}
        for name in sorted(os.listdir(pdir)):
            fp = pdir / name
            if fp.is_file() and name != MANIFEST_NAME:
                listing[name] = _sha256_file(fp)
        listing[MANIFEST_NAME] = hashlib.sha256(
            _canonical_json(manifest_body)
        ).hexdigest()
        return hashlib.sha256(_canonical_json(listing)).hexdigest()
