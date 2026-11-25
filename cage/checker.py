"""独立检查器：只从磁盘上的实际文件取证，不依赖 cage/ledger 的实现。

为保持独立性，本模块：
- 不 import cage、ledger，自带最小日志状态机（与 ledger.apply_event 同语义，
  但代码独立，便于交叉发现实现偏差）；
- 仅复用 seal 的封签/分帧格式原语与 fsutil 的文件摘要工具；
- 所有结论都重新打开文件计算，而不是采信内存状态。

核对三大类事实：
1. 公开字节：每个公开 pack 重新验封签链、重算摘要，逐字节对账索引与根承诺；
2. 释放余额：重放日志算持有/容量，并与 staging 目录实际字节交叉核对；
3. 历史水位：日志水位检查点单调，且不低于按事件重放出的实际持有峰值。

CLI：python -m cage.checker <采集区根目录>；全部通过退出码 0，否则 1。
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import seal

PACK_NAME = "pack.zlb"
MANIFEST_NAME = "manifest.json"
ROOT_COMMIT_NAME = "root.json"


class CheckError(AssertionError):
    """检查器发现不变量被破坏。"""


def _canonical(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------- 独立日志状态机（不 import ledger） ----------

@dataclass
class _State:
    generation: int = -1
    approved_bytes: int = 0
    revoked: bool = True
    held: int = 0
    watermark: int = 0
    peak_held: int = 0
    public_bytes: int = 0
    batches: dict = field(default_factory=dict)


def _apply(state: _State, event: dict) -> None:
    etype = event["etype"]
    if etype == "approve":
        state.generation = event["generation"]
        state.approved_bytes = event["approved_bytes"]
        state.revoked = False
        state.held = 0
    elif etype == "revoke":
        if event["generation"] == state.generation:
            state.revoked = True
            # 持有额由 abort 事件释放，这里不清零，避免重复扣减。
    elif etype == "stage":
        existing = state.batches.get(event["batch"])
        if existing is None:
            bv = {
                "state": "staged",
                "staged_bytes": event["staged_bytes"],
                "generation": event["generation"],
                "last_digest": event["last_digest"],
            }
            state.batches[event["batch"]] = bv
            delta = event["staged_bytes"]
        else:
            bv = existing
            delta = event["staged_bytes"] - bv["staged_bytes"]
            bv["staged_bytes"] = event["staged_bytes"]
            bv["last_digest"] = event["last_digest"]
        bv["state"] = "staged"
        state.held += delta
        state.peak_held = max(state.peak_held, state.held)
    elif etype == "commit":
        # 与 ledger 状态机同样容忍缺 stage 的恢复情形。
        bv = state.batches.get(event["batch"])
        if bv is None:
            bv = {
                "state": "staged",
                "staged_bytes": event.get("staged_bytes", 0),
                "generation": event["generation"],
                "last_digest": event.get("last_digest", ""),
            }
            state.batches[event["batch"]] = bv
        bv["state"] = "committed"
        state.held -= bv["staged_bytes"]
        if state.held < 0:
            raise CheckError(f"日志事件 {event['id']} 使持有额为负")
        state.public_bytes += event["public_bytes"]
    elif etype == "abort":
        bv = state.batches.get(event["batch"])
        if bv is None:
            bv = {
                "state": "staged",
                "staged_bytes": 0,
                "generation": event.get("generation", state.generation),
                "last_digest": "",
            }
            state.batches[event["batch"]] = bv
        if bv["state"] == "staged":
            state.held -= bv["staged_bytes"]
            if state.held < 0:
                raise CheckError(f"中止事件 {event['id']} 使持有额为负")
        bv["state"] = "aborted"
    elif etype == "watermark":
        if event["watermark_bytes"] < state.held:
            raise CheckError(
                f"水位检查点 {event['watermark_bytes']} 低于当前持有 {state.held}"
            )
        if event["watermark_bytes"] < state.watermark:
            raise CheckError(
                f"历史水位回退：{state.watermark} -> {event['watermark_bytes']}"
            )
        state.watermark = max(state.watermark, event["watermark_bytes"])
    else:
        raise CheckError(f"未知日志事件类型：{etype}")


def _replay(ledger_path: Path) -> _State:
    state = _State()
    if not ledger_path.exists():
        return state
    with open(ledger_path, "rb") as fh:
        for line in fh:
            line = line.strip()
            if line:
                _apply(state, json.loads(line.decode("utf-8")))
    return state


def _dir_commit(pdir: Path, manifest_body: dict) -> str:
    listing = {}
    for name in sorted(p.name for p in pdir.iterdir() if p.is_file()):
        if name != MANIFEST_NAME:
            listing[name] = _sha256_file(pdir / name)
    listing[MANIFEST_NAME] = hashlib.sha256(_canonical(manifest_body)).hexdigest()
    return hashlib.sha256(_canonical(listing)).hexdigest()


def _parse_sealed(path: Path):
    """解析封签 pack，把 seal 层异常统一转成检查器的 CheckError。"""
    try:
        return seal.parse_pack(path)
    except seal.SealError as exc:
        raise CheckError(f"封签核验失败 {path}：{exc}") from exc


def check_cage(root) -> dict:
    """对整个采集区做独立核查，返回报告；任何不变量失败都抛 CheckError。"""
    root = Path(root)
    if not root.exists():
        raise CheckError(f"采集区根目录不存在：{root}")

    # 密钥解析器：按封签头部的租户/设备取实际密钥文件
    def resolve(header: dict) -> bytes:
        key_path = root / "keys" / header["t"] / f"{header['d']}.key"
        if not key_path.exists():
            raise CheckError(f"缺少设备密钥：{key_path}")
        return key_path.read_bytes()

    seal.set_key_resolver(resolve)

    report = {"root": str(root), "devices": {}, "totals": {}}
    seen_index: dict[str, dict] = {}
    total_public = total_staging = 0
    total_approved = total_releasable = total_watermark = 0

    tenants_dir = root / "tenants"
    if not tenants_dir.exists():
        # 全新空采集区：零设备也必须有自洽的根承诺
        root_path = root / "public" / ROOT_COMMIT_NAME
        if root_path.exists():
            root_doc = json.loads(root_path.read_text("utf-8"))
            if root_doc.get("entries") != [] or root_doc.get("root_commit") != \
                    hashlib.sha256(_canonical([])).hexdigest():
                raise CheckError("空采集区根承诺不自洽")
        report["totals"] = {
            "public_bytes": 0, "staging_bytes": 0, "approved_bytes": 0,
            "releasable_balance": 0, "watermark_bytes_max": 0,
            "indexed_batches": 0,
            "root_commit": hashlib.sha256(_canonical([])).hexdigest(),
        }
        return report

    for tenant_dir in sorted(p for p in tenants_dir.iterdir() if p.is_dir()):
        devices_dir = tenant_dir / "devices"
        if not devices_dir.exists():
            continue
        for dev_dir in sorted(p for p in devices_dir.iterdir() if p.is_dir()):
            tenant, device = tenant_dir.name, dev_dir.name
            state = _replay(dev_dir / "ledger.log")

            # ---- 1) 公开字节：逐文件验封签链、清单、目录承诺 ----
            dev_public = 0
            public_root = dev_dir / "public"
            if public_root.exists():
                for pdir in sorted(p for p in public_root.iterdir() if p.is_dir()):
                    pack = pdir / PACK_NAME
                    manifest_path = pdir / MANIFEST_NAME
                    if not pack.exists():
                        raise CheckError(f"公开目录 {pdir} 缺少 {PACK_NAME}")
                    if not manifest_path.exists():
                        raise CheckError(f"公开目录 {pdir} 缺少清单（回执丢失未恢复）")

                    try:
                        with open(pack, "rb") as fh:
                            frames = list(seal.iter_frames(fh))
                    except seal.SealError as exc:
                        raise CheckError(f"公开 pack 封签核验失败 {pack}：{exc}") from exc
                    if not frames:
                        raise CheckError(f"公开 pack 为空：{pack}")
                    last_header = frames[-1][0]
                    if not last_header["f"]:
                        raise CheckError(f"未完成批次竟已公开：{pdir}")
                    if (last_header["t"], last_header["d"], last_header["b"]) != (
                        tenant, device, pdir.name
                    ):
                        raise CheckError(f"公开 pack 归属与目录不符：{pdir}")

                    manifest = json.loads(manifest_path.read_text("utf-8"))
                    if manifest["last_digest"] != last_header["digest"]:
                        raise CheckError(f"清单末段摘要与实际封签不符：{pdir}")
                    if manifest["generation"] != last_header["g"]:
                        raise CheckError(f"清单批准代与封签不符：{pdir}")
                    pack_sha = _sha256_file(pack)
                    if manifest["pack_sha256"] != pack_sha:
                        raise CheckError(f"清单 pack 摘要与实际字节不符：{pdir}")
                    if manifest["pack_bytes"] != pack.stat().st_size:
                        raise CheckError(f"清单 pack 字节数与实际不符：{pdir}")

                    body = {k: v for k, v in manifest.items() if k != "dir_commit"}
                    if _dir_commit(pdir, body) != manifest["dir_commit"]:
                        raise CheckError(f"目录承诺与目录实际内容不符：{pdir}")

                    bv = state.batches.get(pdir.name)
                    if bv is None or bv["state"] != "committed":
                        raise CheckError(f"公开批次在日志中不是 committed：{pdir}")
                    if bv["last_digest"] != last_header["digest"]:
                        raise CheckError(f"日志末段摘要与公开封签不符：{pdir}")

                    seen_index[f"{tenant}/{pdir.name}"] = {
                        "tenant": tenant, "device": device, "batch": pdir.name,
                        "generation": manifest["generation"],
                        "last_digest": manifest["last_digest"],
                        "dir_commit": manifest["dir_commit"],
                        "pack_sha256": pack_sha,
                        "public_bytes": manifest["pack_bytes"],
                    }
                    dev_public += manifest["pack_bytes"]

            # ---- 2) 释放余额：日志持有 vs staging 实际字节 ----
            staging_bytes = 0
            staging_root = dev_dir / "staging"
            if staging_root.exists():
                for sdir in sorted(p for p in staging_root.iterdir() if p.is_dir()):
                    pack = sdir / PACK_NAME
                    if pack.exists():
                        # 暂存封签也必须能独立验过
                        _parse_sealed(pack)
                        staging_bytes += pack.stat().st_size
                        bv = state.batches.get(sdir.name)
                        if bv is None or bv["state"] != "staged":
                            raise CheckError(
                                f"暂存目录 {sdir.name} 在日志中不是 staged"
                            )
            if staging_bytes != state.held:
                raise CheckError(
                    f"设备 {device} 日志持有 {state.held} 与暂存实际 {staging_bytes} 不符"
                )
            releasable = max(0, state.approved_bytes - state.held)
            if state.held > state.approved_bytes and not state.revoked:
                raise CheckError(f"设备 {device} 暂存超过签批容量")

            # ---- 3) 历史水位：检查点不得低于重放峰值 ----
            if state.watermark < state.peak_held:
                raise CheckError(
                    f"设备 {device} 水位 {state.watermark} 低于实际峰值 {state.peak_held}"
                )

            report["devices"][f"{tenant}/{device}"] = {
                "generation": state.generation,
                "approved_bytes": state.approved_bytes,
                "revoked": state.revoked,
                "held_bytes": state.held,
                "staging_bytes_on_disk": staging_bytes,
                "releasable_balance": releasable,
                "watermark_bytes": state.watermark,
                "peak_held_replayed": state.peak_held,
                "public_bytes_ledger": state.public_bytes,
                "public_bytes_on_disk": dev_public,
                "batch_states": {b: v["state"] for b, v in state.batches.items()},
            }
            if state.public_bytes != dev_public:
                raise CheckError(
                    f"设备 {device} 日志公开 {state.public_bytes} 与磁盘 {dev_public} 不符"
                )
            total_public += dev_public
            total_staging += staging_bytes
            total_approved += state.approved_bytes
            total_releasable += releasable
            total_watermark = max(total_watermark, state.watermark)

    # ---- 4) 公开索引与根承诺逐条对账 ----
    index_dir = root / "public" / "index"
    on_disk_index: dict[str, dict] = {}
    if index_dir.exists():
        for fp in sorted(index_dir.glob("*.json")):
            entry = json.loads(fp.read_text("utf-8"))
            on_disk_index[f"{entry['tenant']}/{entry['batch']}"] = entry
    if set(on_disk_index) != set(seen_index):
        raise CheckError(
            f"索引批次集合不符：磁盘 {sorted(on_disk_index)} vs 公开目录 {sorted(seen_index)}"
        )
    for bkey, want in seen_index.items():
        if on_disk_index[bkey] != want:
            raise CheckError(f"索引条目与实际公开文件不符：{bkey}")

    root_path = root / "public" / ROOT_COMMIT_NAME
    if not root_path.exists():
        raise CheckError("缺少根承诺 root.json")
    root_doc = json.loads(root_path.read_text("utf-8"))
    ordered = [seen_index[k] for k in sorted(seen_index)]
    want_commit = hashlib.sha256(_canonical(ordered)).hexdigest()
    if root_doc.get("root_commit") != want_commit:
        raise CheckError("根承诺与实际索引条目重算结果不符")
    if root_doc.get("entries") != ordered:
        raise CheckError("root.json 内 entries 与实际索引不符")

    # ---- 5) 临时目录不得残留 ----
    tmp_dir = root / "tmp"
    if tmp_dir.exists() and any(tmp_dir.iterdir()):
        raise CheckError("tmp 目录存在未清理的残留文件")

    report["totals"] = {
        "public_bytes": total_public,
        "staging_bytes": total_staging,
        "approved_bytes": total_approved,
        "releasable_balance": total_releasable,
        "watermark_bytes_max": total_watermark,
        "indexed_batches": len(seen_index),
        "root_commit": want_commit,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("用法: python -m cage.checker <采集区根目录>", file=sys.stderr)
        return 2
    try:
        report = check_cage(argv[0])
    except CheckError as exc:
        print(f"检查失败: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
    print(f"\n[OK] 全部不变量通过，公开批次 {report['totals']['indexed_batches']} 个")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
