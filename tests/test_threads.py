"""双工作线程 + 屏障的确定性故障场景测试。

三个场景对应题面要求，全部用 threading.Barrier 制造确定时序，而非 sleep 碰运气：

1. 撤销抢先：提交线程在锁外阶段 B 的屏障处与撤销线程会合，撤销先落日志，
   提交线程阶段 C 复核失败，批次绝不进公开索引。
2. 末段摘要不符：损坏线程在验证前屏障会合后翻转末段压缩载荷字节，
   封签链的摘要核验抛错，批次被中止且不公开。
3. 目录已落盘回执丢失：清单与目录落盘后、索引回执写入前抛异常模拟崩溃，
   重新打开采集区后由恢复逻辑补全索引并释放暂存。

每个场景都有一个无关租户（tenant-b）并发推进，最终必须出现在公开索引里。
"""

from __future__ import annotations

import threading
import unittest
from pathlib import Path
import tempfile

from cage.cage import Cage, CageError
from cage import checker, seal

TENANT_A, DEV_A = "tenant-a", "dev-a"
TENANT_B, DEV_B = "tenant-b", "dev-b"
BATCH_A = f"{DEV_A}#b0000"
BATCH_B = f"{DEV_B}#b0000"
CAPACITY = 64 * 1024


class ReceiptLost(RuntimeError):
    """模拟“目录已落盘但回执丢失”的崩溃信号。"""


def _payload(tag: str) -> bytes:
    return (f"reading-{tag}-".encode() * 4)


def stage_complete_batch(cage: Cage, batch: str = BATCH_A,
                         tenant: str = TENANT_A, device: str = DEV_A,
                         n: int = 3) -> None:
    for i in range(n):
        cage.ingest(tenant, device, batch, i, i == n - 1,
                    _payload(f"{batch}-{i}"))


def run_unrelated_tenant(cage: Cage, errors: list) -> None:
    """无关租户在同一线程安全采集区上独立注册/签批/暂存/提交。

    复用同一 Cage 实例（每设备一把锁），避免多实例双写同一目录；
    设备不同因而与故障租户互不阻塞。
    """
    try:
        cage.register_device(TENANT_B, DEV_B)
        cage.approve(TENANT_B, DEV_B, CAPACITY)
        for i in range(2):
            cage.ingest(TENANT_B, DEV_B, BATCH_B, i, i == 1,
                        _payload(f"{BATCH_B}-{i}"))
        cage.commit(TENANT_B, DEV_B, BATCH_B)
    except BaseException as exc:  # noqa: BLE001 - 线程内异常回传主线程
        errors.append(exc)


def flip_last_frame_payload(pack_path: Path) -> None:
    """翻转最后一帧压缩载荷区的一个字节，使重算摘要与头部摘要不符。

    按分帧的长度字段逐帧推进，而不是在字节流里找 MAGIC——压缩载荷可能
    偶然包含 b"CSG1"，靠搜索会定位错帧。
    """
    data = pack_path.read_bytes()
    pos = 0
    last_payload_start = -1
    last_payload_len = 0
    while pos < len(data):
        assert data[pos:pos + 4] == seal.MAGIC
        header_len = int.from_bytes(data[pos + 4:pos + 8], "big")
        plen_off = pos + 8 + header_len
        payload_len = int.from_bytes(data[plen_off:plen_off + 8], "big")
        last_payload_start = plen_off + 8
        last_payload_len = payload_len
        pos = last_payload_start + payload_len + seal.DIGEST_BYTES
    assert last_payload_len > 3
    blob = bytearray(data)
    blob[last_payload_start + 2] ^= 0xFF
    pack_path.write_bytes(bytes(blob))


class ThreadFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="cage-thread-"))
        self.cage = Cage(self.root, durable=True)
        self.cage.register_device(TENANT_A, DEV_A)
        self.cage.approve(TENANT_A, DEV_A, CAPACITY)
        self.errors: list[BaseException] = []

    def tearDown(self) -> None:
        self.cage.close()
        # 每个场景结束后采集区都必须通过独立检查器，且无关租户已公开
        checker.check_cage(self.root)
        self.assertIn(BATCH_B, self._index_batches())

    def _index_batches(self) -> set[str]:
        idx = self.root / "public" / "index"
        if not idx.exists():
            return set()
        import json
        return {json.loads(p.read_text("utf-8"))["batch"]
                for p in idx.glob("*.json")}

    # ---- 场景 1：撤销抢先 ----

    def test_revocation_races_ahead_of_commit(self) -> None:
        stage_complete_batch(self.cage)
        barrier = threading.Barrier(2)
        revoked_done = threading.Event()

        def on_before_copy(tenant, device, batch, staged_pack):
            # 阶段 B：已释放设备锁，与撤销线程屏障会合
            barrier.wait(timeout=10)
            self.assertTrue(revoked_done.wait(timeout=10),
                            "撤销线程未能在窗口内完成")

        def committer():
            try:
                self.cage.commit(TENANT_A, DEV_A, BATCH_A,
                                 hooks={"on_before_copy": on_before_copy})
                self.errors.append(AssertionError("撤销抢先下不应提交成功"))
            except CageError:
                pass
            except BaseException as exc:  # noqa: BLE001
                self.errors.append(exc)

        def revoker():
            barrier.wait(timeout=10)
            self.cage.revoke(TENANT_A, DEV_A)
            revoked_done.set()
            run_unrelated_tenant(self.cage, self.errors)

        t1 = threading.Thread(target=committer, name="committer")
        t2 = threading.Thread(target=revoker, name="revoker")
        t1.start(); t2.start(); t1.join(15); t2.join(15)
        self.assertFalse(t1.is_alive() or t2.is_alive(), "线程未在时限内结束")
        self.assertEqual(self.errors, [])

        # 被撤销批次绝不在公开索引，也没有残留公开/暂存文件
        self.assertNotIn(BATCH_A, self._index_batches())
        self.assertFalse(
            (self.root / "tenants" / TENANT_A / "devices" / DEV_A /
             "public" / BATCH_A).exists()
        )
        stats = self.cage.stats(TENANT_A, DEV_A)
        self.assertTrue(stats["revoked"])
        self.assertEqual(stats["held_bytes"], 0)
        # 无关租户正常推进
        self.assertIn(BATCH_B, self._index_batches())

    # ---- 场景 2：末段摘要不符 ----

    def test_final_segment_digest_mismatch_blocks_publication(self) -> None:
        stage_complete_batch(self.cage)
        barrier = threading.Barrier(2)
        corrupted = threading.Event()
        staged_pack = (self.root / "tenants" / TENANT_A / "devices" / DEV_A /
                       "staging" / BATCH_A / "pack.zlb")

        def on_verify(tenant, device, batch, pack_path):
            barrier.wait(timeout=10)
            self.assertTrue(corrupted.wait(timeout=10))

        def committer():
            try:
                self.cage.commit(TENANT_A, DEV_A, BATCH_A,
                                 hooks={"on_verify": on_verify})
                self.errors.append(AssertionError("摘要不符下不应提交成功"))
            except CageError:
                pass
            except BaseException as exc:  # noqa: BLE001
                self.errors.append(exc)

        def corruptor():
            barrier.wait(timeout=10)
            flip_last_frame_payload(staged_pack)
            corrupted.set()
            run_unrelated_tenant(self.cage, self.errors)

        t1 = threading.Thread(target=committer, name="committer")
        t2 = threading.Thread(target=corruptor, name="corruptor")
        t1.start(); t2.start(); t1.join(15); t2.join(15)
        self.assertFalse(t1.is_alive() or t2.is_alive())
        self.assertEqual(self.errors, [])

        self.assertNotIn(BATCH_A, self._index_batches())
        # 损坏暂存已被清理
        self.assertFalse(staged_pack.exists())
        stats = self.cage.stats(TENANT_A, DEV_A)
        self.assertEqual(stats["held_bytes"], 0)
        self.assertIn(BATCH_B, self._index_batches())

    # ---- 场景 3：目录已落盘但回执丢失 ----

    def test_directory_durable_but_receipt_lost_then_recovers(self) -> None:
        stage_complete_batch(self.cage)
        barrier = threading.Barrier(2)

        def on_after_dir_sync(tenant, device, batch, pdir):
            barrier.wait(timeout=10)
            raise ReceiptLost("模拟进程在回执写入前崩溃")

        def committer():
            try:
                self.cage.commit(TENANT_A, DEV_A, BATCH_A,
                                 hooks={"on_after_dir_sync": on_after_dir_sync})
                self.errors.append(AssertionError("回执丢失应抛出崩溃信号"))
            except ReceiptLost:
                pass
            except BaseException as exc:  # noqa: BLE001
                self.errors.append(exc)

        def witness():
            # 与提交线程屏障会合后，作为无关工作线程继续推进
            barrier.wait(timeout=10)
            run_unrelated_tenant(self.cage, self.errors)

        t1 = threading.Thread(target=committer, name="committer")
        t2 = threading.Thread(target=witness, name="witness")
        t1.start(); t2.start(); t1.join(15); t2.join(15)
        self.assertFalse(t1.is_alive() or t2.is_alive())
        self.assertEqual(self.errors, [])

        # 崩溃时刻：公开 pack/清单已在盘上，但索引回执缺失
        self.cage.close()
        self.assertNotIn(BATCH_A, self._index_batches())
        public_pack = (self.root / "tenants" / TENANT_A / "devices" / DEV_A /
                       "public" / BATCH_A / "pack.zlb")
        self.assertTrue(public_pack.exists())

        # 重新打开即恢复：补 commit 日志、重建索引、清掉暂存释放持有
        reopened = Cage(self.root, durable=True)
        try:
            self.assertIn(BATCH_A, self._index_batches())
            self.assertIn(BATCH_B, self._index_batches())
            stats = reopened.stats(TENANT_A, DEV_A)
            self.assertEqual(stats["held_bytes"], 0)
            self.assertEqual(stats["public_bytes"], public_pack.stat().st_size)
            staging = (self.root / "tenants" / TENANT_A / "devices" / DEV_A /
                       "staging" / BATCH_A)
            self.assertFalse(staging.exists())
        finally:
            reopened.close()

    # ---- 重投去重与未完成批次不公开 ----

    def test_redelivery_dedup_and_incomplete_not_indexed(self) -> None:
        # 同段重投三次，只暂存一份
        for _ in range(3):
            r = self.cage.ingest(TENANT_A, DEV_A, "dev-a#b0001", 0, False,
                                 _payload("dup"))
        self.assertEqual(r["status"], "duplicate")
        self.cage.abort(TENANT_A, DEV_A, "dev-a#b0001", "测试中止未完成批次")
        self.assertNotIn("dev-a#b0001", self._index_batches())
        stats = self.cage.stats(TENANT_A, DEV_A)
        self.assertEqual(stats["held_bytes"], 0)
        self.assertIn("dev-a#b0001", stats["batches"])
        self.assertEqual(stats["batches"]["dev-a#b0001"], "aborted")
        # 无关租户不受中止影响，照常推进并公开（满足 tearDown 的共同断言）
        run_unrelated_tenant(self.cage, self.errors)
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
