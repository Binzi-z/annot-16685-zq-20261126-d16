"""封签原语、批准代与检查器抓篡改的单元测试。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
import tempfile

from cage.cage import Cage, CageError
from cage import checker, seal
from cage.seal import SealError

TENANT, DEVICE, BATCH = "tenant-a", "dev-a", "dev-a#b0000"


class SealRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cage-core-"))
        self.cage = Cage(self.tmp, durable=True)
        self.cage.register_device(TENANT, DEVICE)
        self.key = self.cage.load_key(TENANT, DEVICE)
        seal.set_key_resolver(lambda h: self.key)

    def tearDown(self) -> None:
        self.cage.close()

    def test_deterministic_frame_and_chain(self) -> None:
        f1, h1 = seal.make_segment(
            tenant=TENANT, device=DEVICE, batch=BATCH, generation=0,
            seq=0, final=False, prev_digest_hex=seal.ZERO_PREV,
            payload=b"abc", key=self.key,
        )
        f1b, _ = seal.make_segment(
            tenant=TENANT, device=DEVICE, batch=BATCH, generation=0,
            seq=0, final=False, prev_digest_hex=seal.ZERO_PREV,
            payload=b"abc", key=self.key,
        )
        self.assertEqual(f1, f1b)  # 同输入同字节，重投可去重

        f2, h2 = seal.make_segment(
            tenant=TENANT, device=DEVICE, batch=BATCH, generation=0,
            seq=1, final=True, prev_digest_hex=h1["digest"],
            payload=b"def", key=self.key,
        )
        pack = self.tmp / "pack.zlb"
        pack.write_bytes(f1 + f2)
        frames = seal.parse_pack(pack)
        self.assertEqual([h["s"] for h, _ in frames], [0, 1])
        self.assertEqual(frames[1][0]["digest"], h2["digest"])
        self.assertTrue(frames[1][0]["f"])

    def test_tampered_payload_fails_mac_or_digest(self) -> None:
        f1, h1 = seal.make_segment(
            tenant=TENANT, device=DEVICE, batch=BATCH, generation=0,
            seq=0, final=True, prev_digest_hex=seal.ZERO_PREV,
            payload=b"abc", key=self.key,
        )
        blob = bytearray(f1)
        blob[-1] ^= 0x01  # 翻转 HMAC 尾字节
        (self.tmp / "bad.zlb").write_bytes(bytes(blob))
        with self.assertRaises(SealError):
            seal.parse_pack(self.tmp / "bad.zlb")


class ApprovalAndCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cage-core-"))
        self.cage = Cage(self.tmp, durable=True)
        self.cage.register_device(TENANT, DEVICE)

    def tearDown(self) -> None:
        self.cage.close()

    def _stage_and_commit(self, batch: str) -> None:
        self.cage.ingest(TENANT, DEVICE, batch, 0, False, b"x")
        self.cage.ingest(TENANT, DEVICE, batch, 1, True, b"y")
        self.cage.commit(TENANT, DEVICE, batch)

    def test_generation_rotation_aborts_old_batches(self) -> None:
        g0 = self.cage.approve(TENANT, DEVICE, 4096)
        self.assertEqual(g0, 0)
        self.cage.ingest(TENANT, DEVICE, "dev-a#old", 0, False, b"q")
        g1 = self.cage.approve(TENANT, DEVICE, 8192)  # 重签新一代
        self.assertEqual(g1, 1)
        stats = self.cage.stats(TENANT, DEVICE)
        self.assertEqual(stats["held_bytes"], 0)
        self.assertEqual(stats["batches"]["dev-a#old"], "aborted")
        # 旧代批次绝不能再写入或公开
        with self.assertRaises(CageError):
            self.cage.commit(TENANT, DEVICE, "dev-a#old")

    def test_revoked_device_rejects_ingest(self) -> None:
        self.cage.approve(TENANT, DEVICE, 4096)
        self.cage.revoke(TENANT, DEVICE)
        with self.assertRaises(CageError):
            self.cage.ingest(TENANT, DEVICE, "dev-a#x", 0, True, b"z")

    def test_capacity_enforced(self) -> None:
        self.cage.approve(TENANT, DEVICE, 64)  # 故意给很小容量
        with self.assertRaises(CageError):
            self.cage.ingest(TENANT, DEVICE, "dev-a#cap", 0, True,
                             b"z" * 200)
        self.assertEqual(
            self.cage.stats(TENANT, DEVICE)["held_bytes"], 0
        )

    def test_happy_path_passes_independent_checker(self) -> None:
        self.cage.approve(TENANT, DEVICE, 4096)
        self._stage_and_commit(BATCH)
        report = checker.check_cage(self.tmp)
        self.assertEqual(report["totals"]["indexed_batches"], 1)
        self.assertEqual(
            report["devices"][f"{TENANT}/{DEVICE}"]["releasable_balance"],
            4096,
        )

    def test_checker_detects_tampered_public_byte(self) -> None:
        self.cage.approve(TENANT, DEVICE, 4096)
        self._stage_and_commit(BATCH)
        pack = (self.tmp / "tenants" / TENANT / "devices" / DEVICE /
                "public" / BATCH / "pack.zlb")
        blob = bytearray(pack.read_bytes())
        # 在 pack 中部翻转一个非长度字段字节，破坏封签/摘要
        blob[len(blob) // 2] ^= 0xFF
        pack.write_bytes(bytes(blob))
        with self.assertRaises(checker.CheckError):
            checker.check_cage(self.tmp)

    def test_checker_detects_phantom_index_entry(self) -> None:
        self.cage.approve(TENANT, DEVICE, 4096)
        self._stage_and_commit(BATCH)
        idx = self.tmp / "public" / "index" / "tenant-a__ghost.json"
        idx.write_text(
            json.dumps({"tenant": TENANT, "batch": "ghost"}),
            encoding="utf-8",
        )
        with self.assertRaises(checker.CheckError):
            checker.check_cage(self.tmp)

    def test_root_commit_is_joint_commitment(self) -> None:
        self.cage.approve(TENANT, DEVICE, 4096)
        self._stage_and_commit(BATCH)
        root = json.loads(
            (self.tmp / "public" / "root.json").read_text("utf-8")
        )
        self.assertEqual(root["root_commit"], self.cage.root_commit())
        # 末段摘要、批准代、目录承诺都体现在索引/根承诺里
        entry = self.cage.index_snapshot()[0]
        self.assertEqual(entry["last_digest"],
                         root["entries"][0]["last_digest"])
        self.assertEqual(entry["generation"], 0)
        self.assertEqual(len(entry["dir_commit"]), 64)

    def test_checker_cli_exit_codes(self) -> None:
        self.cage.approve(TENANT, DEVICE, 4096)
        self._stage_and_commit(BATCH)
        # 健康采集区：main 入口返回 0
        self.assertEqual(checker.main([str(self.tmp)]), 0)
        # 制造篡改后：main 入口返回 1 而不是抛异常
        pack = (self.tmp / "tenants" / TENANT / "devices" / DEVICE /
                "public" / BATCH / "pack.zlb")
        blob = bytearray(pack.read_bytes())
        blob[len(blob) // 2] ^= 0xFF
        pack.write_bytes(bytes(blob))
        self.assertEqual(checker.main([str(self.tmp)]), 1)
        # 参数错误返回 2
        self.assertEqual(checker.main([]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
