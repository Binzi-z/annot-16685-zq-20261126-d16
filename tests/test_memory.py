"""十万条分段的分阶段内存核算与中断隔离测试。

用 tracemalloc 直接核算 Python 解释器内的工作内存（不把磁盘占用当内存），
按四个阶段给账：
  1. 压缩输入：所有分段压缩后的帧字节总量与压缩时瞬时分配；
  2. 暂存：设备日志里的持有/水位（工作集），与暂存目录磁盘字节对账；
  3. 索引：公开索引条目对象与索引文件字节；
  4. 中断后尚持有的工作内存：中途停写、重开恢复后的当前/峰值内存与持有额。

硬约束：全程 tracemalloc 峰值 < 8 MiB；中断租户被隔离清理，无关租户仍能推进。

为聚焦工作内存，本测试关闭磁盘 fsync（durable=False）；落盘语义由
test_threads.py 在 durable=True 下覆盖。
"""

from __future__ import annotations

import gc
import sys
import zlib
import tracemalloc
import unittest
from pathlib import Path
import tempfile

from cage.cage import Cage
from cage import checker, driver

LIMIT = 8 * 1024 * 1024
TOTAL_SEGMENTS = 100_000
DEVICES = 10
PER_DEVICE = TOTAL_SEGMENTS // DEVICES


def _dir_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def _staging_bytes(root: Path, tenant: str) -> int:
    devices = root / "tenants" / tenant / "devices"
    if not devices.exists():
        return 0
    return sum(_dir_bytes(dev / "staging") for dev in devices.iterdir()
               if dev.is_dir())


class MemoryAccountingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="cage-mem-"))
        gc.collect()
        tracemalloc.start()
        self._baseline = tracemalloc.get_traced_memory()[0]

    def tearDown(self) -> None:
        tracemalloc.stop()

    def _current(self) -> int:
        return tracemalloc.get_traced_memory()[0] - self._baseline

    def test_full_100k_peak_under_8mib_and_phase_accounting(self) -> None:
        raw_total = 0                 # 原始载荷字节
        zpayload_total = 0           # 仅载荷 zlib 压缩后的字节（不含分帧头）
        frame_total = 0              # 实际落盘 frame 字节（载荷 + 规范头 + HMAC）
        sampled = {"staging_peak": 0, "mid_current": 0}
        processed = 0

        with Cage(self.root, durable=False) as cage:
            driver.provision(cage, devices=DEVICES,
                             capacity=driver.DEFAULT_CAPACITY)
            after_approve = self._current()

            for tenant, device, batch, seq, final, payload in driver.segment_stream(
                DEVICES, PER_DEVICE
            ):
                result = cage.ingest(tenant, device, batch, seq, final,
                                     payload, auto_commit=True)
                processed += 1
                raw_total += result["input_bytes"]
                if result["status"] != "duplicate":
                    # 与 seal.ZLIB_LEVEL 同级别，只压载荷以衡量真实压缩收益
                    zpayload_total += len(zlib.compress(payload, 6))
                    frame_total += result["compressed_bytes"]
                stats = cage.stats(tenant, device)
                if stats["watermark_bytes"] > sampled["staging_peak"]:
                    sampled["staging_peak"] = stats["watermark_bytes"]
                if processed == TOTAL_SEGMENTS // 2:
                    sampled["mid_current"] = self._current()

            index_objects = self._measure_index_objects(cage)
            index_disk = _dir_bytes(self.root / "public" / "index")
            index_disk += (self.root / "public" / "root.json").stat().st_size
            public_disk = _dir_bytes(self.root / "tenants")
            end_current, peak = tracemalloc.get_traced_memory()
            end_current -= self._baseline
            peak -= self._baseline

            self.assertEqual(processed, TOTAL_SEGMENTS)
            self.assertEqual(len(cage.index_snapshot()),
                             TOTAL_SEGMENTS // 1000)

        # ---- 硬约束：峰值工作内存 < 8 MiB ----
        self.assertLess(peak, LIMIT,
                        f"峰值工作内存 {peak} 超过 8 MiB 限制")

        # ---- 分阶段账目（断言方向 + 打印给人工核对）----
        # 1) 压缩输入：规则载荷本身应被显著压缩（分帧头/HMAC 是额外固定开销）
        self.assertLess(zpayload_total, raw_total)
        ratio = zpayload_total / raw_total
        self.assertLess(ratio, 0.5)
        framing_overhead = frame_total - zpayload_total
        self.assertGreater(framing_overhead, 0)  # 规范头 + 长度 + HMAC 固定存在
        # 2) 暂存工作集：单设备水位远小于 8 MiB，且提交后持有归零
        self.assertLess(sampled["staging_peak"], LIMIT)
        for di in range(DEVICES):
            s = cage.stats("tenant-a", f"dev-{di:03d}")
            self.assertEqual(s["held_bytes"], 0)
            self.assertEqual(s["releasable_balance"], s["approved_bytes"])
        # 3) 索引内存对象有界；索引磁盘字节随批次数线性、可整体重建
        self.assertLess(index_objects, LIMIT)
        self.assertLess(index_disk, public_disk)
        # 4) 处理中期与收尾的当前内存都有界（不随十万段线性增长）
        self.assertLess(sampled["mid_current"], LIMIT)
        self.assertLess(end_current, LIMIT)

        print("\n[十万段分阶段内存核算]")
        print(f"  原始输入字节        : {raw_total:>12,}")
        print(f"  压缩载荷字节(阶段1) : {zpayload_total:>12,}  载荷压缩比 {ratio:.3f}")
        print(f"  实际 frame 字节     : {frame_total:>12,}  (含分帧/HMAC 开销 "
              f"{framing_overhead:,})")
        print(f"  暂存水位峰值(阶段2) : {sampled['staging_peak']:>12,} 字节/设备")
        print(f"  索引对象内存(阶段3) : {index_objects:>12,} 字节；"
              f"索引磁盘 {index_disk:,} 字节")
        print(f"  中期当前工作内存    : {sampled['mid_current']:>12,}")
        print(f"  收尾当前工作内存    : {end_current:>12,}")
        print(f"  tracemalloc 峰值    : {peak:>12,}  (限制 {LIMIT:,})")
        print(f"  签批后基线内存      : {after_approve:>12,}")

        # 独立检查器从实际文件核对公开字节、释放余额、历史水位
        report = checker.check_cage(self.root)
        self.assertEqual(report["totals"]["staging_bytes"], 0)
        self.assertEqual(report["totals"]["indexed_batches"],
                         TOTAL_SEGMENTS // 1000)
        self.assertEqual(report["totals"]["releasable_balance"],
                         report["totals"]["approved_bytes"])

    @staticmethod
    def _measure_index_objects(cage: Cage) -> int:
        total = 0
        for entry in cage.index_snapshot():
            total += sys.getsizeof(entry)
            total += sum(sys.getsizeof(k) + sys.getsizeof(v)
                         for k, v in entry.items())
        return total

    def test_interrupted_tenant_isolated_and_unrelated_tenant_progresses(self) -> None:
        stop_at = 37_231  # 非整批：保证至少一个设备停在未完成状态
        with Cage(self.root, durable=False) as cage:
            driver.provision(cage, devices=DEVICES,
                             capacity=driver.DEFAULT_CAPACITY)
            for n, (tenant, device, batch, seq, final, payload) in enumerate(
                driver.segment_stream(DEVICES, PER_DEVICE), start=1
            ):
                cage.ingest(tenant, device, batch, seq, final, payload,
                            auto_commit=True)
                if n == stop_at:
                    break
            held_during = sum(
                cage.stats("tenant-a", f"dev-{di:03d}")["held_bytes"]
                for di in range(DEVICES)
            )
        # 退出（模拟中断）。未完成暂存已在盘上但未公开。
        staging_during = _staging_bytes(self.root, "tenant-a")
        self.assertGreater(staging_during, 0)

        # 重开即恢复：未完成/无末段的暂存批次被中止，释放全部持有
        gc.collect()
        pre_reopen = self._current()
        with Cage(self.root, durable=False) as reopened:
            post_reopen, peak = tracemalloc.get_traced_memory()
            post_reopen -= self._baseline
            peak -= self._baseline

            held_after = sum(
                reopened.stats("tenant-a", f"dev-{di:03d}")["held_bytes"]
                for di in range(DEVICES)
            )
            self.assertEqual(held_after, 0)  # 中断后不再持有工作暂存
            self.assertLess(peak, LIMIT)
            self.assertLess(post_reopen, LIMIT)

            staging_after = _staging_bytes(self.root, "tenant-a")
            self.assertEqual(staging_after, 0)

            # 无关租户在恢复后仍能完整推进并公开
            reopened.register_device("tenant-c", "dev-c")
            reopened.approve("tenant-c", "dev-c", driver.DEFAULT_CAPACITY)
            for i in range(4):
                reopened.ingest("tenant-c", "dev-c", "dev-c#b0000", i,
                                i == 3, f"c-{i}".encode() * 8,
                                auto_commit=True)
            self.assertIn("dev-c#b0000", reopened.index_batch_names())

        # 恢复后整个采集区依然通过独立检查器
        report = checker.check_cage(self.root)
        self.assertEqual(report["totals"]["staging_bytes"], 0)
        self.assertGreaterEqual(report["totals"]["indexed_batches"], 1)

        print("\n[中断后尚持有的工作内存(阶段4)]")
        print(f"  中断中暂存磁盘字节  : {staging_during:>12,}")
        print(f"  中断中日志持有合计  : {held_during:>12,}")
        print(f"  重开前当前内存      : {pre_reopen:>12,}")
        print(f"  恢复后当前内存      : {post_reopen:>12,}")
        print(f"  恢复后峰值内存      : {peak:>12,}  (限制 {LIMIT:,})")
        print(f"  恢复后暂存磁盘字节  : {staging_after:>12,}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
