"""每设备追加日志（append-only ledger）与流式回放。

日志是该设备所有状态变更的唯一权威顺序记录，事件类型：

- approve      按代签批容量（含限额字节数）
- revoke       撤销某一代权限
- stage        一批分段暂存完成（记录暂存字节与末段摘要，未公开）
- commit       批次公开（记录公开字节与目录承诺）
- abort        批次中止（未完成/撤销，绝不能进入公开索引）
- watermark    历史持有水位（阶段点，单调）

检查器与采集区都只通过 replay() 重建状态，保证结论来自实际文件。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from . import fsutil


class LedgerError(RuntimeError):
    """日志追加/回放失败。"""


def canonical_event(event: dict) -> bytes:
    return (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


class DeviceLedger:
    """单设备日志句柄：串行追加，回放时不需要持有采集区锁。"""

    def __init__(self, path: Path, *, durable: bool = True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.durable = durable
        self._fh = None
        self._next_id = 1
        if self.path.exists():
            # 扫描已有尾部确定下一个事件号；日志本身保留全部历史。
            last = 0
            for event in self.replay():
                last = max(last, event["id"])
            self._next_id = last + 1

    def open(self) -> "DeviceLedger":
        if self._fh is None:
            self._fh = open(self.path, "ab", buffering=0)
        return self

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "DeviceLedger":
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()

    def append(self, event: dict) -> dict:
        """追加事件并补单调 id；落盘策略由 durable 控制。"""
        event = dict(event)
        event["id"] = self._next_id
        self._next_id += 1
        if self._fh is None:
            self.open()
        self._fh.write(canonical_event(event))
        if self.durable:
            fsutil.fsync_file(self._fh)
        return event

    def replay(self) -> Iterator[dict]:
        """流式逐行回放；损坏行显式报错而不是静默跳过。"""
        if not self.path.exists():
            return
        with open(self.path, "rb") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise LedgerError(
                        f"日志 {self.path} 第 {lineno} 行损坏：{exc}"
                    ) from exc


@dataclass
class BatchView:
    """回放得到的批次生命周期视图。"""

    batch: str
    generation: int
    staged_bytes: int = 0
    last_digest: str = ""
    final: bool = False
    state: str = "staged"  # staged | committed | aborted
    public_bytes: int = 0
    dir_commit: str = ""


@dataclass
class DeviceState:
    """从日志重放出的设备权威状态。"""

    tenant: str = ""
    device: str = ""
    generation: int = -1
    approved_bytes: int = 0
    revoked: bool = True
    held_bytes: int = 0                      # 当前暂存尚持有的字节
    watermark_bytes: int = 0                 # 历史持有水位
    public_bytes: int = 0                    # 累计公开字节
    batches: dict = field(default_factory=dict)
    last_event_id: int = 0

    @property
    def releasable_balance(self) -> int:
        """释放余额 = 签批容量 - 尚持有暂存；撤销代上应为 0 可用。"""
        return max(0, self.approved_bytes - self.held_bytes)


def apply_event(state: DeviceState, event: dict) -> DeviceState:
    """把单个事件应用到状态机（采集区与检查器共用同一份语义）。"""
    etype = event["etype"]
    state.last_event_id = event["id"]
    if etype == "approve":
        state.tenant = event["tenant"]
        state.device = event["device"]
        state.generation = event["generation"]
        state.approved_bytes = event["approved_bytes"]
        state.revoked = False
        # 新一代签批不自动继承旧代暂存；旧代未决批次必须 abort。
        state.held_bytes = 0
    elif etype == "revoke":
        if event["generation"] == state.generation:
            state.revoked = True
            # 不直接清零 held：暂存额由随后的 abort 事件释放，
            # 否则 abort 再扣一次会把持有额打成负数。
    elif etype == "stage":
        existing = state.batches.get(event["batch"])
        if existing is None:
            bv = BatchView(event["batch"], event["generation"])
            state.batches[event["batch"]] = bv
            delta = event["staged_bytes"]
        else:
            bv = existing
            # 同批次重复 stage（崩溃重写/重投）按差额计入，绝不全额重复累加
            delta = event["staged_bytes"] - bv.staged_bytes
        bv.staged_bytes = event["staged_bytes"]
        bv.last_digest = event["last_digest"]
        bv.final = event["final"]
        bv.state = "staged"
        state.held_bytes += delta
        if state.held_bytes > state.watermark_bytes:
            state.watermark_bytes = state.held_bytes
    elif etype == "commit":
        # 容忍日志缺 stage 的恢复情形（崩溃只留下公开文件时由恢复补 commit）：
        # 没有对应批次视图就按事件里的暂存字节建一个，避免 KeyError 与负持有。
        bv = state.batches.get(event["batch"])
        if bv is None:
            bv = BatchView(event["batch"], event["generation"])
            bv.staged_bytes = event.get("staged_bytes", 0)
            state.batches[event["batch"]] = bv
        bv.state = "committed"
        bv.public_bytes = event["public_bytes"]
        bv.dir_commit = event["dir_commit"]
        bv.last_digest = event.get("last_digest", bv.last_digest)
        state.held_bytes -= bv.staged_bytes
        if state.held_bytes < 0:
            raise LedgerError(
                f"设备 {state.device} 批次 {event['batch']} 提交导致持有额为负"
            )
        state.public_bytes += event["public_bytes"]
    elif etype == "abort":
        bv = state.batches.get(event["batch"])
        if bv is None:
            # 未到末段（无 stage 事件）就被中止的批次：登记为 aborted，便于审计
            bv = BatchView(event["batch"], event.get("generation", state.generation))
            state.batches[event["batch"]] = bv
        if bv.state == "staged":
            state.held_bytes -= bv.staged_bytes
            if state.held_bytes < 0:
                raise LedgerError(
                    f"设备 {state.device} 批次 {event['batch']} 中止导致持有额为负"
                )
        bv.state = "aborted"
    elif etype == "watermark":
        # 显式水位检查点：只能推高，且不得低于当前实际持有。
        if event["watermark_bytes"] < state.held_bytes:
            raise LedgerError(
                f"设备 {state.device} 水位检查点 {event['watermark_bytes']} "
                f"低于当前持有 {state.held_bytes}"
            )
        state.watermark_bytes = max(state.watermark_bytes, event["watermark_bytes"])
    else:
        raise LedgerError(f"未知日志事件类型：{etype}")
    return state


def replay_ledger(path: Path) -> DeviceState:
    """从日志文件完整重放一台设备的状态。"""
    ledger = DeviceLedger(path, durable=False)
    state = DeviceState()
    for event in ledger.replay():
        apply_event(state, event)
        if not state.device:
            state.device = event.get("device", state.device)
            state.tenant = event.get("tenant", state.tenant)
    return state
