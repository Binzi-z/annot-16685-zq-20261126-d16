"""流式合成负载：虚构设备的封签分段与按设备签批的容量。

生成器逐段产出，调用方随取随喂给 Cage，十万段也不会在内存里堆积。
分段载荷是高压缩比的规则字节（模拟采集读数），用于核算压缩前后体积。
"""

from __future__ import annotations

import hashlib

DEFAULT_DEVICES = 10
DEFAULT_SEGMENTS_PER_DEVICE = 10_000  # 合计十万段
DEFAULT_CAPACITY = 1024 * 1024        # 每设备签批 1 MiB 暂存容量（够装一个批次）
PAYLOAD_SIZE = 256
_BLOCK_SIZE = 16


def make_payload(tenant: str, device: str, seq: int) -> bytes:
    """确定性载荷：同 (设备, 序号) 永远得到同字节，便于重投测试。

    16 字节确定块重复 16 次得到 256 字节，块内/块间高度重复，zlib 单段
    压缩比即可稳定低于 0.2，用于核算压缩输入阶段的真实收益。
    """
    seed = f"{tenant}|{device}|{seq}".encode("utf-8")
    block = hashlib.sha256(seed).digest()[:_BLOCK_SIZE]
    return block * (PAYLOAD_SIZE // _BLOCK_SIZE)


def segment_stream(devices: int = DEFAULT_DEVICES,
                   segments_per_device: int = DEFAULT_SEGMENTS_PER_DEVICE,
                   tenant: str = "tenant-a"):
    """逐段产出 (tenant, device, batch, seq, final, payload) 的生成器。

    每 1000 段一个批次，末段 final=True；全程不持有历史分段。
    """
    batch_size = 1000
    for di in range(devices):
        device = f"dev-{di:03d}"
        total = segments_per_device
        for seq in range(total):
            batch = f"{device}#b{seq // batch_size:04d}"
            yield (tenant, device, batch, seq % batch_size,
                   (seq % batch_size) == batch_size - 1 or seq == total - 1,
                   make_payload(tenant, device, seq))


def provision(cage, devices: int = DEFAULT_DEVICES,
              capacity: int = DEFAULT_CAPACITY,
              tenant: str = "tenant-a") -> list[str]:
    """注册虚构设备并按设备签批容量，返回设备名列表。"""
    names = []
    for di in range(devices):
        device = f"dev-{di:03d}"
        cage.register_device(tenant, device)
        cage.approve(tenant, device, capacity)
        names.append(device)
    return names


def run_load(cage, devices: int = DEFAULT_DEVICES,
             segments_per_device: int = DEFAULT_SEGMENTS_PER_DEVICE,
             tenant: str = "tenant-a", *, on_event=None):
    """流式喂入全部封签分段，自动提交，返回分设备计数。

    on_event(stage, info) 可选，用于测试在阶段点采样内存；本函数自身不缓存分段。
    """
    counts = {}
    for tenant_id, device, batch, seq, final, payload in segment_stream(
        devices, segments_per_device, tenant
    ):
        result = cage.ingest(tenant_id, device, batch, seq, final, payload,
                             auto_commit=True)
        counts[device] = counts.get(device, 0) + 1
        if on_event is not None:
            on_event({"device": device, "batch": batch, "seq": seq,
                      "final": final, "result": result})
    return counts
