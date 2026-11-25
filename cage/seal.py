"""封签分段原语：规范信封、摘要链、HMAC 封签、zlib 压缩与 pack 分帧。

磁盘上的一个分段（frame）布局（全部为字节流，可流式解析）::

    MAGIC(4) | 头部长度 4 字节大端 | zlib(规范头部 JSON UTF-8)
             | 载荷长度 8 字节大端 | zlib(载荷) | HMAC-SHA256 32 字节

规范头部（canonical JSON，sort_keys + 紧凑分隔符）字段::

    v       格式版本，固定 1
    t       租户标识
    d       虚构设备标识
    b       批次标识
    g       批准代（approval generation）
    s       批次内序号（0 起，连续）
    f       是否本批最后一段
    p       上一段摘要（首段为 32 个 0x00 的十六进制）
    n       原始（压缩前）载荷字节数
    digest  本段摘要 = sha256( prev_digest_bytes || zlib载荷 )
    mac     HMAC-SHA256( 设备密钥, 规范头部去掉 mac 字段后的字节 )

摘要链以「压缩后的载荷字节」为输入，重投同一段必然产生相同 frame。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import zlib

VERSION = 1
MAGIC = b"CSG1"  # cage sealed segment, version 1
HEADER_LEN_BYTES = 4
PAYLOAD_LEN_BYTES = 8
DIGEST_BYTES = 32
ZERO_PREV = "00" * DIGEST_BYTES
ZLIB_LEVEL = 6


class SealError(ValueError):
    """封签/分帧/摘要链校验失败。"""


def canonical_header_bytes(header: dict) -> bytes:
    """把头部按规范形式序列化为字节（不含 mac 的封签输入也走这里）。"""
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_mac(key: bytes, header_without_mac: dict) -> str:
    """对去掉 mac 字段的规范头部计算 HMAC-SHA256（十六进制）。"""
    msg = canonical_header_bytes(header_without_mac)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def make_segment(
    *,
    tenant: str,
    device: str,
    batch: str,
    generation: int,
    seq: int,
    final: bool,
    prev_digest_hex: str,
    payload: bytes,
    key: bytes,
) -> tuple[bytes, dict]:
    """生成单个封签分段的磁盘 frame，并返回 (frame, 头部)。

    同输入必然得到同 frame —— 重投去重直接按整段字节比较。
    """
    if not prev_digest_hex:
        prev_digest_hex = ZERO_PREV
    compressed_payload = zlib.compress(payload, ZLIB_LEVEL)
    digest = hashlib.sha256(
        bytes.fromhex(prev_digest_hex) + compressed_payload
    ).hexdigest()

    header = {
        "v": VERSION,
        "t": tenant,
        "d": device,
        "b": batch,
        "g": generation,
        "s": seq,
        "f": bool(final),
        "p": prev_digest_hex,
        "n": len(payload),
        "digest": digest,
    }
    header["mac"] = compute_mac(key, header)

    header_blob = zlib.compress(canonical_header_bytes(header), ZLIB_LEVEL)
    frame = b"".join(
        (
            MAGIC,
            len(header_blob).to_bytes(HEADER_LEN_BYTES, "big"),
            header_blob,
            len(compressed_payload).to_bytes(PAYLOAD_LEN_BYTES, "big"),
            compressed_payload,
            bytes.fromhex(header["mac"]),
        )
    )
    return frame, header


def _read_exact(stream, size: int, what: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise SealError(f"截断的分段流：期望读取 {what} {size} 字节，实际 {len(data)}")
    return data


def iter_frames(stream):
    """流式解析 pack 文件，逐个产出 (头部 dict, 原始载荷 bytes)。

    解析过程即校验：魔数、HMAC、摘要链、序号连续性、长度全部核对。
    调用方还可进一步核对租户/设备/批次/批准代归属。
    """
    expected_seq = 0
    prev_hex = ZERO_PREV
    while True:
        magic = stream.read(len(MAGIC))
        if not magic:
            return
        if magic != MAGIC:
            raise SealError(f"分段魔数错误：{magic!r}")

        header_len = int.from_bytes(
            _read_exact(stream, HEADER_LEN_BYTES, "头部长度"), "big"
        )
        header_blob = _read_exact(stream, header_len, "头部")
        payload_len = int.from_bytes(
            _read_exact(stream, PAYLOAD_LEN_BYTES, "载荷长度"), "big"
        )
        compressed_payload = _read_exact(stream, payload_len, "压缩载荷")
        mac_bytes = _read_exact(stream, DIGEST_BYTES, "封签")

        try:
            header = json.loads(zlib.decompress(header_blob).decode("utf-8"))
        except (zlib.error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SealError(f"头部无法解压/解析：{exc}") from exc

        # 0) 格式版本必须匹配，避免把未来版本当 v1 解析
        if header.get("v") != VERSION:
            raise SealError(f"不支持的封签版本：{header.get('v')!r}（期望 {VERSION}）")

        # 1) HMAC 封签：重算后常量时间比较
        mac_given = header.pop("mac", None)
        if mac_given is None or not hmac.compare_digest(
            mac_given, compute_mac(_lookup_key(header), header)
        ):
            raise SealError(f"批次 {header.get('b')} 序号 {header.get('s')} 封签不符")
        if not hmac.compare_digest(mac_bytes.hex(), mac_given):
            raise SealError("frame 尾部封签字节与头部 mac 不一致")

        # 2) 摘要链：prev 与 digest 都要对上
        if header["p"] != prev_hex:
            raise SealError(
                f"批次 {header['b']} 序号 {header['s']} 上一段摘要不符"
            )
        want_digest = hashlib.sha256(
            bytes.fromhex(prev_hex) + compressed_payload
        ).hexdigest()
        if not hmac.compare_digest(want_digest, header["digest"]):
            raise SealError(f"批次 {header['b']} 序号 {header['s']} 摘要不符")

        # 3) 序号连续、原始长度一致
        if header["s"] != expected_seq:
            raise SealError(
                f"批次 {header['b']} 序号不连续：期望 {expected_seq}，实际 {header['s']}"
            )
        try:
            payload = zlib.decompress(compressed_payload)
        except zlib.error as exc:
            raise SealError(f"批次 {header['b']} 序号 {header['s']} 载荷解压失败") from exc
        if len(payload) != header["n"]:
            raise SealError(
                f"批次 {header['b']} 序号 {header['s']} 原始长度记录 {header['n']}，实际 {len(payload)}"
            )

        yield header, payload
        prev_hex = header["digest"]
        expected_seq += 1


# iter_frames 需要设备密钥来验签。为保持「流式 + 不依赖 cage」，
# 由调用方通过 seal.KEY_RESOLVER 注入解析函数 header -> key。
def _lookup_key(header: dict) -> bytes:
    resolver = globals().get("KEY_RESOLVER")
    if resolver is None:
        raise SealError("未配置 seal.KEY_RESOLVER，无法核验封签")
    return resolver(header)


KEY_RESOLVER = None  # 形如 callable(header) -> bytes


def set_key_resolver(resolver) -> None:
    """安装密钥解析器（采集区与检查器各自注入，避免模块级硬编码）。"""
    globals()["KEY_RESOLVER"] = resolver


def parse_pack(path) -> list[tuple[dict, bytes]]:
    """一次性解析整个 pack 文件（小文件/测试便利接口）。"""
    with open(path, "rb") as fh:
        return list(iter_frames(fh))
