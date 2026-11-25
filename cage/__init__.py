"""本地防泄露采集区（纯标准库，原生 Windows / Python 3.12）。

模块划分：
- seal:   封签分段的规范信封、摘要链、HMAC 封签、zlib 压缩与 pack 分帧
- fsutil: 原子写与目录级落盘（Windows 走 CreateFileW/FlushFileBuffers）
- ledger: 每设备追加日志与流式回放
- cage:   采集区核心（签批、暂存、提交、恢复、公开索引、容量水位）
- checker:独立检查器（不 import cage，仅复用 seal 的格式原语）
- driver: 流式合成负载
"""

__all__ = ["seal", "fsutil", "ledger", "cage", "checker", "driver"]
