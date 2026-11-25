"""原子写与目录级落盘。

Windows 上 Python 的 os.fsync 不支持目录句柄，因此直接经 ctypes 调
Win32 API：CreateFileW 以 FILE_FLAG_BACKUP_SEMANTICS 打开目录，
FlushFileBuffers 强制目录项落盘，再 CloseHandle。POSIX 回退到
open(dir, O_RDONLY) + fsync。

全部只用标准库，原生 Windows 可运行，不依赖 WSL/第三方包。
"""

from __future__ import annotations

import ctypes
import os
import sys
import tempfile
from pathlib import Path

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_DELETE = 0x00000004
    _OPEN_EXISTING = 3
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _kernel32.FlushFileBuffers.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL


class FsError(OSError):
    """持久化（落盘/原子替换）失败。"""


def sync_dir(path) -> None:
    """强制目录条目落盘（rename/unlink 后调用，保证崩溃后目录状态可见）。

    Windows 上目录不是普通文件，需要 FILE_FLAG_BACKUP_SEMANTICS；而
    FlushFileBuffers 对目录句柄要求写访问，先用 GENERIC_WRITE 打开，
    若被策略拒绝（ERROR_ACCESS_DENIED），退回只读句柄再尝试。
    """
    path = os.fspath(path)
    if _IS_WINDOWS:
        last_error = 0
        handle = None
        for access in (_GENERIC_WRITE, _GENERIC_READ):
            handle = _kernel32.CreateFileW(
                path,
                access,
                _FILE_SHARE_READ | _FILE_SHARE_DELETE,
                None,
                _OPEN_EXISTING,
                _FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
            if handle and handle != _INVALID_HANDLE_VALUE:
                break
            last_error = ctypes.get_last_error()
        if not handle or handle == _INVALID_HANDLE_VALUE:
            raise ctypes.WinError(last_error)
        try:
            if not _kernel32.FlushFileBuffers(handle):
                err = ctypes.get_last_error()
                # 部分 Windows 配置/非提升会话不允许对目录句柄刷缓冲
                # （ERROR_ACCESS_DENIED）。此时文件内容已 fsync、改名是原子的，
                # 目录条目持久化降级为尽力而为，其余错误仍须显式抛出。
                if err != 5:
                    raise ctypes.WinError(err)
        finally:
            _kernel32.CloseHandle(handle)
    else:  # pragma: no cover - 非 Windows 回退路径
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def fsync_file(fh) -> None:
    """文件内容落盘（Windows 下 os.fsync 对普通文件可用）。"""
    fh.flush()
    os.fsync(fh.fileno())


def atomic_write(path, data: bytes, *, durable: bool = True) -> None:
    """同目录临时文件 + fsync + os.replace 原子替换 + 目录落盘。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            if durable:
                fsync_file(fh)
        os.replace(tmp, path)
        if durable:
            sync_dir(path.parent)
    except BaseException:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def durable_rename(src, dst, *, durable: bool = True) -> None:
    """原子改名并落盘目录；目标已存在时 os.replace 直接覆盖。"""
    os.replace(src, dst)
    if durable:
        sync_dir(Path(dst).parent)
        # src 与 dst 同目录，一次目录落盘即可。


def durable_unlink(path, *, durable: bool = True) -> None:
    """删除文件并落盘目录，文件不存在视为成功（崩溃恢复幂等）。"""
    try:
        Path(path).unlink()
    except FileNotFoundError:
        return
    if durable:
        sync_dir(Path(path).parent)
