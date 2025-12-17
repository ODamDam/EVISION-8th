from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import os
import msvcrt

from dataclasses import asdict
from pathlib import Path
from typing import Optional, Tuple

from .proc import get_process_info
from .util import FileMeta, ensure_parent, now_iso, relpath_for_display

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)

# Access rights (minimum-ish)
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# MiniDump types (subset)
MiniDumpNormal = 0x00000000
MiniDumpWithFullMemory = 0x00000002
MiniDumpWithHandleData = 0x00000004
MiniDumpWithUnloadedModules = 0x00000020
MiniDumpWithFullMemoryInfo = 0x00000800
MiniDumpWithThreadInfo = 0x00001000

# Default: enough for strings/keyword scanning in many cases
DEFAULT_DUMP_TYPE = (
    MiniDumpWithFullMemory
    | MiniDumpWithFullMemoryInfo
    | MiniDumpWithHandleData
    | MiniDumpWithUnloadedModules
    | MiniDumpWithThreadInfo
)

# Function prototypes
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = wt.HANDLE

kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.CloseHandle.restype = wt.BOOL

dbghelp.MiniDumpWriteDump.argtypes = [
    wt.HANDLE,      # hProcess
    wt.DWORD,       # ProcessId
    wt.HANDLE,      # hFile
    wt.DWORD,       # DumpType
    wt.LPVOID,      # ExceptionParam
    wt.LPVOID,      # UserStreamParam
    wt.LPVOID,      # CallbackParam
]
dbghelp.MiniDumpWriteDump.restype = wt.BOOL


class DumpError(RuntimeError):
    pass


def _raise_last_error(msg: str) -> None:
    err = ctypes.get_last_error()
    raise DumpError(f"{msg} (WinError={err})")


def dump_process_minidump(
    pid: int,
    out_path: str,
    dump_type: int = DEFAULT_DUMP_TYPE,
) -> Tuple[str, str]:
    """
    Create a minidump for a target PID.
    Returns (dump_file_path, meta_file_path) as relative/absolute strings.
    """
    out_p = ensure_parent(out_path)
    meta_p = out_p.with_suffix(out_p.suffix + ".meta.json")

    # Open process
    hProc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not hProc:
        _raise_last_error("OpenProcess failed. Try running as Administrator.")

    try:
        # Create output file (Windows handle from Python file object)
        with open(out_p, "wb") as f:
        # Use stdlib msvcrt.get_osfhandle for reliability on Python 3.12/Windows
            os_handle = msvcrt.get_osfhandle(f.fileno())
            if os_handle == -1:
                raise DumpError("msvcrt.get_osfhandle failed")

            hFile = wt.HANDLE(os_handle)
            ok = dbghelp.MiniDumpWriteDump(hProc, pid, hFile, dump_type, None, None, None)
            if not ok:
                _raise_last_error("MiniDumpWriteDump failed")

        # Sidecar metadata (helpful for reports)
        pinfo = get_process_info(pid)
        meta = FileMeta(
            created_at=now_iso(),
            source_pid=pid,
            source_process_name=pinfo.name if pinfo else None,
            source_exe=pinfo.exe if pinfo else None,
            dump_path=relpath_for_display(out_p),
        )
        with open(meta_p, "w", encoding="utf-8") as mf:
            json.dump(asdict(meta), mf, ensure_ascii=False, indent=2)

        return str(out_p), str(meta_p)
    finally:
        kernel32.CloseHandle(hProc)


def resolve_dump_type(name: Optional[str]) -> int:
    """
    Map user-friendly dump type string to flags.
    """
    if not name:
        return DEFAULT_DUMP_TYPE
    n = name.strip().lower()
    if n in ("normal", "minidumpnormal"):
        return MiniDumpNormal
    if n in ("full", "withfullmemory", "fullmemory"):
        return DEFAULT_DUMP_TYPE
    if n in ("full_only", "fullmemory_only"):
        return MiniDumpWithFullMemory
    return DEFAULT_DUMP_TYPE
