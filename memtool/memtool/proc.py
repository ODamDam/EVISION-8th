from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import psutil


@dataclass
class ProcessInfo:
    pid: int
    name: str
    rss: int  # bytes
    exe: str


def list_processes(limit: Optional[int] = None) -> List[ProcessInfo]:
    out: List[ProcessInfo] = []
    for p in psutil.process_iter(attrs=["pid", "name", "exe"]):
        try:
            info = p.info
            pid = int(info["pid"])
            name = info.get("name") or ""
            exe = info.get("exe") or ""
            rss = int(p.memory_info().rss)
            out.append(ProcessInfo(pid=pid, name=name, rss=rss, exe=exe))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    out.sort(key=lambda x: x.rss, reverse=True)
    if limit is not None:
        out = out[: max(0, int(limit))]
    return out


def get_process_info(pid: int) -> Optional[ProcessInfo]:
    try:
        p = psutil.Process(pid)
        return ProcessInfo(
            pid=pid,
            name=p.name() or "",
            rss=int(p.memory_info().rss),
            exe=p.exe() or "",
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def processes_as_dict(rows: List[ProcessInfo]) -> List[Dict]:
    return [
        {"pid": r.pid, "name": r.name, "rss": r.rss, "exe": r.exe}
        for r in rows
    ]
