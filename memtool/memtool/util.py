from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Tuple

PRINTABLE_ASCII_MIN = 0x20
PRINTABLE_ASCII_MAX = 0x7E

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_JWT_LIKE_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

DEFAULT_KEYWORDS = ["password", "token", "key", "secret", "apikey", "auth", "bearer"]


def ensure_parent(path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def relpath_for_display(path: str | Path) -> str:
    """Return a repo-friendly relative path string if possible."""
    p = Path(path)
    try:
        return str(p.relative_to(Path.cwd()))
    except Exception:
        return str(p)


def safe_decode_bytes_to_printable(b: bytes) -> str:
    # Convert bytes to a readable ASCII-ish string; replace nonprintables with '.'
    out = []
    for x in b:
        if PRINTABLE_ASCII_MIN <= x <= PRINTABLE_ASCII_MAX:
            out.append(chr(x))
        elif x in (0x0A, 0x0D, 0x09):  # \n \r \t
            out.append(" ")
        else:
            out.append(".")
    return "".join(out)


def highlight_keywords(text: str, keywords: Iterable[str]) -> str:
    # HTML-safe minimal escaping + <mark> highlight
    escaped = (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    for kw in sorted(set(k for k in keywords if k), key=len, reverse=True):
        # case-insensitive replace using regex
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        escaped = pattern.sub(lambda m: f"<mark>{m.group(0)}</mark>", escaped)
    return escaped


def is_suspicious_string(s: str, keywords: Iterable[str]) -> Tuple[bool, str]:
    """
    Heuristics for 'suspicious' highlight.
    Returns (is_suspicious, reason).
    """
    sl = s.lower()
    for kw in keywords:
        if kw and kw.lower() in sl:
            return True, f"contains keyword '{kw}'"

    if len(s) >= 60:
        return True, "very long string"

    if _JWT_LIKE_RE.match(s):
        return True, "JWT-like pattern"

    # base64-ish: long and valid charset
    if len(s) >= 24 and _BASE64_RE.match(s):
        return True, "Base64-like pattern"

    # long hex
    if len(s) >= 32 and _HEX_RE.match(s):
        return True, "hex-like pattern"

    return False, ""


@dataclass(frozen=True)
class FileMeta:
    created_at: str
    source_pid: Optional[int] = None
    source_process_name: Optional[str] = None
    source_exe: Optional[str] = None
    dump_path: Optional[str] = None
