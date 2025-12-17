from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .util import safe_decode_bytes_to_printable


@dataclass
class FoundString:
    offset: int
    encoding: str  # "ascii" or "utf16le"
    value: str


@dataclass
class KeywordHit:
    offset: int
    encoding: str  # "ascii" or "utf16le"
    keyword: str
    context_printable: str
    context_hex: str


# Tunables
CHUNK_SIZE = 8 * 1024 * 1024  # 8MB
MAX_OUTPUT_STRINGS = 200_000  # safety cap to avoid huge RAM/JSON


def _file_size(path: str) -> int:
    return Path(path).stat().st_size


def _ensure_non_empty(path: str) -> None:
    sz = _file_size(path)
    if sz <= 0:
        raise ValueError(f"Input file is empty: {path}")


def extract_ascii_strings(path: str, minlen: int) -> List[FoundString]:
    """
    Stream-scan file for printable ASCII runs (0x20..0x7E).
    Handles boundary runs across chunks.
    """
    _ensure_non_empty(path)

    out: List[FoundString] = []
    base_off = 0

    carry = bytearray()

    def flush_run(run: bytearray, run_start_off: int):
        if len(run) >= minlen:
            try:
                s = run.decode("ascii", "ignore")
            except Exception:
                return
            out.append(FoundString(offset=run_start_off, encoding="ascii", value=s))

    run = bytearray()
    run_start = 0

    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            data = carry + chunk
            data_off = base_off - len(carry)

            # scan
            for i, b in enumerate(data):
                if 0x20 <= b <= 0x7E:
                    if not run:
                        run_start = data_off + i
                    run.append(b)
                else:
                    if run:
                        flush_run(run, run_start)
                        if len(out) >= MAX_OUTPUT_STRINGS:
                            return out
                        run.clear()

            # keep tail of printable run if chunk ended mid-run
            # If run is ongoing, keep it as carry. Otherwise carry empty.
            # But we cannot keep entire huge run; keep as run itself already holds it.
            carry = bytearray()
            base_off += len(chunk)

    # flush last run
    if run:
        flush_run(run, run_start)

    return out[:MAX_OUTPUT_STRINGS]


def extract_utf16le_strings(path: str, minlen: int) -> List[FoundString]:
    """
    Stream-scan for UTF-16LE strings that look like:
      [0x20..0x7E] 0x00 repeated
    This is a pragmatic approach for typical Windows user-mode strings.
    """
    _ensure_non_empty(path)

    out: List[FoundString] = []
    base_off = 0

    carry = bytearray()

    run_chars: List[int] = []
    run_start = 0

    def flush_run(chars: List[int], run_start_off: int):
        if len(chars) >= minlen:
            try:
                s = bytes(chars).decode("ascii", "ignore")
            except Exception:
                return
            out.append(FoundString(offset=run_start_off, encoding="utf16le", value=s))

    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            data = carry + chunk
            data_off = base_off - len(carry)

            # ensure even length for 2-byte stepping; keep last byte as carry if odd
            if len(data) % 2 == 1:
                carry = bytearray([data[-1]])
                data = data[:-1]
            else:
                carry = bytearray()

            i = 0
            n = len(data)
            while i + 1 < n:
                b0 = data[i]
                b1 = data[i + 1]
                if 0x20 <= b0 <= 0x7E and b1 == 0x00:
                    if not run_chars:
                        run_start = data_off + i
                    run_chars.append(b0)
                else:
                    if run_chars:
                        flush_run(run_chars, run_start)
                        if len(out) >= MAX_OUTPUT_STRINGS:
                            return out
                        run_chars.clear()
                i += 2

            base_off += len(chunk)

    if run_chars:
        flush_run(run_chars, run_start)

    return out[:MAX_OUTPUT_STRINGS]


def search_keywords(path: str, keywords: Iterable[str], context: int = 32) -> List[KeywordHit]:
    """
    Stream search for keywords in both ASCII and UTF-16LE encodings.
    Reports file offsets and surrounding context bytes.
    """
    _ensure_non_empty(path)

    kws = [k for k in keywords if k]
    hits: List[KeywordHit] = []

    patterns: List[Tuple[str, str, bytes]] = []
    for kw in kws:
        a = kw.encode("ascii", "ignore")
        if a:
            patterns.append(("ascii", kw, a))
        patterns.append(("utf16le", kw, kw.encode("utf-16le")))

    # Precompute maximum overlap to catch boundary matches
    max_pat = max((len(pat) for _, _, pat in patterns), default=1)
    overlap = max(0, max_pat - 1)

    base_off = 0
    carry = b""

    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            data = carry + chunk
            data_off = base_off - len(carry)

            for enc, kw, pat in patterns:
                start = 0
                while True:
                    idx = data.find(pat, start)
                    if idx == -1:
                        break
                    abs_off = data_off + idx
                    lo = max(0, idx - context)
                    hi = min(len(data), idx + len(pat) + context)
                    ctx = data[lo:hi]
                    hits.append(
                        KeywordHit(
                            offset=abs_off,
                            encoding=enc,
                            keyword=kw,
                            context_printable=safe_decode_bytes_to_printable(ctx),
                            context_hex=ctx.hex(),
                        )
                    )
                    start = idx + 1

            # keep overlap tail for boundary matching
            if len(chunk) >= overlap:
                carry = data[-overlap:]
            else:
                carry = data

            base_off += len(chunk)

    hits.sort(key=lambda h: (h.offset, h.encoding, h.keyword.lower()))
    return hits


def load_sidecar_meta(dump_path: str) -> Optional[Dict]:
    p = Path(dump_path)
    meta = p.with_suffix(p.suffix + ".meta.json")
    if not meta.exists():
        return None
    try:
        return json.loads(meta.read_text(encoding="utf-8"))
    except Exception:
        return None
