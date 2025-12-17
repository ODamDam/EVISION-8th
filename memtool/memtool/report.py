from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .analyze import FoundString, KeywordHit, load_sidecar_meta
from .util import (
    DEFAULT_KEYWORDS,
    FileMeta,
    ensure_parent,
    highlight_keywords,
    is_suspicious_string,
    now_iso,
    relpath_for_display,
)


def build_findings(
    dump_path: str,
    minlen: int,
    extract_unicode: bool,
    keywords: Iterable[str],
    context: int,
    max_strings: int = 5000,
) -> Dict:
    """
    Runs full analysis pipeline for reporting.
    """
    from .analyze import extract_ascii_strings, extract_utf16le_strings, search_keywords

    ascii_strings = extract_ascii_strings(dump_path, minlen=minlen)
    uni_strings: List[FoundString] = []
    if extract_unicode:
        uni_strings = extract_utf16le_strings(dump_path, minlen=minlen)

    # avoid explosive outputs; keep first N by offset
    all_strings = sorted(ascii_strings + uni_strings, key=lambda s: s.offset)[:max_strings]
    hits = search_keywords(dump_path, keywords=keywords, context=context)

    # suspicious strings subset
    suspicious = []
    for s in all_strings:
        flag, reason = is_suspicious_string(s.value, keywords)
        if flag:
            suspicious.append({"offset": s.offset, "encoding": s.encoding, "value": s.value, "reason": reason})

    meta = load_sidecar_meta(dump_path)

    return {
        "tool": {"name": "memtool", "created_at": now_iso()},
        "dump": {"path": relpath_for_display(dump_path), "meta": meta},
        "params": {
            "minlen": minlen,
            "extract_unicode": extract_unicode,
            "keywords": list(keywords),
            "context": context,
            "max_strings": max_strings,
        },
        "stats": {
            "ascii_strings": len(ascii_strings),
            "unicode_strings": len(uni_strings),
            "total_strings_in_report": len(all_strings),
            "keyword_hits": len(hits),
            "suspicious_strings": len(suspicious),
        },
        "strings": [asdict(s) for s in all_strings],
        "suspicious": suspicious,
        "keyword_hits": [asdict(h) for h in hits],
    }


def write_json_report(findings: Dict, out_path: str) -> str:
    p = ensure_parent(out_path)
    Path(p).write_text(json.dumps(findings, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(p)


def write_html_report(findings: Dict, out_path: str) -> str:
    p = ensure_parent(out_path)
    keywords = findings.get("params", {}).get("keywords", DEFAULT_KEYWORDS)

    dump_path = findings.get("dump", {}).get("path", "")
    stats = findings.get("stats", {})
    meta = findings.get("dump", {}).get("meta", None)

    suspicious_rows = []
    for s in findings.get("suspicious", []):
        suspicious_rows.append(
            "<tr>"
            f"<td class='mono'>{hex(int(s['offset']))}</td>"
            f"<td>{s['encoding']}</td>"
            f"<td class='mono'>{highlight_keywords(s['value'], keywords)}</td>"
            f"<td>{s.get('reason','')}</td>"
            "</tr>"
        )

    hit_rows = []
    for h in findings.get("keyword_hits", []):
        hit_rows.append(
            "<tr>"
            f"<td class='mono'>{hex(int(h['offset']))}</td>"
            f"<td>{h['encoding']}</td>"
            f"<td class='mono'>{highlight_keywords(h['keyword'], keywords)}</td>"
            f"<td class='mono small'>{highlight_keywords(h['context_printable'], keywords)}</td>"
            "</tr>"
        )

    meta_block = ""
    if meta:
        meta_lines = []
        for k in ["source_pid", "source_process_name", "source_exe", "created_at"]:
            if k in meta and meta[k] is not None:
                meta_lines.append(f"<li><b>{k}</b>: {escape_html(str(meta[k]))}</li>")
        if meta_lines:
            meta_block = "<ul>" + "".join(meta_lines) + "</ul>"

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>memtool report</title>
<style>
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }}
  .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ border-bottom: 1px solid #eee; padding: 8px; vertical-align: top; }}
  th {{ text-align: left; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  .small {{ font-size: 12px; }}
  mark {{ padding: 0 2px; }}
  .muted {{ color: #666; }}
</style>
</head>
<body>
  <h1>memtool report</h1>
  <p class="muted">Generated at: {escape_html(findings.get("tool",{}).get("created_at",""))}</p>

  <div class="card">
    <h2>Dump</h2>
    <div><b>Path</b>: <span class="mono">{escape_html(dump_path)}</span></div>
    {meta_block}
  </div>

  <div class="card">
    <h2>Stats</h2>
    <ul>
      <li><b>ASCII strings</b>: {stats.get("ascii_strings",0)}</li>
      <li><b>Unicode strings</b>: {stats.get("unicode_strings",0)}</li>
      <li><b>Keyword hits</b>: {stats.get("keyword_hits",0)}</li>
      <li><b>Suspicious strings</b>: {stats.get("suspicious_strings",0)}</li>
    </ul>
  </div>

  <div class="card">
    <h2>Suspicious strings (highlighted)</h2>
    <table>
      <thead><tr><th>Offset</th><th>Enc</th><th>String</th><th>Reason</th></tr></thead>
      <tbody>
        {("".join(suspicious_rows) if suspicious_rows else "<tr><td colspan='4' class='muted'>None</td></tr>")}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Keyword hits (context)</h2>
    <table>
      <thead><tr><th>Offset</th><th>Enc</th><th>Keyword</th><th>Context</th></tr></thead>
      <tbody>
        {("".join(hit_rows) if hit_rows else "<tr><td colspan='4' class='muted'>None</td></tr>")}
      </tbody>
    </table>
  </div>

  <p class="muted small">Note: This report is heuristic and may include false positives.</p>
</body>
</html>
"""
    Path(p).write_text(html, encoding="utf-8")
    return str(p)


def escape_html(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )
