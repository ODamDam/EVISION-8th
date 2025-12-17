from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import List

from . import __version__
from .proc import list_processes, processes_as_dict
from .dump_windows import dump_process_minidump, resolve_dump_type, DumpError
from .analyze import extract_ascii_strings, extract_utf16le_strings, search_keywords
from .report import build_findings, write_html_report, write_json_report
from .util import DEFAULT_KEYWORDS, ensure_parent, relpath_for_display


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="memtool",
        description="Forensic memory dump analysis tool (Windows 11)",
    )
    parser.add_argument("--version", action="version", version=f"memtool {__version__}")

    sub = parser.add_subparsers(dest="cmd", required=True)

    # list
    p_list = sub.add_parser("list", help="List running processes")
    p_list.add_argument("--limit", type=int, default=30, help="Max number of processes to show (default: 30)")
    p_list.add_argument("--json", action="store_true", help="Output as JSON")

    # dump
    p_dump = sub.add_parser("dump", help="Dump memory of a target PID to a file (minidump)")
    p_dump.add_argument("--pid", type=int, required=True, help="Target PID")
    p_dump.add_argument("--out", type=str, default=os.path.join("out", "dump.dmp"), help="Output dump path (relative recommended)")
    p_dump.add_argument("--type", type=str, default="full", help="Dump type: full|normal|full_only")

    # strings
    p_str = sub.add_parser("strings", help="Extract strings from a dump file")
    p_str.add_argument("--in", dest="in_path", type=str, required=True, help="Input dump path")
    p_str.add_argument("--minlen", type=int, default=4, help="Minimum string length")
    p_str.add_argument("--unicode", action="store_true", help="Also extract UTF-16LE strings")
    p_str.add_argument("--out", type=str, default="", help="Optional output JSON path (relative recommended)")

    # search
    p_s = sub.add_parser("search", help="Search keywords in a dump file")
    p_s.add_argument("--in", dest="in_path", type=str, required=True, help="Input dump path")
    p_s.add_argument("--kw", type=str, default="", help="Single keyword to search (if omitted, uses default keyword set)")
    p_s.add_argument("--kws", type=str, nargs="*", default=[], help="Multiple keywords (space-separated)")
    p_s.add_argument("--context", type=int, default=32, help="Context bytes around hits")
    p_s.add_argument("--out", type=str, default="", help="Optional output JSON path (relative recommended)")

    # report
    p_r = sub.add_parser("report", help="Generate JSON/HTML report")
    p_r.add_argument("--in", dest="in_path", type=str, required=True, help="Input dump path")
    p_r.add_argument("--minlen", type=int, default=4, help="Minimum string length")
    p_r.add_argument("--unicode", action="store_true", help="Also extract UTF-16LE strings")
    p_r.add_argument("--kw", type=str, default="", help="Single keyword to search")
    p_r.add_argument("--kws", type=str, nargs="*", default=[], help="Multiple keywords (space-separated)")
    p_r.add_argument("--context", type=int, default=32, help="Context bytes around hits")
    p_r.add_argument("--format", type=str, choices=["json", "html", "both"], default="both", help="Report output format")
    p_r.add_argument("--outdir", type=str, default="out", help="Output directory (relative recommended)")

    args = parser.parse_args(argv)

    if args.cmd == "list":
        rows = list_processes(limit=args.limit)
        if args.json:
            print(json.dumps(processes_as_dict(rows), ensure_ascii=False, indent=2))
        else:
            print(f"{'PID':>7}  {'RSS(MB)':>8}  {'NAME':<30}  EXE")
            for r in rows:
                rss_mb = r.rss / (1024 * 1024)
                print(f"{r.pid:>7}  {rss_mb:>8.1f}  {r.name[:30]:<30}  {r.exe}")
        return 0

    if args.cmd == "dump":
        dump_type = resolve_dump_type(args.type)
        try:
            dump_path, meta_path = dump_process_minidump(args.pid, args.out, dump_type=dump_type)
        except DumpError as e:
            print(f"[ERROR] {e}")
            print("Hint: Try running terminal as Administrator, or dump a process owned by your user.")
            return 2

        print("[OK] Dump created")
        print(f"  dump: {relpath_for_display(dump_path)}")
        print(f"  meta: {relpath_for_display(meta_path)}")
        return 0

    if args.cmd == "strings":
        in_path = args.in_path
        minlen = args.minlen
        ascii_s = extract_ascii_strings(in_path, minlen=minlen)
        uni_s = extract_utf16le_strings(in_path, minlen=minlen) if args.unicode else []
        payload = {
            "input": relpath_for_display(in_path),
            "minlen": minlen,
            "ascii_count": len(ascii_s),
            "unicode_count": len(uni_s),
            "strings": [s.__dict__ for s in (ascii_s + uni_s)],
        }
        if args.out:
            outp = ensure_parent(args.out)
            Path(outp).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"[OK] Wrote: {relpath_for_display(outp)}")
        else:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "search":
        in_path = args.in_path
        kws = _collect_keywords(args.kw, args.kws)
        hits = search_keywords(in_path, keywords=kws, context=args.context)
        payload = {
            "input": relpath_for_display(in_path),
            "keywords": kws,
            "context": args.context,
            "hits": [h.__dict__ for h in hits],
            "hit_count": len(hits),
        }
        if args.out:
            outp = ensure_parent(args.out)
            Path(outp).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"[OK] Wrote: {relpath_for_display(outp)}")
        else:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "report":
        in_path = args.in_path
        kws = _collect_keywords(args.kw, args.kws)
        outdir = Path(args.outdir)
        outdir.mkdir(parents=True, exist_ok=True)

        findings = build_findings(
            dump_path=in_path,
            minlen=args.minlen,
            extract_unicode=args.unicode,
            keywords=kws,
            context=args.context,
        )

        base = Path(in_path).name
        json_out = outdir / f"{base}.report.json"
        html_out = outdir / f"{base}.report.html"

        wrote = []
        if args.format in ("json", "both"):
            write_json_report(findings, str(json_out))
            wrote.append(relpath_for_display(json_out))
        if args.format in ("html", "both"):
            write_html_report(findings, str(html_out))
            wrote.append(relpath_for_display(html_out))

        print("[OK] Report generated:")
        for w in wrote:
            print(f"  - {w}")
        return 0

    return 1


def _collect_keywords(single_kw: str, kw_list: List[str]) -> List[str]:
    kws: List[str] = []
    if single_kw:
        kws.append(single_kw)
    kws.extend([k for k in kw_list if k])
    if not kws:
        kws = list(DEFAULT_KEYWORDS)
    # de-dup preserve order
    seen = set()
    out = []
    for k in kws:
        kl = k.lower()
        if kl not in seen:
            seen.add(kl)
            out.append(k)
    return out


if __name__ == "__main__":
    raise SystemExit(main())
