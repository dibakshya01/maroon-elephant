"""Maroon Elephant command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__, model
from .model import SEVERITY_RANK

_BANNER = "🐘 Maroon Elephant %s — AI-era threat modeling (OWASP-2026)" % __version__


def _write(text: str, out: Optional[str]) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
    else:
        sys.stdout.write(text + "\n")


def _combined_json(result) -> str:
    return json.dumps({
        "tool": "maroon-elephant", "version": __version__,
        "target": result.name, "files": result.files, "elapsed_seconds": round(result.elapsed, 3),
        "subscanners": result.subscanners,
        "inventory": result.inventory.to_dict(),
        "governance": result.governance,
        "findings": [f.to_dict() for f in result.findings],
        "summary": result.counts(),
    }, indent=2)


def cmd_scan(args: argparse.Namespace) -> int:
    from . import engine
    from .reporters import cyclonedx, sarif, terminal, tmac
    try:
        result = engine.scan(args.target, with_subscanners=not args.no_subscanners,
                             baseline=args.baseline, ref=args.ref)
    except ValueError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2

    fmt = args.format
    if fmt == "sarif":
        _write(sarif.dumps(result.findings, repo_name=result.name, ref=args.ref or ""), args.output)
    elif fmt == "cyclonedx":
        _write(cyclonedx.dumps(result.inventory, result.name), args.output)
    elif fmt == "tmac":
        _write(tmac.dumps(result.inventory, result.findings, result.governance, result.name), args.output)
    elif fmt == "mermaid":
        _write(tmac.mermaid(result.inventory), args.output)
    elif fmt == "json":
        _write(_combined_json(result), args.output)
    else:
        text = terminal.render(result.findings, result.inventory, result.governance,
                               name=result.name, elapsed=result.elapsed, files=result.files)
        _write(text, args.output)

    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK.get(f.severity, 0) >= threshold for f in result.findings):
            return 1
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    from .analyzer import _load_rules
    rules = sorted(_load_rules(), key=lambda r: r["id"])
    if args.format == "json":
        _write(json.dumps(rules, indent=2), None)
        return 0
    print(_BANNER)
    print("%d rules:\n" % len(rules))
    for r in rules:
        prim = r.get("primary", "")
        print("  %-32s %-8s %s" % (r["id"], r.get("severity", ""), prim))
        print("      %s" % r.get("title", ""))
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    print(_BANNER)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .ui import server
    return server.serve(host=args.host, port=args.port, open_browser=not args.no_open)


def cmd_serve_mcp(args: argparse.Namespace) -> int:
    from .mcpserver import server
    return server.serve()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="maroon", description=_BANNER)
    p.add_argument("--version", action="version", version=_BANNER)
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan a repo (path, git URL, or .zip)")
    s.add_argument("target", help="local path, git URL, or .zip file")
    s.add_argument("-f", "--format", default="terminal",
                   choices=["terminal", "sarif", "cyclonedx", "tmac", "mermaid", "json"])
    s.add_argument("-o", "--output", help="write to a file instead of stdout")
    s.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"],
                   help="exit 1 if any finding is at/above this severity")
    s.add_argument("--baseline", help="a prior SARIF file; suppress its findings (diff-aware)")
    s.add_argument("--no-subscanners", action="store_true", help="native rules only (skip grey-panda etc.)")
    s.add_argument("--ref", help="git ref/branch for SARIF versionControlProvenance")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("rules", help="list the loaded rules")
    r.add_argument("-f", "--format", default="text", choices=["text", "json"])
    r.set_defaults(func=cmd_rules)

    v = sub.add_parser("version", help="show version")
    v.set_defaults(func=cmd_version)

    sv = sub.add_parser("serve", help="Enterprise: local web dashboard")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=7879)
    sv.add_argument("--no-open", action="store_true", help="do not open a browser")
    sv.set_defaults(func=cmd_serve)

    m = sub.add_parser("serve-mcp", help="run Maroon Elephant's own MCP server (stdio)")
    m.set_defaults(func=cmd_serve_mcp)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
