"""Maroon Elephant MCP server — stdio, newline-delimited JSON-RPC 2.0, stdlib only.

Exposes Maroon Elephant as MCP tools so coding agents / IDEs / Copilot can threat-model a
repo in-editor. Protocol 2025-06-18 (negotiates down). stdout carries protocol only; logs
go to stderr.

Register (Claude Code):  claude mcp add maroon -- maroon serve-mcp
Or config:               {"mcpServers": {"maroon": {"command": "maroon", "args": ["serve-mcp"]}}}

Tools:
  maroon_scan_path(path, format)   -> scan a repo path; format = summary|json
  maroon_explain_risk(control_id)  -> crosswalk + title for an OWASP id (e.g. LLM01, ASI02)
  maroon_list_rules()              -> the loaded rule catalog
  maroon_governance(path)          -> the AT x L governance verdict for a path
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, List

from .. import __version__, kb

SUPPORTED = ["2025-06-18", "2025-03-26", "2024-11-05"]

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "maroon_scan_path",
        "description": "Threat-model a local repo/path with Maroon Elephant: AI/agentic/MCP "
                       "component inventory + OWASP-2026 findings + AT x L governance verdict.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local directory to scan."},
                "format": {"type": "string", "enum": ["summary", "json"], "default": "summary"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "maroon_explain_risk",
        "description": "Explain an OWASP risk id (LLM01-10, ASI01-10, DSGAI01-21) with its "
                       "title and cross-framework mapping (MAESTRO/AIVSS/ATLAS/CWE/...).",
        "inputSchema": {
            "type": "object",
            "properties": {"control_id": {"type": "string"}},
            "required": ["control_id"],
        },
    },
    {
        "name": "maroon_list_rules",
        "description": "List Maroon Elephant's detection rules.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "maroon_governance",
        "description": "Return the AT x L governance verdict (adoption tier x maturity) for a path.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
]


def _text(s: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": s}]}


def _scan_summary(path: str) -> str:
    from .. import engine
    r = engine.scan(path, with_subscanners=True)
    lines = ["Maroon Elephant scan of %s" % r.name,
             "Components: %d | Findings: %d | %s" % (
                 len(r.inventory.components), len(r.findings),
                 "  ".join("%s:%d" % (k.upper(), v) for k, v in sorted(r.counts().items()))),
             "Governance: %s x %s -> %s" % (
                 r.governance["adoption_tier"], r.governance["governance_level"],
                 r.governance["verdict"])]
    for f in sorted(r.findings, key=lambda x: x.severity)[:40]:
        prim = f.frameworks.get("primary", "")
        lines.append("  [%s] %s:%s %s (%s)" % (f.severity.upper()[:4], f.file, f.line, prim, f.rule_id))
    return "\n".join(lines)


def _call_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    try:
        if name == "maroon_scan_path":
            if args.get("format") == "json":
                from .. import engine
                r = engine.scan(args["path"], with_subscanners=True)
                return _text(json.dumps({
                    "target": r.name, "inventory": r.inventory.to_dict(),
                    "governance": r.governance,
                    "findings": [f.to_dict() for f in r.findings],
                }, indent=2))
            return _text(_scan_summary(args["path"]))
        if name == "maroon_explain_risk":
            cid = args["control_id"].strip().upper().split(":")[0]
            tup = kb.crosswalk_tuple(cid)
            title = kb.control_title(cid)
            return _text(json.dumps({"id": cid, "title": title, "crosswalk": tup}, indent=2))
        if name == "maroon_list_rules":
            from ..analyzer import _load_rules
            rules = [{"id": r["id"], "title": r["title"], "severity": r.get("severity"),
                      "primary": r.get("primary")} for r in _load_rules()]
            return _text(json.dumps(rules, indent=2))
        if name == "maroon_governance":
            from .. import engine
            r = engine.scan(args["path"], with_subscanners=False)
            return _text(json.dumps(r.governance, indent=2))
        return {"content": [{"type": "text", "text": "unknown tool: %s" % name}], "isError": True}
    except Exception as e:  # tools never crash the server
        return {"content": [{"type": "text", "text": "error: %s" % e}], "isError": True}


def _handle(msg: Dict[str, Any]) -> Dict[str, Any]:
    mid = msg.get("id")
    method = msg.get("method")
    if method == "initialize":
        client = (msg.get("params") or {}).get("protocolVersion")
        proto = client if client in SUPPORTED else SUPPORTED[0]
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": proto,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "maroon-elephant", "version": __version__},
        }}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        result = _call_tool(params.get("name", ""), params.get("arguments") or {})
        return {"jsonrpc": "2.0", "id": mid, "result": result}
    if method in ("notifications/initialized", "initialized"):
        return None  # notification, no response
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": "method not found: %s" % method}}


def serve() -> int:
    sys.stderr.write("maroon-elephant MCP server %s ready (%d tools, stdio JSON-RPC)\n"
                     % (__version__, len(TOOLS)))
    sys.stderr.flush()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = _handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0
