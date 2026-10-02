"""Self-contained HTML threat-model report (zero-dep, inline CSS) — a shareable governance
deliverable. One file, no external assets, works offline."""
from __future__ import annotations

import html as _h
from typing import Dict, List

from .. import __version__, kb, model
from ..detect import Inventory

_SEV = ["critical", "high", "medium", "low", "info"]
_SEVC = {"critical": "#c62828;color:#fff", "high": "#e5533c", "medium": "#d9a406",
         "low": "#3a97a8", "info": "#6b7280"}
_LAYER = {"1": "Foundation Models", "2": "Data Operations", "3": "Agent Frameworks",
          "4": "Deployment & Infra", "5": "Eval & Observability",
          "6": "Security & Compliance", "7": "Agent Ecosystem"}


def _ids(fw: Dict) -> str:
    out: List[str] = []
    for k in ("llm", "asi", "dsgai"):
        out += (fw.get(k) or [])
    return " ".join(out[:6])


def build(findings: List[model.Finding], inv: Inventory, governance: Dict,
          name: str = "scanned-repo", elapsed: float = 0.0) -> str:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    order = {s: i for i, s in enumerate(_SEV)}
    rows = []
    for f in sorted(findings, key=lambda x: (order.get(x.severity, 9), x.file, x.line or 0)):
        srcs = ",".join(sorted({s.scanner for s in f.sources}))
        expl = ("<div class='expl'>%s</div>" % _h.escape(f.explanation)) if f.explanation else ""
        rows.append(
            "<tr><td><span class='sev' style='background:%s'>%s</span></td>"
            "<td><code>%s:%s</code></td><td>%s%s<div class='meta'>%s · score %s · %s</div></td>"
            "<td class='ids'>%s</td></tr>" % (
                _SEVC.get(f.severity, "#888"), f.severity.upper(),
                _h.escape(f.file), f.line or "?", _h.escape(f.message or f.title), expl,
                _h.escape(f.rule_id), f.severity_score if f.severity_score is not None else "-",
                _h.escape(srcs), _h.escape(_ids(f.frameworks))))
    comp_rows = "".join(
        "<tr><td><code>%s</code></td><td>%s</td><td>L%s · %s</td><td>%s</td></tr>" % (
            _h.escape(c.id), _h.escape(c.category), c.maestro_layer,
            _h.escape(_LAYER.get(str(c.maestro_layer), "")), _h.escape(c.trust_tier))
        for c in inv.components) or "<tr><td colspan=4 class='muted'>no AI/agentic/MCP components detected</td></tr>"
    g = governance
    bad = g.get("verdict") in {"HIGH EXPOSURE", "CRITICAL GAP", "INSUFFICIENT", "DO NOT DEPLOY"}
    summary = " ".join(
        "<span class='pill' style='background:%s'>%s %d</span>" % (_SEVC.get(s, "#888"), s.upper(), counts[s])
        for s in _SEV if counts.get(s))
    return _TEMPLATE % {
        "name": _h.escape(name), "version": __version__, "elapsed": "%.2f" % elapsed,
        "ncomp": len(inv.components), "nfind": len(findings),
        "summary": summary or "<span class='muted'>no findings</span>",
        "verdict": _h.escape(g.get("verdict", "?")), "verdict_cls": "bad" if bad else "good",
        "tier": _h.escape(g.get("adoption_tier", "")), "tier_name": _h.escape(g.get("adoption_tier_name", "")),
        "level": _h.escape(g.get("governance_level", "")), "level_name": _h.escape(g.get("governance_level_name", "")),
        "rec": _h.escape(g.get("recommendation") or ""),
        "rows": "".join(rows) or "<tr><td colspan=4 class='muted'>No findings 🎉</td></tr>",
        "comp_rows": comp_rows,
    }


def dumps(findings, inv, governance, name="scanned-repo", elapsed=0.0) -> str:
    return build(findings, inv, governance, name, elapsed)


_TEMPLATE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Maroon Elephant report — %(name)s</title><style>
:root{--bg:#0f0a0b;--card:#1b1215;--line:#39222a;--ink:#f3e9eb;--muted:#b79aa1;--maroon:#c13a48;--accent:#e07783}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:28px 20px 70px}
h1{font-size:22px;margin:0 0 2px}h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:30px 0 10px}
.sub{color:var(--muted);font-size:13px}.muted{color:var(--muted)}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin-top:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;flex:1;min-width:200px}
.big{font-size:26px;font-weight:800}.bad{color:#e5533c}.good{color:#49c17c}
.pill{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700;color:#fff;margin:2px}
table{width:100%%;border-collapse:collapse;font-size:13px;margin-top:8px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em}
code{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--accent)}
.sev{padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap}
.meta{color:var(--muted);font-family:ui-monospace,monospace;font-size:11px;margin-top:3px}
.ids{color:var(--muted);font-family:ui-monospace,monospace;font-size:11px}
.expl{color:var(--muted);font-size:12px;margin-top:6px;border-left:2px solid var(--line);padding-left:8px}
footer{margin-top:40px;color:var(--muted);font-size:12px}
</style></head><body><div class=wrap>
<h1>🐘 Maroon Elephant — Threat Model Report</h1>
<div class=sub>%(name)s · v%(version)s · %(elapsed)ss</div>
<div class=cards>
<div class=card><div class=muted>Findings</div><div class=big>%(nfind)d</div><div>%(summary)s</div></div>
<div class=card><div class=muted>AI components</div><div class=big>%(ncomp)d</div></div>
<div class=card><div class=muted>Governance verdict</div><div class="big %(verdict_cls)s">%(verdict)s</div>
<div class=sub>Tier %(tier)s · %(tier_name)s<br>Maturity %(level)s · %(level_name)s</div></div>
</div>
<p class=sub>%(rec)s</p>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Location</th><th>Finding</th><th>OWASP</th></tr></thead>
<tbody>%(rows)s</tbody></table>
<h2>AI Inventory</h2>
<table><thead><tr><th>Component</th><th>Category</th><th>MAESTRO layer</th><th>Trust tier</th></tr></thead>
<tbody>%(comp_rows)s</tbody></table>
<footer>Generated by Maroon Elephant · deterministic-first · OWASP-2026 / MAESTRO / AIVSS. Every finding carries file:line evidence and a cross-framework tuple.</footer>
</div></body></html>"""
