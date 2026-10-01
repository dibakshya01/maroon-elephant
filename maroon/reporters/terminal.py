"""Human-readable terminal report. ANSI color when the stream is a TTY; plain otherwise."""
from __future__ import annotations

import os
import sys
from typing import Dict, List

from .. import model
from ..detect import Inventory

_COLOR = {
    "critical": "\033[1;37;41m", "high": "\033[1;31m", "medium": "\033[1;33m",
    "low": "\033[0;36m", "info": "\033[0;90m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_MAROON = "\033[38;5;131m"


def _supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def render(findings: List[model.Finding], inv: Inventory, governance: Dict,
           name: str = "", elapsed: float = 0.0, files: int = 0, stream=None) -> str:
    stream = stream or sys.stdout
    color = _supports_color(stream)

    def c(txt, code):
        return (code + txt + _RESET) if color else txt

    out: List[str] = []
    out.append("")
    out.append(c("  🐘 Maroon Elephant", _MAROON + _BOLD) + c("  AI-era threat model", _DIM))
    out.append(c("  " + "─" * 58, _DIM))
    out.append("  Target: %s   (%d files, %.2fs)" % (name, files, elapsed))

    # Inventory
    out.append("")
    out.append(c("  AI Inventory", _BOLD) + "  (%d components)" % len(inv.components))
    for comp in inv.components:
        out.append("    • %-22s %s %s" % (
            comp.id, c("L%d" % comp.maestro_layer, _DIM), c(comp.category, _DIM)))
    if not inv.components:
        out.append(c("    (no AI/agentic/MCP components detected)", _DIM))

    # Findings, grouped by severity
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    out.append("")
    summary = "  ".join(c("%s %d" % (s.upper(), counts.get(s, 0)), _COLOR[s])
                        for s in ("critical", "high", "medium", "low", "info") if counts.get(s))
    out.append(c("  Findings", _BOLD) + "  (%d)   " % len(findings) + (summary or c("none", _DIM)))
    out.append("")
    order = {s: i for i, s in enumerate(["critical", "high", "medium", "low", "info"])}
    for f in sorted(findings, key=lambda x: (order.get(x.severity, 9), x.file, x.line or 0)):
        tag = c(" %-4s " % f.severity.upper()[:4], _COLOR.get(f.severity, ""))
        owasp = []
        for fam in ("llm", "asi", "dsgai"):
            owasp += (f.frameworks.get(fam) or [])
        ids = c(" ".join(owasp[:4]), _DIM)
        out.append("  %s %s%s" % (tag, c("%s:%s" % (f.file, f.line or "?"), _BOLD), "  " + ids))
        out.append("       %s" % f.message)
        srcs = ",".join(sorted(set(s.scanner for s in f.sources)))
        out.append(c("       %s  ·  score %s  ·  %s" % (
            f.rule_id, f.severity_score, srcs), _DIM))
    # Governance verdict
    out.append("")
    out.append(c("  Governance verdict", _BOLD))
    v = governance
    verdict = v["verdict"]
    bad = verdict in {"HIGH EXPOSURE", "CRITICAL GAP", "INSUFFICIENT", "DO NOT DEPLOY"}
    out.append("    Adoption tier : %s (%s)" % (v["adoption_tier"], v["adoption_tier_name"]))
    out.append("    Governance    : %s (%s)" % (v["governance_level"], v["governance_level_name"]))
    out.append("    Verdict       : %s" % c(verdict, (_COLOR["high"] if bad else "\033[1;32m")))
    if v.get("recommendation"):
        out.append("    → %s" % v["recommendation"])
    out.append("")
    return "\n".join(out)
