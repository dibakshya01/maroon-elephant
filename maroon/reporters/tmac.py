"""Threat-model-as-code emitter: a diffable JSON model of components (by MAESTRO layer),
findings-as-threats, and the governance verdict. Reviewable in PRs, re-runnable.
"""
from __future__ import annotations

import json
from typing import Dict, List

from .. import kb, model
from ..detect import Inventory


def build(inv: Inventory, findings: List[model.Finding], governance: Dict, name: str = "scanned-repo") -> Dict:
    layers = kb.frameworks().get("maestro_layers", {})
    by_layer: Dict[str, Dict] = {}
    for c in inv.components:
        key = str(c.maestro_layer)
        by_layer.setdefault(key, {"layer": c.maestro_layer, "name": layers.get(key, "?"),
                                  "components": [], "threats": []})
        by_layer[key]["components"].append(c.id)
    for f in findings:
        key = str(f.maestro_layer) if f.maestro_layer else "6"
        by_layer.setdefault(key, {"layer": int(key), "name": layers.get(key, "?"),
                                  "components": [], "threats": []})
        by_layer[key]["threats"].append({
            "rule": f.rule_id, "title": f.title, "severity": f.severity,
            "file": f.file, "line": f.line, "owasp": f.frameworks.get("primary"),
            "fingerprint": f.fingerprint,
        })
    return {
        "maroon_threat_model": "v1",
        "target": name,
        "maestro_layers": [by_layer[k] for k in sorted(by_layer, key=lambda x: int(x))],
        "governance": governance,
        "summary": {
            "components": len(inv.components),
            "threats": len(findings),
        },
    }


def dumps(inv: Inventory, findings: List[model.Finding], governance: Dict, name: str = "scanned-repo") -> str:
    return json.dumps(build(inv, findings, governance, name), indent=2)


def mermaid(inv: Inventory) -> str:
    """A Mermaid diagram of components grouped by MAESTRO layer."""
    layers = kb.frameworks().get("maestro_layers", {})
    lines = ["graph TD"]
    groups: Dict[str, List[str]] = {}
    for c in inv.components:
        groups.setdefault(str(c.maestro_layer), []).append(c.id)
    for lk in sorted(groups, key=lambda x: int(x)):
        lines.append('  subgraph L%s["L%s %s"]' % (lk, lk, layers.get(lk, "")))
        for cid in groups[lk]:
            lines.append('    %s["%s"]' % (cid.replace("-", "_"), cid))
        lines.append("  end")
    return "\n".join(lines)
