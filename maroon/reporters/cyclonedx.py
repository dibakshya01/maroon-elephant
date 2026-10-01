"""CycloneDX AI/ML-BOM emitter (hand-built JSON, zero-dep).

Emits a CycloneDX 1.5 document whose components are the detected AI/agentic/MCP/data
components, typed as machine-learning-model / data / library, with MAESTRO layer and
trust tier as properties. This is the AI inventory deliverable.
"""
from __future__ import annotations

import datetime
import json
from typing import Dict, List

from .. import __version__
from ..detect import Inventory

_TYPE = {
    "model_sdk": "library", "model_runtime": "machine-learning-model",
    "model_serving": "machine-learning-model", "model_gateway": "library",
    "agent_framework": "library", "code_exec_agent": "library",
    "vector_db": "data", "finetune": "library", "observability": "library",
    "mcp": "library", "mcp_config": "library", "a2a": "library", "lowcode": "application",
}


def build(inv: Inventory, name: str = "scanned-repo") -> Dict:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    components: List[Dict] = []
    for c in inv.components:
        ev = c.evidence[0] if c.evidence else {}
        components.append({
            "type": _TYPE.get(c.category, "library"),
            "name": c.id,
            "bom-ref": "me:comp:%s" % c.id,
            "properties": [
                {"name": "maroon:category", "value": c.category},
                {"name": "maroon:maestro_layer", "value": str(c.maestro_layer)},
                {"name": "maroon:trust_tier", "value": c.trust_tier},
                {"name": "maroon:at_signals", "value": ",".join(c.at_signals)},
                {"name": "maroon:evidence", "value": "%s:%s" % (ev.get("file", ""), ev.get("line", ""))},
            ],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "Maroon Elephant", "name": "maroon", "version": __version__}],
            "component": {"type": "application", "name": name, "bom-ref": "me:root"},
            "properties": [{"name": "maroon:bom_type", "value": "AI-BOM"}],
        },
        "components": components,
    }


def dumps(inv: Inventory, name: str = "scanned-repo") -> str:
    return json.dumps(build(inv, name), indent=2)
