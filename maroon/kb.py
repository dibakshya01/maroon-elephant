"""Knowledge-pack loader. Reads the versioned JSON knowledge pack shipped inside the
package (`maroon/knowledge/`) via importlib.resources, so it works from any install
location. Pure standard library; results are cached.
"""
from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any, Dict, List, Optional

# Anchor on the `maroon` package (which has __init__.py) and join into the knowledge/
# data directory. Targeting `maroon.knowledge` directly fails on Python 3.9 because the
# data dir is not an importable package.
_PKG = "maroon"

# The core crosswalk tuple fields (all but the required core set are optional/nullable).
TUPLE_FIELDS = [
    "llm", "asi", "dsgai", "maestro_layer", "aivss", "nhi", "atlas", "attack",
    "cwe", "nist_ai_600_1", "aicm", "regulatory", "agentic_threats",
]


def _read_json(relpath: str) -> Dict[str, Any]:
    """relpath is POSIX, relative to maroon/knowledge (e.g. 'scoring/aivss.json')."""
    node = resources.files(_PKG).joinpath("knowledge")
    for part in relpath.split("/"):
        node = node.joinpath(part)
    return json.loads(node.read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def frameworks() -> Dict[str, Any]:
    return _read_json("frameworks.json")


@lru_cache(maxsize=None)
def crosswalk() -> Dict[str, Any]:
    return _read_json("crosswalk.json")


@lru_cache(maxsize=None)
def cve_fingerprints() -> Dict[str, Any]:
    return _read_json("cve_fingerprints.json")


@lru_cache(maxsize=None)
def components() -> Dict[str, Any]:
    return _read_json("detectors/components.json").get("components", {})


@lru_cache(maxsize=None)
def aivss() -> Dict[str, Any]:
    return _read_json("scoring/aivss.json")


@lru_cache(maxsize=None)
def llm_prices() -> Dict[str, Any]:
    return _read_json("scoring/llm_prices.json")


@lru_cache(maxsize=None)
def at_x_l() -> Dict[str, Any]:
    return _read_json("maturity/at_x_l.json")


@lru_cache(maxsize=None)
def greypanda_vocab() -> Dict[str, Any]:
    return _read_json("vocab/greypanda.json")


def _clean(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if not k.startswith("_") and k != "title"}


def crosswalk_tuple(control_id: str) -> Dict[str, Any]:
    """Return the cross-framework tuple for a primary control id (e.g. 'LLM01'),
    normalized so the primary id is always present. Missing fields are omitted
    (optional/nullable per spec §19.5)."""
    cw = crosswalk()
    entry = cw.get(control_id.upper())
    out: Dict[str, Any] = {"primary": control_id.upper()}
    if entry:
        out.update(_clean(entry))
    # classify the primary id's own family
    fam = _family_of(control_id.upper())
    if fam:
        out.setdefault(fam, [])
        if control_id.upper() not in out[fam]:
            out[fam] = [control_id.upper()] + list(out[fam])
    return out


def merged_tuple(control_ids: List[str]) -> Dict[str, Any]:
    """Union the crosswalk tuples for several primary control ids."""
    merged: Dict[str, Any] = {"primary": control_ids[0].upper() if control_ids else None}
    for cid in control_ids:
        t = crosswalk_tuple(cid)
        for k, v in t.items():
            if k == "primary":
                continue
            if isinstance(v, list):
                merged.setdefault(k, [])
                for item in v:
                    if item not in merged[k]:
                        merged[k].append(item)
            else:
                merged.setdefault(k, v)
    return merged


def _family_of(control_id: str) -> Optional[str]:
    if control_id.startswith("LLM"):
        return "llm"
    if control_id.startswith("ASI"):
        return "asi"
    if control_id.startswith("DSGAI"):
        return "dsgai"
    return None


def control_title(control_id: str) -> Optional[str]:
    fam = _family_of(control_id.upper())
    if not fam:
        return None
    return frameworks().get(fam, {}).get(control_id.upper())
