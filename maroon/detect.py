"""Component detection → AI inventory / AI-BOM and the AT-classifier signal set.

Deterministic, table-driven from knowledge/detectors/components.json. Matches:
  * python imports              (import X / from X import ...)
  * dependency manifests        (requirements.txt, pyproject.toml, package.json, ...)
  * config files by name        (mcp.json, claude_desktop_config.json, .well-known/agent.json)
  * environment-variable keys   (observability/tracing flags, etc.)
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set

from . import kb
from .ingest import Target

_IMPORT_RE = re.compile(r"^\s*(?:from\s+([a-zA-Z0-9_.]+)\s+import|import\s+([a-zA-Z0-9_.]+))")


@dataclass
class DetectedComponent:
    id: str
    category: str
    maestro_layer: int
    trust_tier: str
    at_signals: List[str] = field(default_factory=list)
    evidence: List[Dict] = field(default_factory=list)   # [{file, line, kind}]

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "category": self.category, "maestro_layer": self.maestro_layer,
            "trust_tier": self.trust_tier, "at_signals": self.at_signals,
            "evidence": self.evidence[:12],
        }


@dataclass
class Inventory:
    components: List[DetectedComponent] = field(default_factory=list)
    at_signals: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict:
        return {
            "components": [c.to_dict() for c in self.components],
            "at_signals": sorted(self.at_signals),
            "count": len(self.components),
        }


def _top_module(mod: str) -> str:
    return mod.split(".")[0] if mod else ""


def _manifest_packages(target: Target) -> Dict[str, List[Dict]]:
    """Map a declared package name -> evidence list, from dependency manifests."""
    pkgs: Dict[str, List[Dict]] = {}

    def add(name: str, file: str, line: int):
        name = name.strip().lower()
        if name:
            pkgs.setdefault(name, []).append({"file": file, "line": line, "kind": "dependency"})

    for rel in target.files:
        base = os.path.basename(rel)
        lines = target.read_lines(rel)
        if base == "requirements.txt":
            for i, ln in enumerate(lines, 1):
                s = ln.strip()
                if s and not s.startswith("#"):
                    name = re.split(r"[=<>!~\[ ]", s, 1)[0]
                    add(name, rel, i)
        elif base in ("pyproject.toml", "Pipfile"):
            for i, ln in enumerate(lines, 1):
                mobj = re.match(r'\s*["\']?([A-Za-z0-9_.\-]+)["\']?\s*[=>~]', ln)
                if mobj and "=" in ln:
                    add(mobj.group(1), rel, i)
        elif base == "package.json":
            for i, ln in enumerate(lines, 1):
                mobj = re.match(r'\s*"(@?[A-Za-z0-9_.\-/]+)"\s*:\s*"', ln)
                if mobj:
                    add(mobj.group(1), rel, i)
    return pkgs


def detect(target: Target) -> Inventory:
    catalog = kb.components()
    found: Dict[str, DetectedComponent] = {}

    def ensure(cid: str, spec: Dict) -> DetectedComponent:
        if cid not in found:
            found[cid] = DetectedComponent(
                id=cid, category=spec.get("category", "unknown"),
                maestro_layer=int(spec.get("maestro_layer", 6)),
                trust_tier=spec.get("trust_tier", "internal"),
                at_signals=list(spec.get("at_signals", [])),
            )
        return found[cid]

    # Pre-index import module -> component id, package -> component id, config name -> id
    import_index: Dict[str, str] = {}
    package_index: Dict[str, str] = {}
    config_index: Dict[str, str] = {}
    envkey_index: Dict[str, str] = {}
    for cid, spec in catalog.items():
        for imp in spec.get("imports", []):
            import_index[_top_module(imp)] = cid
        for pkg in spec.get("packages", []):
            package_index[pkg.lower()] = cid
        for cf in spec.get("config_files", []):
            config_index[os.path.basename(cf)] = cid
        for ek in spec.get("env_keys", []):
            envkey_index[ek] = cid

    # 1) imports in python files
    for rel in target.files:
        if not rel.endswith(".py"):
            continue
        for i, ln in enumerate(target.read_lines(rel), 1):
            m = _IMPORT_RE.match(ln)
            if not m:
                continue
            mod = _top_module(m.group(1) or m.group(2) or "")
            cid = import_index.get(mod)
            if cid:
                ensure(cid, catalog[cid]).evidence.append({"file": rel, "line": i, "kind": "import"})

    # 2) dependency manifests
    pkgs = _manifest_packages(target)
    for pkg, ev in pkgs.items():
        cid = package_index.get(pkg)
        if cid:
            comp = ensure(cid, catalog[cid])
            comp.evidence.extend(ev)

    # 3) config files by name + 4) env keys (scan text files)
    for rel in target.files:
        base = os.path.basename(rel)
        cid = config_index.get(base)
        if cid:
            ensure(cid, catalog[cid]).evidence.append({"file": rel, "line": 1, "kind": "config"})
        # .well-known/agent.json lives in a subdir
        if rel.endswith(".well-known/agent.json") and "agent_card" in catalog:
            ensure("agent_card", catalog["agent_card"]).evidence.append({"file": rel, "line": 1, "kind": "config"})
        if envkey_index and (rel.endswith((".env", ".py", ".ts", ".js", ".yaml", ".yml", ".sh")) or base.startswith(".env")):
            text = "\n".join(target.read_lines(rel))
            for ek, cid2 in envkey_index.items():
                if ek in text:
                    ensure(cid2, catalog[cid2]).evidence.append({"file": rel, "line": 1, "kind": "env"})

    inv = Inventory(components=[found[k] for k in sorted(found)])
    for comp in inv.components:
        inv.at_signals.update(comp.at_signals)
    if not inv.components:
        inv.at_signals.add("no_ai_components")
    return inv
