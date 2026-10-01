"""Scan pipeline: ingest -> detect -> analyze (native + optional sub-scanners) -> merge
-> score -> governance. Produces a ScanResult that the reporters render.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from . import analyzer, detect, ingest, model, score
from .detect import Inventory
from .ingest import Target


@dataclass
class ScanResult:
    name: str
    files: int
    inventory: Inventory
    findings: List[model.Finding]
    governance: Dict
    elapsed: float = 0.0
    subscanners: List[str] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def worst(self) -> str:
        order = ["info", "low", "medium", "high", "critical"]
        worst = "info"
        for f in self.findings:
            if order.index(f.severity) > order.index(worst):
                worst = f.severity
        return worst if self.findings else "none"


def _baseline_fingerprints(path: str) -> Set[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return set()
    out: Set[str] = set()
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            fp = res.get("partialFingerprints", {}).get("maroonElephant/v1")
            if fp:
                out.add(fp)
    return out


def scan(target_str: str, with_subscanners: bool = True, baseline: Optional[str] = None,
         ref: Optional[str] = None) -> ScanResult:
    t0 = time.time()
    target: Target = ingest.acquire(target_str, ref)
    try:
        inv = detect.detect(target)
        findings: List[model.Finding] = analyzer.analyze(target)

        subscanners_used: List[str] = []
        if with_subscanners:
            try:
                from .subscanners import greypanda
                gp_findings = greypanda.run(target)
                if gp_findings is not None:
                    findings.extend(gp_findings)
                    if gp_findings:
                        subscanners_used.append("grey-panda")
            except Exception:
                pass  # sub-scanner failures never break the native run

        findings = model.merge_findings(findings)
        for f in findings:
            score.score_finding(f)

        if baseline:
            base = _baseline_fingerprints(baseline)
            findings = [f for f in findings if f.fingerprint not in base]

        governance = score.governance_verdict(target, findings, inv)
        elapsed = time.time() - t0
        return ScanResult(
            name=target.name, files=len(target.files), inventory=inv,
            findings=findings, governance=governance, elapsed=elapsed,
            subscanners=subscanners_used,
        )
    finally:
        target.cleanup()
