"""Deterministic orchestrator for multi-repo, crown-jewels-first scanning.

Priority (worst-first): a target is P0 if its name/path matches the crown-jewels
description; P2 if it looks like docs/tests/examples; P1 otherwise. Scans run in priority
order under hard agency caps, emitting progress events. The run log is hash-chained
(tamper-evident) — the same control class Maroon Elephant checks for in others.
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .. import engine

# Hard agency caps (Build Plan §19.5 defaults).
MAX_TARGETS = 200
WALL_CLOCK_SECONDS = 1800

_WORD = re.compile(r"[a-z0-9]+")
_LOW_RISK = re.compile(r"(^|/)(docs?|examples?|samples?|tests?|fixtures?)(/|$|-)", re.IGNORECASE)


def _keywords(text: str) -> List[str]:
    stop = {"the", "our", "and", "for", "with", "that", "this", "are", "all", "service",
            "services", "app", "apps", "system", "data", "api"}
    return [w for w in _WORD.findall((text or "").lower()) if len(w) > 2 and w not in stop]


def prioritize(targets: List[str], crown_jewels: str = "") -> List[Dict]:
    kws = _keywords(crown_jewels)
    out = []
    for t in targets:
        name = t.lower()
        score = sum(1 for k in kws if k in name)
        if score > 0:
            prio = "P0"
        elif _LOW_RISK.search(t):
            prio = "P2"
        else:
            prio = "P1"
        out.append({"target": t, "priority": prio, "match_score": score})
    order = {"P0": 0, "P1": 1, "P2": 2}
    out.sort(key=lambda x: (order[x["priority"]], -x["match_score"], x["target"]))
    return out


@dataclass
class RunLog:
    """Hash-chained, tamper-evident run log."""
    entries: List[Dict] = field(default_factory=list)
    _prev: str = ""

    def add(self, kind: str, data: Dict) -> Dict:
        payload = {"ts": round(time.time(), 3), "kind": kind, **data}
        h = hashlib.sha256((self._prev + str(payload)).encode("utf-8")).hexdigest()[:16]
        entry = {**payload, "hash": h, "prev": self._prev}
        self._prev = h
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        prev = ""
        for e in self.entries:
            body = {k: v for k, v in e.items() if k not in ("hash", "prev")}
            h = hashlib.sha256((prev + str(body)).encode("utf-8")).hexdigest()[:16]
            if h != e["hash"] or e["prev"] != prev:
                return False
            prev = h
        return True


@dataclass
class Orchestrator:
    crown_jewels: str = ""
    with_subscanners: bool = True
    log: RunLog = field(default_factory=RunLog)

    def run(self, targets: List[str], on_event: Optional[Callable[[Dict], None]] = None) -> Dict:
        def emit(ev: Dict):
            e = self.log.add(ev.get("kind", "event"), ev)
            if on_event:
                on_event(e)

        targets = targets[:MAX_TARGETS]
        queue = prioritize(targets, self.crown_jewels)
        emit({"kind": "plan", "queue": queue, "crown_jewels": self.crown_jewels,
              "caps": {"max_targets": MAX_TARGETS, "wall_clock_s": WALL_CLOCK_SECONDS}})

        t0 = time.time()
        results = []
        agg = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for i, item in enumerate(queue):
            if time.time() - t0 > WALL_CLOCK_SECONDS:
                emit({"kind": "halt", "reason": "wall_clock_cap_reached"})
                break
            tgt = item["target"]
            emit({"kind": "scan_start", "index": i, "total": len(queue),
                  "target": tgt, "priority": item["priority"]})
            try:
                r = engine.scan(tgt, with_subscanners=self.with_subscanners)
                counts = r.counts()
                for k, v in counts.items():
                    agg[k] = agg.get(k, 0) + v
                summary = {
                    "target": r.name, "priority": item["priority"], "files": r.files,
                    "components": len(r.inventory.components), "findings": len(r.findings),
                    "counts": counts, "governance": r.governance,
                    "inventory": r.inventory.to_dict(),
                    "findings_detail": [f.to_dict() for f in r.findings],
                    "mermaid": _mermaid(r),
                }
                results.append(summary)
                emit({"kind": "scan_done", "index": i, "target": r.name,
                      "findings": len(r.findings), "verdict": r.governance["verdict"],
                      "priority": item["priority"], "result": summary})
            except Exception as e:
                emit({"kind": "scan_error", "index": i, "target": tgt, "error": str(e)})
        emit({"kind": "complete", "targets": len(results), "totals": agg,
              "log_verified": self.log.verify()})
        return {"results": results, "totals": agg, "queue": queue,
                "log_verified": self.log.verify(), "log": self.log.entries}


def _mermaid(result) -> str:
    from ..reporters import tmac
    return tmac.mermaid(result.inventory)
