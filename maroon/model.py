"""Core finding model + the deterministic identity functions (Build Plan §19.1).

Two keys, both line-number- and host-FS-independent, computed identically for every
finding class (Python, config, IaC, Dockerfile, secret, grey-panda), purely lexical,
NO AST required:

  * correlation_key  -- rule_id-free; groups findings across sources so ME-native and
                        grey-panda findings on the same span MERGE.
  * fingerprint      -- post-merge, includes the canonical rule_id; stable per-alert
                        identity for SARIF partialFingerprints and `--baseline`.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

_WS = re.compile(r"\s+")


# --------------------------------------------------------------------------- #
# Identity primitives (§19.1)
# --------------------------------------------------------------------------- #
def normalize_text(text: str) -> str:
    """Lexical normalization: per line strip + collapse internal whitespace, drop
    blank lines, join with '\\n'. No comment-strip, no AST — works for any language."""
    out: List[str] = []
    for raw in text.splitlines():
        collapsed = _WS.sub(" ", raw.strip())
        if collapsed:
            out.append(collapsed)
    return "\n".join(out)


def normalize_path(path: str) -> str:
    """Repo-relative POSIX path, case PRESERVED (host-FS-independent)."""
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def evidence_digest_from_lines(file_lines: List[str], line: int, window: int = 2) -> str:
    """Digest over file lines [line-2 .. line+2] (1-indexed), re-extracted from the file
    so every source hashes identical input."""
    if line is None or line < 1:
        return _sha256_hex(normalize_text("\n".join(file_lines[:window])))
    lo = max(0, (line - 1) - window)
    hi = min(len(file_lines), (line - 1) + window + 1)
    return _sha256_hex(normalize_text("\n".join(file_lines[lo:hi])))


def evidence_digest_from_token(token: str) -> str:
    """No-line fallback for dependency/CVE/config-key findings (e.g. 'pkg@1.2.3')."""
    return _sha256_hex(normalize_text(token))


def correlation_key(primary: str, norm_path: str, evidence_digest: str, occurrence: int = 0) -> str:
    """Cross-source merge key: rule_id-free (so ME-native and grey-panda findings of the
    SAME issue class on the same span merge) but keyed on the primary OWASP id (so two
    DIFFERENT issue classes on the same line stay distinct) AND on the occurrence index (so
    two IDENTICAL code blocks at different lines stay distinct — they are different findings,
    not one). First 32 hex chars (128-bit)."""
    return _sha256_hex((primary or "") + "\x00" + norm_path + "\x00" + evidence_digest
                       + "\x00#" + str(occurrence))[:32]


def fingerprint(canonical_rule_id: str, norm_path: str, evidence_digest: str, occurrence: int = 0) -> str:
    """Per-alert identity for SARIF partialFingerprints + baseline (first 32 hex chars).
    Includes the occurrence index so a newly-added duplicate of an existing finding gets a
    DISTINCT fingerprint and is NOT suppressed by --baseline."""
    return _sha256_hex(canonical_rule_id + "\x00" + norm_path + "\x00" + evidence_digest
                       + "\x00#" + str(occurrence))[:32]


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Source:
    """One scanner's contribution to a (possibly merged) finding."""
    scanner: str                       # "maroon" | "grey-panda" | "semgrep" | ...
    rule_id: str
    owasp_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {"scanner": self.scanner, "rule_id": self.rule_id}
        if self.owasp_id:
            d["owasp_id"] = self.owasp_id
        return d


@dataclass
class Finding:
    """A single deterministic finding. `rule_id` is the canonical (post-merge) rule id."""
    rule_id: str
    title: str
    severity: str
    file: str
    line: Optional[int] = None
    end_line: Optional[int] = None
    message: str = ""
    description: str = ""
    remediation: str = ""
    confidence: str = "medium"
    evidence_digest: str = ""
    evidence_token: Optional[str] = None      # for no-line findings
    frameworks: Dict[str, Any] = field(default_factory=dict)
    sources: List[Source] = field(default_factory=list)
    severity_score: Optional[float] = None
    derived_factors: Dict[str, Any] = field(default_factory=dict)
    maestro_layer: Optional[int] = None
    occurrence: int = 0   # index among identical findings at distinct lines (set by assign_occurrences)
    explanation: Optional[str] = None   # optional, evidence-gated LLM enrichment (never a source of findings)

    def __post_init__(self) -> None:
        self.file = normalize_path(self.file)
        if self.severity not in SEVERITY_RANK:
            self.severity = "medium"
        if not self.sources:
            self.sources = [Source("maroon", self.rule_id,
                                    (self.frameworks.get("primary") if self.frameworks else None))]

    @property
    def primary(self) -> str:
        if self.frameworks and self.frameworks.get("primary"):
            return self.frameworks["primary"]
        if self.sources and self.sources[0].owasp_id:
            return self.sources[0].owasp_id.split(":")[0].upper()
        return ""

    @property
    def correlation_key(self) -> str:
        return correlation_key(self.primary, self.file, self.evidence_digest, self.occurrence)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.rule_id, self.file, self.evidence_digest, self.occurrence)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "severity_score": self.severity_score,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "message": self.message,
            "description": self.description,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint,
            "correlation_key": self.correlation_key,
            "frameworks": self.frameworks,
            "sources": [s.to_dict() for s in self.sources],
            "derived_factors": self.derived_factors,
            "maestro_layer": self.maestro_layer,
            "explanation": self.explanation,
        }


def _severity_max(a: str, b: str) -> str:
    return a if SEVERITY_RANK.get(a, 0) >= SEVERITY_RANK.get(b, 0) else b


def _union_frameworks(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in set(a) | set(b):
        va, vb = a.get(key), b.get(key)
        if isinstance(va, list) or isinstance(vb, list):
            merged = list(dict.fromkeys((va or []) + (vb or [])))
            out[key] = merged
        else:
            out[key] = va if va is not None else vb
    return out


def assign_occurrences(findings: List[Finding]) -> None:
    """Disambiguate identical findings at different lines. Group by (primary, file,
    evidence_digest); within each group, rank by DISTINCT line number. Each finding's
    `occurrence` = the rank of its line. Same-line findings (e.g. ME + grey-panda) share an
    occurrence so they still merge; identical blocks at different lines get distinct
    occurrences so neither is lost to merge or hidden by --baseline. Line-number-independent:
    a lone finding is always occurrence 0 regardless of where it sits."""
    groups: Dict[tuple, List[Finding]] = {}
    for f in findings:
        groups.setdefault((f.primary, f.file, f.evidence_digest), []).append(f)
    for group in groups.values():
        distinct_lines = sorted({f.line for f in group if f.line is not None})
        line_rank = {ln: i for i, ln in enumerate(distinct_lines)}
        for f in group:
            f.occurrence = line_rank.get(f.line, 0) if f.line is not None else 0


def merge_findings(findings: List[Finding]) -> List[Finding]:
    """Group by correlation_key (§19.3). ME-native metadata is authoritative for the
    crosswalk tuple and canonical rule_id; grey-panda etc. are recorded in sources[].
    Neither is dropped; severity is the max; frameworks are unioned."""
    groups: Dict[str, Finding] = {}
    for f in findings:
        key = f.correlation_key
        if key not in groups:
            groups[key] = f
            continue
        base = groups[key]
        base_is_native = any(s.scanner == "maroon" for s in base.sources)
        incoming_is_native = any(s.scanner == "maroon" for s in f.sources)
        # Canonical finding prefers the ME-native one.
        if incoming_is_native and not base_is_native:
            base, f = f, base
            groups[key] = base
        # merge
        existing = {(s.scanner, s.rule_id) for s in base.sources}
        for s in f.sources:
            if (s.scanner, s.rule_id) not in existing:
                base.sources.append(s)
                existing.add((s.scanner, s.rule_id))
        base.severity = _severity_max(base.severity, f.severity)
        base.frameworks = _union_frameworks(base.frameworks, f.frameworks)
        if not base.remediation and f.remediation:
            base.remediation = f.remediation
    return list(groups.values())
