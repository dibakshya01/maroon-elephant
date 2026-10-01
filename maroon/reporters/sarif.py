"""SARIF 2.1.0 emitter (hand-built JSON, zero-dep).

Carries `partialFingerprints.maroonElephant/v1` (the §19.1 fingerprint) so GitHub tracks
alerts across commits, a distinct `automationDetails.id`/category, and `security-severity`
so findings get the right severity in GitHub code scanning.
"""
from __future__ import annotations

import json
from typing import Dict, List

from .. import __version__, model

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
CATEGORY = "maroon-elephant"


def _rules(findings: List[model.Finding]) -> List[Dict]:
    seen: Dict[str, Dict] = {}
    for f in findings:
        if f.rule_id in seen:
            continue
        primaries = []
        for fam in ("llm", "asi", "dsgai"):
            primaries += (f.frameworks.get(fam) or [])
        seen[f.rule_id] = {
            "id": f.rule_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description or f.title},
            "help": {"text": f.remediation or ""},
            "defaultConfiguration": {"level": _LEVEL.get(f.severity, "warning")},
            "properties": {
                "tags": ["security", "ai", "owasp"] + primaries,
                "security-severity": str(f.severity_score if f.severity_score is not None else ""),
            },
        }
    return list(seen.values())


def build(findings: List[model.Finding], repo_name: str = "", commit: str = "", ref: str = "") -> Dict:
    results = []
    for f in findings:
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": f.line or 1},
            }
        }
        results.append({
            "ruleId": f.rule_id,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message or f.title},
            "locations": [loc],
            "partialFingerprints": {"maroonElephant/v1": f.fingerprint},
            "properties": {
                "severity": f.severity,
                "security-severity": str(f.severity_score if f.severity_score is not None else ""),
                "frameworks": f.frameworks,
                "sources": [s.to_dict() for s in f.sources],
                "correlationKey": f.correlation_key,
            },
        })
    run = {
        "tool": {"driver": {
            "name": "Maroon Elephant",
            "informationUri": "https://github.com/dibakshya01/maroon-elephant",
            "version": __version__,
            "rules": _rules(findings),
        }},
        "automationDetails": {"id": "%s/%s" % (CATEGORY, repo_name or "scan")},
        "results": results,
    }
    if commit or ref:
        vc = {"repositoryUri": "", "revisionId": commit}
        if ref:
            vc["branch"] = ref
        run["versionControlProvenance"] = [vc]
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def dumps(findings: List[model.Finding], **kw) -> str:
    return json.dumps(build(findings, **kw), indent=2)
