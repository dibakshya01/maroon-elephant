"""Severity scoring (AIVSS v0.8 anchor) + the deterministic AT x L governance classifier.

Severity label stays the rule's curated value; `severity_score` is a deterministic 0-10
AIVSS-anchored number (used for SARIF security-severity). The AT x L classifier is fully
table-driven from knowledge/maturity/at_x_l.json.
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional, Set

from . import kb, model
from .detect import Inventory
from .ingest import Target

_SEV_POINTS = {"critical": 9.5, "high": 8.0, "medium": 5.0, "low": 2.5, "info": 0.5}


def score_finding(f: model.Finding) -> None:
    a = kb.aivss()
    weights = a.get("rule_base_weights", {})
    prim = (f.frameworks.get("primary") if f.frameworks else None) or (
        f.sources[0].owasp_id if f.sources else None)
    key = None
    if prim in weights:
        key = prim
    elif prim and str(prim).startswith("DSGAI"):
        key = "DSGAI"
    base = float(weights.get(key, 6.0))
    f.severity_score = round(0.5 * base + 0.5 * _SEV_POINTS.get(f.severity, 5.0), 1)
    core = a.get("aivss_core_risk_default_map", {}).get(prim)
    f.derived_factors = {
        "aivss_core_risk": core,
        "aars_factors": "defaulted (autonomy/oversight/blast-radius not derivable from static code)",
    }


# --------------------------------------------------------------------------- #
# AT x L governance classifier
# --------------------------------------------------------------------------- #
def classify_at(at_signals: Set[str]) -> str:
    cfg = kb.at_x_l()
    for rule in cfg["at_classifier"]["rules"]:
        if set(rule.get("when_any", [])) & set(at_signals):
            return rule["tier"]
    return "AT0"


def _detect_controls(target: Target, findings: List[model.Finding], inv: Inventory) -> Dict[str, str]:
    """Return {control: present|absent|needs-attestation}. Conservative: a control is
    only 'present' with positive evidence; a contradicting finding marks it 'absent';
    otherwise 'needs-attestation' (never silently counted as present)."""
    rule_ids = {f.rule_id for f in findings}
    files = set(target.files)
    basenames = {os.path.basename(p) for p in files}

    def any_file(names: Set[str]) -> bool:
        return bool(names & basenames)

    controls: Dict[str, str] = {}

    # dependency pinning: lockfile present and no unpinned-model finding
    lock = any_file({"poetry.lock", "package-lock.json", "Pipfile.lock", "pnpm-lock.yaml", "go.sum", "Cargo.lock"})
    controls["dependency_pinning"] = "present" if (lock and "ME-LLM04-unpinned-model-ref" not in rule_ids) else (
        "absent" if "ME-LLM04-unpinned-model-ref" in rule_ids else "needs-attestation")

    # secret management: contradicted by a hardcoded-secret finding
    controls["secret_management"] = "absent" if "ME-LLM08-hardcoded-secret" in rule_ids else "needs-attestation"

    # HITL gates: contradicted by an auto-approve/HITL-bypass finding
    controls["hitl_gates"] = "absent" if ("ME-ASI02-hitl-bypass" in rule_ids or "ME-MCP-client-config" in rule_ids) else "needs-attestation"

    # rate/cost caps: contradicted by an unbounded-agent finding
    controls["rate_cost_caps"] = "absent" if "ME-LLM06-unbounded-agent" in rule_ids else "needs-attestation"

    # SBOM/AIBOM present if an SBOM file exists
    controls["sbom_aibom"] = "present" if any_file(
        {"sbom.json", "bom.json", "cyclonedx.json", "sbom.spdx.json", "aibom.json"}) else "needs-attestation"

    for c in ("audit_logging", "redaction_middleware", "per_agent_identity", "policy_as_code",
              "tenant_isolation", "schema_validation", "kill_switch"):
        controls[c] = "needs-attestation"

    # Positive evidence from declared dependencies (lets a well-built repo rise above L0/L1).
    try:
        from .detect import _manifest_packages
        pkgs = set(_manifest_packages(target).keys())
    except Exception:
        pkgs = set()
    vault = {"hvac", "boto3", "azure-keyvault", "azure-keyvault-secrets",
             "google-cloud-secret-manager", "keyring", "python-dotenv"}
    if pkgs & vault and "ME-LLM08-hardcoded-secret" not in rule_ids:
        controls["secret_management"] = "present"
    if pkgs & {"pydantic", "marshmallow", "jsonschema", "zod"}:
        controls["schema_validation"] = "present"
    if pkgs & {"opa", "open-policy-agent", "opal"}:
        controls["policy_as_code"] = "present"
    return controls


def classify_l(controls: Dict[str, str]) -> str:
    cfg = kb.at_x_l()
    present = {k for k, v in controls.items() if v == "present"}
    best = "L0"
    for level in sorted(cfg["l_classifier"]["levels"], key=lambda x: x["level"]):
        if set(level["requires_all"]).issubset(present):
            if level["level"] > best:
                best = level["level"]
    return best


def _tier_bucket(tier: str) -> str:
    n = int(tier[2:])
    if n <= 2:
        return "low"
    if n <= 5:
        return "mid"
    if n <= 7:
        return "high"
    return "extreme"


def governance_verdict(target: Target, findings: List[model.Finding], inv: Inventory) -> Dict:
    cfg = kb.at_x_l()
    tier = classify_at(inv.at_signals)
    controls = _detect_controls(target, findings, inv)
    level = classify_l(controls)
    bucket = _tier_bucket(tier)
    cell = cfg["matrix"].get(bucket, {}).get(level, "Unknown")
    missing = [k for k, v in controls.items() if v != "present"]
    negative = cell in {"HIGH EXPOSURE", "CRITICAL GAP", "INSUFFICIENT", "DO NOT DEPLOY"}
    rec = None
    if negative:
        rec = ("Raise maturity: the highest-leverage missing control is '%s'. "
               % (missing[0] if missing else "audit_logging"))
        if bucket == "extreme" and level < "L3":
            rec += "Also reduce tier (gate federation / remove unapproved external agents) until L3+."
    return {
        "adoption_tier": tier,
        "adoption_tier_name": cfg["adoption_tiers"].get(tier),
        "governance_level": level,
        "governance_level_name": cfg["governance_levels"].get(level),
        "verdict": cell,
        "controls": controls,
        "recommendation": rec,
        "note": "AISVS (gp verify) is a separate verification-depth axis, not this L0-L4 maturity.",
    }
