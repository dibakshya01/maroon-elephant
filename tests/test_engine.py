"""End-to-end scan behavior against the pre-registered fixtures (benchmarks/LABELS.json)."""
import json
import os

import pytest

from maroon import engine

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "benchmarks", "fixtures")
LABELS = json.load(open(os.path.join(ROOT, "benchmarks", "LABELS.json")))


def _scan(name):
    return engine.scan(os.path.join(FIX, name), with_subscanners=False)


def test_vuln_app_fires_all_registered_rules():
    r = _scan("vuln_app")
    fired = {f.rule_id for f in r.findings}
    missing = set(LABELS["vuln_app"]["must_fire_rules"]) - fired
    assert not missing, "rules failed to fire: %s" % sorted(missing)


def test_vuln_app_governance():
    r = _scan("vuln_app")
    assert r.governance["adoption_tier"] == LABELS["vuln_app"]["expected_tier"]
    assert r.governance["verdict"] == LABELS["vuln_app"]["expected_verdict"]


def test_clean_app_no_false_positives():
    r = _scan("clean_app")
    assert len(r.findings) == LABELS["clean_app"]["max_findings"], \
        [f.rule_id + "@" + f.file + ":" + str(f.line) for f in r.findings]


def test_findings_have_evidence_and_crosswalk():
    r = _scan("vuln_app")
    for f in r.findings:
        assert f.file and f.fingerprint
        assert f.severity in ("info", "low", "medium", "high", "critical")
        assert f.frameworks.get("primary"), f.rule_id


def test_inventory_detects_components():
    r = _scan("vuln_app")
    ids = {c.id for c in r.inventory.components}
    assert {"langchain", "openai_sdk", "mcp_client_config", "qdrant"} <= ids


def test_ai_bom_at_signals():
    r = _scan("vuln_app")
    assert "mcp_client_config" in r.inventory.at_signals
