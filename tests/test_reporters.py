"""Output format validity (SARIF 2.1.0, CycloneDX AI-BOM, TMAC)."""
import json
import os

from maroon import engine
from maroon.reporters import cyclonedx, sarif, tmac

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "benchmarks", "fixtures", "vuln_app")


def _result():
    return engine.scan(FIX, with_subscanners=False)


def test_sarif_structure():
    r = _result()
    doc = json.loads(sarif.dumps(r.findings, repo_name=r.name))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Maroon Elephant"
    assert run["results"], "no results"
    for res in run["results"]:
        assert res["ruleId"] and res["message"]["text"]
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
        assert res["partialFingerprints"]["maroonElephant/v1"]
        assert res["properties"]["security-severity"]
        assert res["level"] in ("error", "warning", "note")


def test_sarif_fingerprints_unique_per_finding():
    r = _result()
    doc = json.loads(sarif.dumps(r.findings))
    fps = [res["partialFingerprints"]["maroonElephant/v1"] for res in doc["runs"][0]["results"]]
    assert len(fps) == len(set(fps)), "duplicate fingerprints"


def test_cyclonedx_ai_bom():
    r = _result()
    doc = json.loads(cyclonedx.dumps(r.inventory, r.name))
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert doc["components"]
    assert any(p["name"] == "maroon:maestro_layer" for p in doc["components"][0]["properties"])


def test_tmac_threat_model():
    r = _result()
    doc = json.loads(tmac.dumps(r.inventory, r.findings, r.governance, r.name))
    assert doc["maroon_threat_model"] == "v1"
    assert doc["maestro_layers"]
    assert doc["governance"]["verdict"]
