"""Tests for the finishing features: CVE version comparison + HTML report."""
import json
import os
import tempfile

from maroon import analyzer, engine, ingest
from maroon.reporters import html


def _scan_reqs(contents):
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "requirements.txt"), "w") as fh:
        fh.write(contents)
    return analyzer.analyze(ingest.from_path(d))


def test_cve_patched_version_not_flagged():
    fs = _scan_reqs("qdrant-client==2.0.0\n")   # affected <1.9.0 -> patched
    assert not [f for f in fs if f.rule_id == "ME-SCA-known-cve"]


def test_cve_vulnerable_version_flagged():
    fs = _scan_reqs("qdrant-client==1.8.0\n")   # affected <1.9.0 -> vulnerable
    cve = [f for f in fs if f.rule_id == "ME-SCA-known-cve"]
    assert cve and "CVE-2024-3584" in cve[0].message


def test_cve_unknown_version_flags_conservatively():
    fs = _scan_reqs("vllm\n")                    # no version pinned -> flag for review
    assert [f for f in fs if f.rule_id == "ME-SCA-known-cve"]


def test_version_predicate():
    from maroon.analyzer import _parse_version, _version_affected
    assert _version_affected(_parse_version("1.8.0"), "<1.9.0") is True
    assert _version_affected(_parse_version("1.9.0"), "<1.9.0") is False
    assert _version_affected(_parse_version("2.0.0"), "<1.9.0") is False
    assert _version_affected(None, "<1.9.0") is True          # unknown -> conservative
    assert _version_affected(_parse_version("1.0.0"), "*") is True


def test_html_report_self_contained_and_complete():
    r = engine.scan(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "benchmarks", "fixtures", "vuln_app"), with_subscanners=False)
    doc = html.dumps(r.findings, r.inventory, r.governance, r.name, r.elapsed)
    assert "<table" in doc and "Governance verdict" in doc
    assert r.governance["verdict"] in doc
    # self-contained: no external stylesheet/script links
    assert "stylesheet" not in doc and "<script" not in doc
