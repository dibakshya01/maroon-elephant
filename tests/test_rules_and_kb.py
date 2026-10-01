"""Rule-schema integrity, knowledge-pack loading, and inline suppression."""
import os
import tempfile

from maroon import analyzer, ingest, kb
from maroon.analyzer import _load_rules


def test_rules_load_and_have_required_fields():
    rules = _load_rules()
    assert len(rules) >= 15
    ids = set()
    for r in rules:
        assert r.get("id") and r.get("title") and r.get("detector")
        assert r.get("primary") or r.get("also"), r["id"]
        assert r["id"] not in ids, "duplicate rule id %s" % r["id"]
        ids.add(r["id"])


def test_knowledge_pack_loads():
    assert kb.control_title("LLM01") == "Prompt Injection"
    assert kb.crosswalk_tuple("LLM10")["cwe"]
    assert len(kb.components()) >= 30
    assert len(kb.cve_fingerprints()["cves"]) >= 10
    assert kb.at_x_l()["adoption_tiers"]["AT8"]


def test_crosswalk_tuple_optional_fields():
    t = kb.crosswalk_tuple("ASI10")
    assert t["primary"] == "ASI10"
    # missing optional fields are simply absent, not errors
    assert "regulatory" not in t or isinstance(t["regulatory"], list)


def test_inline_suppression():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "x.py"), "w") as fh:
            fh.write("import pickle\n")
            fh.write("pickle.loads(data)  # maroon: ignore\n")
            fh.write("pickle.loads(other)\n")
        findings = analyzer.analyze(ingest.from_path(d))
        deser = [f for f in findings if f.rule_id == "ME-LLM04-unsafe-deserialization"]
        # the suppressed line is dropped; the other remains
        assert len(deser) == 1
        assert deser[0].line == 3
