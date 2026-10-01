"""Finding-identity contracts (Build Plan §19.1)."""
from maroon import model


def test_evidence_digest_stable_under_reindent():
    base = ["def f():", "    x=1", "    run(user_input)", "    y=2", "    z=3"]
    reindented = ["def f():", "        x=1", "        run(user_input)", "        y=2", "        z=3"]
    assert model.evidence_digest_from_lines(base, 3) == model.evidence_digest_from_lines(reindented, 3)


def test_evidence_digest_stable_under_distant_line_shift():
    base = ["def f():", "    x=1", "    run(user_input)", "    y=2", "    z=3"]
    shifted = ["import os"] * 10 + base
    assert model.evidence_digest_from_lines(base, 3) == model.evidence_digest_from_lines(shifted, 13)


def test_evidence_digest_changes_on_code_change():
    base = ["a", "b", "run(user_input)", "c", "d"]
    other = ["a", "b", "exec(evil)", "c", "d"]
    assert model.evidence_digest_from_lines(base, 3) != model.evidence_digest_from_lines(other, 3)


def test_correlation_key_merges_same_issue_across_sources():
    d = model.evidence_digest_from_token("x")
    native = model.Finding("ME-LLM10", "t", "high", "a.py", line=3, evidence_digest=d,
                           sources=[model.Source("maroon", "ME-LLM10", "LLM10")])
    gp = model.Finding("GP-AI-014", "t", "critical", "a.py", line=3, evidence_digest=d,
                       sources=[model.Source("grey-panda", "GP-AI-014", "LLM10")])
    assert native.correlation_key == gp.correlation_key  # same primary + span -> merge
    merged = model.merge_findings([native, gp])
    assert len(merged) == 1
    assert merged[0].rule_id == "ME-LLM10"            # ME-native canonical
    assert merged[0].severity == "critical"           # severity max
    assert len(merged[0].sources) == 2


def test_different_issue_class_same_line_stays_separate():
    d = model.evidence_digest_from_token("x")
    secret = model.Finding("ME-LLM08", "t", "high", "a.py", line=3, evidence_digest=d,
                           sources=[model.Source("maroon", "ME-LLM08", "LLM08")])
    sink = model.Finding("ME-LLM10", "t", "high", "a.py", line=3, evidence_digest=d,
                         sources=[model.Source("maroon", "ME-LLM10", "LLM10")])
    assert secret.correlation_key != sink.correlation_key
    assert len(model.merge_findings([secret, sink])) == 2


def test_fingerprint_is_32_hex():
    d = model.evidence_digest_from_token("x")
    f = model.Finding("ME-LLM10", "t", "high", "a.py", line=1, evidence_digest=d)
    assert len(f.fingerprint) == 32 and all(c in "0123456789abcdef" for c in f.fingerprint)
