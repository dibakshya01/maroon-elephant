"""Polyglot (JS/TS) taint via tree-sitter — only runs when the [polyglot] extra is installed."""
import os

import pytest

from maroon import analyzer, ingest, model, polyglot

pytestmark = pytest.mark.skipif(not polyglot.available(),
                                reason="tree-sitter ([polyglot] extra) not installed")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS_FIX = os.path.join(ROOT, "benchmarks", "fixtures", "vuln_js")


def test_js_model_output_to_sinks_detected():
    t = ingest.from_path(JS_FIX)
    findings = model.merge_findings(analyzer.analyze(t))
    js = [f for f in findings if f.file.endswith(".js") and f.rule_id == "ME-LLM10-model-output-sink"]
    lines = {f.line for f in js}
    assert {8, 9, 10} <= lines, "JS eval/exec/innerHTML model-output sinks must be caught: %s" % lines


def test_js_sanitized_value_not_flagged():
    t = ingest.from_path(JS_FIX)
    findings = analyzer.analyze(t)
    js_lines = {f.line for f in findings if f.file.endswith(".js")}
    assert 15 not in js_lines, "eval of a non-model (sanitized) value must not be flagged"
