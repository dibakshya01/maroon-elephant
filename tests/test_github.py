"""GitHub integration: webhook signature verification + SARIF-upload/Checks payloads (FR-14,
unit-testable without live auth)."""
import json
import os

from maroon import engine
from maroon.github import sarif_upload, webhooks

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "benchmarks", "fixtures", "vuln_app")


def test_webhook_signature_valid():
    secret, body = "s3cr3t", b'{"hello":"world"}'
    sig = webhooks.expected_signature(secret, body)
    assert sig.startswith("sha256=")
    assert webhooks.verify_signature(secret, body, sig) is True


def test_webhook_signature_rejects_tampered_body():
    secret, body = "s3cr3t", b'{"hello":"world"}'
    sig = webhooks.expected_signature(secret, body)
    assert webhooks.verify_signature(secret, b'{"hello":"evil"}', sig) is False


def test_webhook_signature_rejects_wrong_secret_and_missing_header():
    body = b"x"
    assert webhooks.verify_signature("a", body, webhooks.expected_signature("b", body)) is False
    assert webhooks.verify_signature("a", body, None) is False


def test_sarif_encode_roundtrip():
    doc = '{"version":"2.1.0","runs":[]}'
    enc = sarif_upload.encode_sarif(doc)
    assert sarif_upload.decode_sarif(enc) == doc


def test_upload_payload_shape():
    p = sarif_upload.build_upload_payload('{"version":"2.1.0"}', "abc123", "refs/pull/7/merge")
    assert p["commit_sha"] == "abc123" and p["ref"] == "refs/pull/7/merge"
    assert p["sarif"] and p["tool_name"] == "Maroon Elephant"


def test_check_run_and_annotations():
    r = engine.scan(FIX, with_subscanners=False)
    run = sarif_upload.build_check_run(r.findings, head_sha="deadbeef")
    assert run["head_sha"] == "deadbeef" and run["status"] == "completed"
    assert run["conclusion"] == "failure"  # vuln app has high/critical
    for ann in run["output"]["annotations"]:
        assert ann["path"] and ann["start_line"] >= 1
        assert ann["annotation_level"] in ("failure", "warning", "notice")
    assert len(run["output"]["annotations"]) <= 50


def test_annotation_chunking():
    anns = [{"path": "a", "start_line": 1} for _ in range(120)]
    chunks = sarif_upload.chunk_annotations(anns)
    assert len(chunks) == 3 and len(chunks[0]) == 50 and len(chunks[-1]) == 20
