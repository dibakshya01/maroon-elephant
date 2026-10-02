"""Attack-tests from the adversarial hardening rounds. Each fails before its fix and passes
after, so a regression can't silently reintroduce the vulnerability."""
import json
import os
import tempfile
import zipfile

import pytest

from maroon import analyzer, engine, ingest, model
from maroon.reporters import sarif

# Two identical deser blocks with IDENTICAL +-2 context -> identical evidence_digest.
_DUP = "pass\npass\npickle.loads(blob)\npass\npass\npass\npass\npickle.loads(blob)\npass\npass\n"
_SINGLE = "pass\npass\npickle.loads(blob)\npass\npass\n"


def _scan_dir(contents, name="x.py"):
    d = tempfile.mkdtemp()
    with open(os.path.join(d, name), "w") as fh:
        fh.write(contents)
    return engine.scan(d, with_subscanners=False)


# ---- #1 CRITICAL: fingerprint collision / --baseline suppressing new vulns ----
def test_identical_blocks_not_merged_into_one():
    r = _scan_dir(_DUP)
    deser = [f for f in r.findings if f.rule_id == "ME-LLM04-unsafe-deserialization"]
    assert len(deser) == 2, "two identical blocks at different lines must stay two findings"
    assert len({f.fingerprint for f in deser}) == 2, "distinct findings must have distinct fingerprints"


def test_baseline_does_not_suppress_a_newly_added_duplicate():
    base = _scan_dir(_SINGLE)
    base_sarif = os.path.join(tempfile.mkdtemp(), "base.sarif")
    with open(base_sarif, "w") as fh:
        fh.write(sarif.dumps(base.findings))
    # new commit copy-pastes the identical block elsewhere; scan diff-aware
    newdir = tempfile.mkdtemp()
    with open(os.path.join(newdir, "x.py"), "w") as fh:
        fh.write(_DUP)
    r = engine.scan(newdir, with_subscanners=False, baseline=base_sarif)
    deser = [f for f in r.findings if f.rule_id == "ME-LLM04-unsafe-deserialization"]
    assert len(deser) == 1, "the newly-introduced duplicate must NOT be suppressed by --baseline"


# ---- #3/#4: git URL hardening ----
@pytest.mark.parametrize("bad", [
    "--upload-pack=touch /tmp/x",          # option injection
    "ext::sh -c id",                        # ext transport (RCE)
    "file:///etc/passwd",                   # file transport
    "https://169.254.169.254/x.git",        # cloud metadata SSRF
    "ftp://evil/x.git",                     # disallowed scheme
])
def test_git_url_validation_rejects(bad):
    with pytest.raises(ValueError):
        ingest._validate_git_url(bad)


def test_git_url_validation_allows_normal():
    ingest._validate_git_url("https://github.com/org/repo.git")  # must not raise
    ingest._validate_git_url("git@github.com:org/repo.git")


# ---- #7: zip bomb ----
def test_zip_bomb_rejected(monkeypatch):
    monkeypatch.setattr(ingest, "MAX_ZIP_TOTAL_BYTES", 1000)
    zp = os.path.join(tempfile.mkdtemp(), "bomb.zip")
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", "A" * 50_000)   # compresses tiny, inflates past the cap
    with pytest.raises(ValueError):
        ingest.from_zip(zp)


# ---- #8: suppression must be a real comment ----
def test_ignore_inside_string_does_not_suppress():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "x.py"), "w") as fh:
        fh.write('msg = "docs mention maroon: ignore here"\n')
        fh.write("pickle.loads(blob)\n")   # line 2: no real comment -> must fire
    fs = analyzer.analyze(ingest.from_path(d))
    deser = [f for f in fs if f.rule_id == "ME-LLM04-unsafe-deserialization"]
    assert len(deser) == 1 and deser[0].line == 2


def test_real_comment_ignore_still_works():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "x.py"), "w") as fh:
        fh.write("pickle.loads(blob)  # maroon: ignore\n")
    fs = analyzer.analyze(ingest.from_path(d))
    assert not [f for f in fs if f.rule_id == "ME-LLM04-unsafe-deserialization"]


# ---- #6: taint through for / with / comprehension ----
def test_taint_through_for_with_comprehension():
    code = (
        "import os\n"
        "def g(x):\n"
        "    for cmd in llm.generate(x):\n"
        "        os.system(cmd)\n"
        "def h(x):\n"
        "    with llm.generate(x) as c:\n"
        "        eval(c)\n"
        "def i(x):\n"
        "    r = llm.generate(x)\n"
        "    [eval(c) for c in r]\n"
    )
    r = _scan_dir(code)
    lines = {f.line for f in r.findings if f.rule_id == "ME-LLM10-model-output-sink"}
    assert 4 in lines, "for-target taint missed (os.system(cmd))"
    assert 7 in lines, "with-as taint missed (eval(c))"
    assert 10 in lines, "comprehension-target taint missed"


# ---- LLM enrichment: off by default + citation gate ----
class _FakeProvider:
    def __init__(self, text, raises=False):
        self.text, self.raises, self.calls = text, raises, 0

    def complete(self, prompt):
        self.calls += 1
        if self.raises:
            raise RuntimeError("provider down")
        return self.text


def _finding():
    return model.Finding("ME-LLM10", "t", "high", "a.py", line=5,
                         evidence_digest=model.evidence_digest_from_token("x"))


def test_enrichment_off_by_default_makes_no_calls():
    from maroon.llm import enrich_findings
    fs = [_finding()]
    enrich_findings(fs, provider=None)
    assert fs[0].explanation is None   # no provider -> untouched, no network


def test_enrichment_citation_gate_strips_foreign_locations():
    from maroon.llm import enrich_findings
    p = _FakeProvider("This is risky. See a.py:5 and also evil.py:999 for a backdoor.")
    f = _finding()
    enrich_findings([f], provider=p)
    assert f.explanation and "a.py:5" in f.explanation
    assert "evil.py:999" not in f.explanation
    assert "unverified location removed" in f.explanation


def test_enrichment_provider_error_leaves_finding_intact():
    from maroon.llm import enrich_findings
    f = _finding()
    enrich_findings([f], provider=_FakeProvider("", raises=True))
    assert f.explanation is None


def test_redaction_strips_obvious_secrets():
    from maroon.llm import redact
    out = redact('API_KEY = "sk-abc123def456ghi789jkl"')
    assert "sk-abc123" not in out and "REDACTED" in out


# ---- #5: UI server CSRF + Host (DNS-rebinding) defenses ----
def test_ui_rejects_missing_csrf_and_bad_host():
    import http.client
    import threading
    from http.server import ThreadingHTTPServer

    from maroon.ui import server as uiserver

    uiserver._TOKEN = "testtoken"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), uiserver.Handler)
    port = httpd.server_address[1]
    uiserver._ALLOWED_HOSTS = {"127.0.0.1:%d" % port, "localhost:%d" % port}
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        good_host = "127.0.0.1:%d" % port
        body = json.dumps({"targets": ["."]})
        # missing CSRF token -> 403
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/api/scan", body=body,
                  headers={"Content-Type": "application/json", "Host": good_host})
        assert c.getresponse().status == 403
        # token present but foreign Host (DNS-rebinding) -> 403
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/api/scan", body=body,
                  headers={"Content-Type": "application/json", "Host": "evil.com",
                           "X-Maroon-Token": "testtoken"})
        assert c.getresponse().status == 403
        # token present, wrong content-type -> 415
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/api/scan", body=body,
                  headers={"Content-Type": "text/plain", "Host": good_host,
                           "X-Maroon-Token": "testtoken"})
        assert c.getresponse().status == 415
    finally:
        httpd.shutdown()
        httpd.server_close()
