"""Grey Panda adapter failure contract (Build Plan §19.3): absent / version-skew /
malformed output all degrade to a successful native-only run."""
import os
import stat

from maroon import ingest
from maroon.subscanners import greypanda

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "benchmarks", "fixtures", "vuln_app")


def _stub(tmp_path, version_line, scan_output):
    p = tmp_path / "gp"
    p.write_text("#!/usr/bin/env python3\n"
                 "import sys\n"
                 "if '--version' in sys.argv: print(%r)\n"
                 "elif 'scan' in sys.argv: print(%r)\n" % (version_line, scan_output))
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(p)


def test_absent_gp_returns_none(monkeypatch):
    monkeypatch.setattr(greypanda.shutil, "which", lambda name: None)
    assert greypanda.run(ingest.from_path(FIX)) is None


def test_version_below_floor_returns_none(monkeypatch, tmp_path):
    stub = _stub(tmp_path, "Grey Panda 1.0.0", "{}")
    monkeypatch.setattr(greypanda.shutil, "which", lambda name: stub)
    assert greypanda.run(ingest.from_path(FIX)) is None


def test_garbage_output_returns_none(monkeypatch, tmp_path):
    stub = _stub(tmp_path, "Grey Panda 1.0.7", "THIS IS NOT JSON {{{")
    monkeypatch.setattr(greypanda.shutil, "which", lambda name: stub)
    assert greypanda.run(ingest.from_path(FIX)) is None


def test_native_run_succeeds_without_gp(monkeypatch):
    """The whole scan completes even when grey-panda is unavailable."""
    from maroon import engine
    monkeypatch.setattr(greypanda.shutil, "which", lambda name: None)
    r = engine.scan(FIX, with_subscanners=True)
    assert r.findings and "grey-panda" not in r.subscanners
