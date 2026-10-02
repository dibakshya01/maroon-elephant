"""Grey Panda adapter (Build Plan §19.3).

Invokes grey-panda as an optional deterministic sub-scanner and normalizes its findings
into ME's model. Contract:
  * version floor >= 1.0.6 (detected via `gp --version`); below floor -> disabled.
  * consumes `gp scan <path> --format json` -> findings[]; recomputes ME's own evidence
    digest by RE-READING THE FILE at file+line (never from GP's snippet).
  * owasp_id normalized via knowledge/vocab/greypanda.json.
  * any failure (missing / timeout / non-zero / malformed JSON / version skew) -> returns
    [] so the native run proceeds and succeeds.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import List, Optional

from .. import kb, model
from ..ingest import Target

_TIMEOUT = 60
_FLOOR = (1, 0, 6)
_VER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _version_ok() -> bool:
    exe = shutil.which("gp") or shutil.which("greypanda")
    if not exe:
        return False
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    m = _VER_RE.search((out.stdout or "") + (out.stderr or ""))
    if not m:
        return False
    return tuple(int(x) for x in m.groups()) >= _FLOOR


def _normalize_owasp(owasp_id: Optional[str]) -> Optional[str]:
    if not owasp_id:
        return None
    vocab = kb.greypanda_vocab()
    val = owasp_id.strip().upper()
    for suf in vocab.get("owasp_id_normalization", {}).get("suffixes_to_strip", []):
        val = val.replace(suf.upper(), "")
    return val.strip()


def _rel(target: Target, path: str):
    """Repo-relative POSIX path, or None if it escapes the scan root (don't read outside)."""
    if os.path.isabs(path):
        try:
            rel = os.path.relpath(path, target.root)
        except ValueError:
            return None
    else:
        rel = path
    rel = rel.replace(os.sep, "/")
    if rel.startswith("../") or rel == ".." or os.path.isabs(rel):
        return None
    return rel


def run(target: Target) -> Optional[List[model.Finding]]:
    if not _version_ok():
        return None
    exe = shutil.which("gp") or shutil.which("greypanda")
    try:
        proc = subprocess.run(
            [exe, "scan", target.root, "--profile", "enterprise", "--format", "json"],
            capture_output=True, text=True, timeout=_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        doc = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return None

    sev_map = kb.greypanda_vocab().get("severity_map", {})
    from ..ingest import _ignored, _load_ignore
    ignore = _load_ignore(target.root)
    out: List[model.Finding] = []
    for item in doc.get("findings", []):
        try:
            rel = _rel(target, item.get("file", ""))
            if rel is None or (ignore and _ignored(rel, ignore)):
                continue   # outside the scan root, or excluded by .maroonignore (parity with native)
            line = item.get("line")
            lines = target.read_lines(rel)
            if line and int(line) >= 1:
                digest = model.evidence_digest_from_lines(lines, int(line))
            else:
                digest = model.evidence_digest_from_token(item.get("rule_id", "gp"))
            owasp = _normalize_owasp(item.get("owasp_id"))
            primaries = [owasp] if owasp and owasp[:3] in ("LLM", "ASI", "DSG") else []
            fw = kb.merged_tuple(primaries) if primaries else ({"primary": owasp} if owasp else {})
            f = model.Finding(
                rule_id=item.get("rule_id", "GP-UNKNOWN"),
                title=item.get("title", "grey-panda finding"),
                severity=sev_map.get(str(item.get("severity", "")).upper(), "medium"),
                file=rel, line=int(line) if line else None,
                message=item.get("title", ""), description=item.get("description", ""),
                remediation=item.get("remediation", ""), confidence="high",
                evidence_digest=digest, frameworks=fw, maestro_layer=fw.get("maestro_layer"),
                sources=[model.Source("grey-panda", item.get("rule_id", "GP-UNKNOWN"), item.get("owasp_id"))],
            )
            out.append(f)
        except Exception:
            continue
    return out
