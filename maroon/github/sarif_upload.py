"""Code Scanning SARIF upload + Checks-API annotations (payload builders + optional POST).

SARIF upload: POST /repos/{owner}/{repo}/code-scanning/sarifs with the SARIF gzip-compressed
then Base64-encoded in the `sarif` field, plus commit_sha + ref. (Private repos need the
customer's GitHub Code Security license; public repos are free.)

Checks API: POST /repos/{owner}/{repo}/check-runs — inline PR annotations (<=50 per request)
and a pass/fail conclusion. Works on any repo without a Code Security license.

Payload builders are stdlib-only and unit-tested; the live POST uses stdlib urllib.
"""
from __future__ import annotations

import base64
import gzip
import json
from typing import Dict, List, Optional

API = "https://api.github.com"
_LEVEL = {"critical": "failure", "high": "failure", "medium": "warning",
          "low": "notice", "info": "notice"}
_MAX_ANNOTATIONS = 50


def encode_sarif(sarif_json: str) -> str:
    """gzip then Base64 (what the Code Scanning API expects in the `sarif` field)."""
    return base64.b64encode(gzip.compress(sarif_json.encode("utf-8"))).decode("ascii")


def decode_sarif(encoded: str) -> str:
    return gzip.decompress(base64.b64decode(encoded)).decode("utf-8")


def build_upload_payload(sarif_json: str, commit_sha: str, ref: str,
                         tool_name: str = "Maroon Elephant") -> Dict:
    return {
        "commit_sha": commit_sha,
        "ref": ref,
        "sarif": encode_sarif(sarif_json),
        "tool_name": tool_name,
        "checkout_uri": "file:///",
    }


def build_check_annotations(findings: List) -> List[Dict]:
    """Checks-API annotation objects from findings (GitHub caps 50 per request; the caller
    paginates via PATCH for more)."""
    out = []
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else f
        out.append({
            "path": d["file"],
            "start_line": d.get("line") or 1,
            "end_line": d.get("end_line") or d.get("line") or 1,
            "annotation_level": _LEVEL.get(d["severity"], "warning"),
            "message": d.get("message") or d.get("title") or "",
            "title": "%s (%s)" % (d.get("rule_id", ""), (d.get("frameworks") or {}).get("primary", "")),
        })
    return out


def build_check_run(findings: List, head_sha: str, name: str = "Maroon Elephant") -> Dict:
    annotations = build_check_annotations(findings)
    worst = "success"
    for f in findings:
        sev = (f.to_dict() if hasattr(f, "to_dict") else f)["severity"]
        if sev in ("critical", "high"):
            worst = "failure"
            break
    counts: Dict[str, int] = {}
    for f in findings:
        sev = (f.to_dict() if hasattr(f, "to_dict") else f)["severity"]
        counts[sev] = counts.get(sev, 0) + 1
    summary = "  ".join("%s: %d" % (k.upper(), v) for k, v in sorted(counts.items())) or "no findings"
    return {
        "name": name,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": worst,
        "output": {
            "title": "%d findings" % len(annotations),
            "summary": summary,
            "annotations": annotations[:_MAX_ANNOTATIONS],  # first page; PATCH the rest
        },
    }


def chunk_annotations(annotations: List[Dict]) -> List[List[Dict]]:
    return [annotations[i:i + _MAX_ANNOTATIONS] for i in range(0, len(annotations), _MAX_ANNOTATIONS)]


# --------------------------------------------------------------------------- #
# Live POST (stdlib urllib). Used by the hosted App; mocked in tests.
# --------------------------------------------------------------------------- #
def post(url: str, token: str, payload: Dict, method: str = "POST") -> int:
    import urllib.error
    import urllib.request
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), method=method,
        headers={
            "Authorization": "Bearer %s" % token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "maroon-elephant",
        })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def upload_sarif(owner: str, repo: str, token: str, sarif_json: str,
                 commit_sha: str, ref: str) -> int:
    url = "%s/repos/%s/%s/code-scanning/sarifs" % (API, owner, repo)
    return post(url, token, build_upload_payload(sarif_json, commit_sha, ref))


def post_check_run(owner: str, repo: str, token: str, findings: List, head_sha: str) -> int:
    url = "%s/repos/%s/%s/check-runs" % (API, owner, repo)
    return post(url, token, build_check_run(findings, head_sha))
