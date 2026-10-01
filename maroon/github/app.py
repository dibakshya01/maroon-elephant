"""GitHub App client: JWT (RS256) -> installation access token -> org repo enumeration +
clone URL. Build Plan §7/§9. Least-privilege perms: metadata:read, contents:read,
code scanning alerts:write, checks:write, pull requests:read.

The JWT signing needs the `[github]` extra (PyJWT); imported lazily so the core stays
zero-dependency. Live App registration + webhook hosting are handoff items.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional

API = "https://api.github.com"

REQUIRED_PERMISSIONS = {
    "metadata": "read",
    "contents": "read",
    "code_scanning_alerts": "write",
    "checks": "write",
    "pull_requests": "read",
}


def mint_jwt(app_id: str, private_key_pem: str) -> str:
    """App JWT (RS256), ~9 min expiry. Requires PyJWT (the [github] extra)."""
    try:
        import jwt  # type: ignore
    except ImportError as e:
        raise RuntimeError("GitHub App JWT needs the [github] extra: pip install "
                           "'maroon-elephant[github]'") from e
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": app_id}
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


def _get(url: str, token: str, bearer: bool = True) -> Dict:
    req = urllib.request.Request(url, headers={
        "Authorization": ("Bearer %s" if bearer else "token %s") % token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "maroon-elephant",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post(url: str, token: str) -> Dict:
    req = urllib.request.Request(url, data=b"", method="POST", headers={
        "Authorization": "Bearer %s" % token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "maroon-elephant",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def installation_token(app_jwt: str, installation_id: str) -> str:
    """Mint a 1-hour installation access token."""
    data = _post("%s/app/installations/%s/access_tokens" % (API, installation_id), app_jwt)
    return data["token"]


def list_installation_repos(inst_token: str) -> List[Dict]:
    """Repos this installation can access (handles pagination)."""
    repos: List[Dict] = []
    page = 1
    while True:
        data = _get("%s/installation/repositories?per_page=100&page=%d" % (API, page),
                    inst_token, bearer=True)
        batch = data.get("repositories", [])
        repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return [r for r in repos if not r.get("archived")]


def clone_url(full_name: str, inst_token: str) -> str:
    """HTTPS clone URL carrying the installation token (shallow-clone this)."""
    return "https://x-access-token:%s@github.com/%s.git" % (inst_token, full_name)
