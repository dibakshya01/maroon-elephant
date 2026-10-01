"""GitHub webhook signature verification (stdlib only).

Verifies the X-Hub-Signature-256 header: 'sha256=' + HMAC-SHA256(secret, raw_body), using a
constant-time compare. Verify over the RAW request body, respond fast, process async, and
dedupe on X-GitHub-Delivery (the caller's responsibility).
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Optional


def expected_signature(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), msg=body, digestmod=hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def verify_signature(secret: str, body: bytes, signature_header: Optional[str]) -> bool:
    """True iff signature_header matches HMAC-SHA256 of body under secret. Never raises."""
    if not signature_header or not secret:
        return False
    try:
        return hmac.compare_digest(expected_signature(secret, body), signature_header)
    except (TypeError, ValueError):
        return False


# Events a scanner subscribes to (for documentation / handler routing).
SUBSCRIBED_EVENTS = [
    "installation", "installation_repositories",
    "push", "pull_request", "repository", "check_run",
]
