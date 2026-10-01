"""GitHub integration (Enterprise): GitHub App client, webhook verification, SARIF upload,
and Checks-API annotations. The signature/encoding layers are stdlib-only; the App's
JWT/token minting rides the `[github]` extra (PyJWT/cryptography). Live App registration and
webhook hosting are handoff items (they need the user's GitHub account)."""
from __future__ import annotations

from . import sarif_upload, webhooks

__all__ = ["webhooks", "sarif_upload"]
