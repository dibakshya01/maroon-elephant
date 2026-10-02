"""Optional, evidence-gated LLM enrichment (BYOK). OFF by default — the deterministic core
is fully functional with zero LLM and makes zero external calls unless enrichment is enabled.
The LLM can only DESCRIBE a deterministic finding; it can never create one, and any code
location it cites that isn't the finding's own is stripped (the citation gate)."""
from __future__ import annotations

from .enrich import enrich_findings, make_provider, redact

__all__ = ["enrich_findings", "make_provider", "redact"]
