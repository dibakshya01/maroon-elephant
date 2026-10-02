"""Evidence-gated LLM enrichment. Provider-agnostic over stdlib urllib (BYOK).

Guarantees that back the headline claims:
  * OFF by default: no provider -> no calls. Air-gapped/Ollama -> local only.
  * Keys come from the caller/env and are NEVER written to logs.
  * Best-effort redaction strips obvious secrets from the snippet before it leaves the machine
    (explicitly best-effort, not a guarantee — the same class of control ME flags under LLM02).
  * Citation gate: the model can only describe THIS finding. Any `path:line` it emits that is
    not the finding's own location is stripped, and it can never add a finding.
"""
from __future__ import annotations

import json
import re
import urllib.request
from typing import List, Optional

from .. import model

_SECRET_RES = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),           # GitHub tokens
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),          # Slack tokens
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),               # Google API keys
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"),     # bearer tokens
    re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----"),     # PEM private keys
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWTs
]
# Location-like tokens in several formats: f.py:12, f.py :12, f.py#L12, f.py#12.
_LOC_RE = re.compile(r"[\w./\\-]+\.[A-Za-z0-9]+\s*(?::|#L?)\s*\d+")


def _norm_loc(s: str) -> str:
    return re.sub(r"\s*(?::|#L?)\s*", ":", s.strip().replace("\\", "/"))


def redact(text: str) -> str:
    """Best-effort secret redaction. NOT a guarantee."""
    for rx in _SECRET_RES:
        text = rx.sub("[REDACTED]", text)
    return text


class Provider:
    """Minimal provider interface. complete(prompt) -> str. Implementations use urllib."""
    def complete(self, prompt: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class OllamaProvider(Provider):
    def __init__(self, model_name: str = "llama3", host: str = "http://127.0.0.1:11434"):
        self.model_name, self.host = model_name, host

    def complete(self, prompt: str) -> str:
        body = json.dumps({"model": self.model_name, "prompt": prompt, "stream": False,
                           "options": {"temperature": 0, "seed": 7}}).encode()
        req = urllib.request.Request(self.host + "/api/generate", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read()).get("response", "")


class OpenAICompatProvider(Provider):
    """OpenAI-style chat completions (OpenAI, Azure, many local servers)."""
    def __init__(self, model_name: str, api_key: str, base: str = "https://api.openai.com/v1"):  # maroon: ignore[ME-ASI01-lethal-trifecta] this IS the hardened BYOK LLM client (redaction + citation gate), not an agent app
        self.model_name, self.api_key, self.base = model_name, api_key, base.rstrip("/")

    def complete(self, prompt: str) -> str:
        body = json.dumps({"model": self.model_name, "temperature": 0, "seed": 7,
                           "messages": [{"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request(self.base + "/chat/completions", data=body, headers={
            "Content-Type": "application/json", "Authorization": "Bearer %s" % self.api_key})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]


class AnthropicProvider(Provider):
    def __init__(self, model_name: str, api_key: str):
        self.model_name, self.api_key = model_name, api_key

    def complete(self, prompt: str) -> str:
        body = json.dumps({"model": self.model_name, "max_tokens": 400, "temperature": 0,
                           "messages": [{"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={
            "Content-Type": "application/json", "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        return "".join(b.get("text", "") for b in data.get("content", []))


def make_provider(name: str, model_name: str = "", api_key: str = "") -> Optional[Provider]:
    name = (name or "").lower()
    if not name:
        return None
    if name.startswith("ollama"):
        return OllamaProvider(model_name or "llama3")
    if name.startswith("lmstudio"):
        return OpenAICompatProvider(model_name or "local", api_key or "lm-studio",
                                    base="http://127.0.0.1:1234/v1")
    if name in ("openai", "azure", "google"):
        return OpenAICompatProvider(model_name or "gpt-4o-mini", api_key)
    if name == "anthropic":
        return AnthropicProvider(model_name or "claude-3-5-haiku-latest", api_key)
    return None


def _citation_gate(finding: model.Finding, text: str) -> str:
    """Strip any code location the model cites that is NOT this finding's own, so enrichment
    can only ever describe the deterministic finding. Normalizes location formats (f.py:12,
    f.py :12, f.py#L12) on both sides so none slip past."""
    own = _norm_loc("%s:%s" % (finding.file, finding.line))

    def repl(m):
        norm = _norm_loc(m.group(0))
        if norm == own or norm.endswith("/" + own) or own.endswith("/" + norm):
            return m.group(0)
        return "[unverified location removed]"
    return _LOC_RE.sub(repl, text)


def _prompt(finding: model.Finding, snippet: str) -> str:
    return (
        "You are a security reviewer. In 2-3 sentences, explain this STATIC finding to a "
        "developer and how to fix it. Do not invent other issues or other file locations.\n\n"
        "Rule: %s\nSeverity: %s\nOWASP: %s\nLocation: %s:%s\nFinding: %s\nRemediation hint: %s\n"
        "Code (secrets redacted):\n%s\n" % (
            finding.rule_id, finding.severity, (finding.frameworks or {}).get("primary", ""),
            finding.file, finding.line, finding.message, finding.remediation, redact(snippet)))


def enrich_findings(findings: List[model.Finding], provider: Optional[Provider],
                    read_snippet=None) -> List[model.Finding]:
    """Attach .explanation to each finding via the provider. No provider -> no-op, no calls.
    Any provider error leaves the finding unchanged. Never creates findings."""
    if provider is None:
        return findings
    for f in findings:
        snippet = ""
        if read_snippet and f.line:
            try:
                snippet = read_snippet(f.file, f.line)
            except Exception:
                snippet = ""
        try:
            text = provider.complete(_prompt(f, snippet))
            f.explanation = _citation_gate(f, (text or "").strip())[:1200]
        except Exception:
            continue  # provider down / bad response -> finding stands on its own
    return findings
