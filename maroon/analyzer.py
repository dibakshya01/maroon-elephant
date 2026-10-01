"""Deterministic rule engine. Loads JSON rules from knowledge/rules/ and dispatches by
`detector` type. Every finding carries file:line evidence and the crosswalk tuple.

Detector types:
  regex            -- one or more regex patterns over matching files
  unsafe_deser     -- regex specialized for deserialization sinks (alias of regex)
  config_mcp       -- parse MCP client configs for risky settings
  dependency_cve   -- match declared packages against the CVE fingerprint DB
  python_ast_taint -- model-output -> dangerous-sink taint (see taint.py)
  trifecta         -- Lethal-Trifecta heuristic (untrusted input + sensitive data + egress)
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
from importlib import resources
from typing import Dict, List, Optional

from . import kb, model, taint
from .ingest import Target

_EXT_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "typescript", ".jsx": "javascript",
    ".tsx": "typescript", ".go": "go", ".java": "java", ".rb": "ruby",
}


def _load_rules() -> List[Dict]:
    rules: List[Dict] = []
    root = resources.files("maroon").joinpath("knowledge", "rules")
    for fam in ("llm", "asi", "dsgai", "mcp", "general"):
        node = root.joinpath(fam)
        try:
            entries = list(node.iterdir())
        except (FileNotFoundError, NotADirectoryError, OSError):
            continue
        for entry in entries:
            if entry.name.endswith(".json"):
                try:
                    rules.append(json.loads(entry.read_text(encoding="utf-8")))
                except (json.JSONDecodeError, OSError):
                    continue
    return rules


def _lang_of(rel: str) -> Optional[str]:
    return _EXT_LANG.get(os.path.splitext(rel)[1].lower())


def _path_ok(rule: Dict, rel: str) -> bool:
    globs = rule.get("path_globs")
    if globs and not any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(os.path.basename(rel), g) for g in globs):
        return False
    langs = rule.get("languages")
    if langs and _lang_of(rel) not in langs:
        return False
    return True


def make_finding(rule: Dict, target: Target, rel: str, line: Optional[int],
                 token: Optional[str] = None, message: Optional[str] = None) -> model.Finding:
    lines = target.read_lines(rel)
    if line and line >= 1:
        digest = model.evidence_digest_from_lines(lines, line)
    else:
        digest = model.evidence_digest_from_token(token or rule["id"])
    primaries = [p for p in ([rule.get("primary")] + rule.get("also", [])) if p]
    fw = kb.merged_tuple(primaries) if primaries else {}
    return model.Finding(
        rule_id=rule["id"], title=rule["title"], severity=rule.get("severity", "medium"),
        file=rel, line=line or None,
        message=message or rule.get("message", rule["title"]),
        description=rule.get("description", ""), remediation=rule.get("remediation", ""),
        confidence=rule.get("confidence", "medium"), evidence_digest=digest, evidence_token=token,
        frameworks=fw, maestro_layer=fw.get("maestro_layer"),
        sources=[model.Source("maroon", rule["id"], primaries[0] if primaries else None)],
    )


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #
def _run_regex(rule: Dict, target: Target) -> List[model.Finding]:
    pats = []
    for p in (rule.get("patterns") or ([{"pattern": rule["pattern"]}] if rule.get("pattern") else [])):
        if isinstance(p, str):
            p = {"pattern": p}
        try:
            pats.append((re.compile(p["pattern"]), p.get("message")))
        except re.error:
            continue
    neg = rule.get("exclude_if_line_matches")
    neg_re = re.compile(neg) if neg else None
    out: List[model.Finding] = []
    for rel in target.files:
        if not _path_ok(rule, rel):
            continue
        for i, ln in enumerate(target.read_lines(rel), 1):
            for rx, msg in pats:
                if rx.search(ln):
                    if neg_re and neg_re.search(ln):
                        continue
                    out.append(make_finding(rule, target, rel, i, token=ln.strip()[:120], message=msg))
                    break
    return out


def _run_config_mcp(rule: Dict, target: Target) -> List[model.Finding]:
    risky_keys = rule.get("params", {}).get("risky_keys", [])
    unpinned_re = re.compile(r"(npx\s+-y|npx\s+)[^\n]*@latest|uvx\s|\bcurl\b[^\n]*\|\s*sh")
    http_re = re.compile(r'"url"\s*:\s*"http://')
    secret_re = re.compile(r'(?i)"(authorization|api[_-]?key|token|secret|password)"\s*:\s*"[^"$]{8,}"')
    names = {"mcp.json", ".mcp.json", "claude_desktop_config.json", "config.json"}
    out: List[model.Finding] = []
    for rel in target.files:
        base = os.path.basename(rel)
        if base not in names and "mcp" not in base.lower():
            continue
        lines = target.read_lines(rel)
        text = "\n".join(lines)
        if "mcpServers" not in text and "servers" not in text and "command" not in text:
            continue
        for i, ln in enumerate(lines, 1):
            low = ln.lower()
            hit = None
            if any(k.lower() in low for k in risky_keys):
                hit = "HITL bypass / auto-approve flag"
            elif unpinned_re.search(ln):
                hit = "Unpinned MCP server source (rug-pull exposure)"
            elif http_re.search(ln):
                hit = "Non-TLS (http://) MCP server endpoint"
            elif secret_re.search(ln):
                hit = "Inline secret in MCP config"
            if hit:
                out.append(make_finding(rule, target, rel, i, token=ln.strip()[:120], message=hit))
    return out


def _run_dependency_cve(rule: Dict, target: Target) -> List[model.Finding]:
    from .detect import _manifest_packages
    db = kb.cve_fingerprints()
    pkgs = _manifest_packages(target)
    index = {}
    for entry in db.get("cves", []):
        index.setdefault(entry["package"].lower(), []).append(entry)
    out: List[model.Finding] = []
    for pkg, evs in pkgs.items():
        for entry in index.get(pkg, []):
            ev = evs[0]
            msg = "%s: %s (%s)" % (entry["cve"], entry["class"], entry.get("affected", "*"))
            f = make_finding(rule, target, ev["file"], ev["line"],
                             token="%s@%s" % (pkg, entry["cve"]), message=msg)
            f.severity = entry.get("severity", f.severity)
            # enrich crosswalk with the CVE's own risk ids
            for fam, ids in entry.get("risk", {}).items():
                f.frameworks.setdefault(fam, [])
                for cid in ids:
                    if cid not in f.frameworks[fam]:
                        f.frameworks[fam].append(cid)
            f.frameworks.setdefault("cve", []).append(entry["cve"])
            out.append(f)
    return out


# Lethal-Trifecta signal sets (deterministic, file-local heuristic).
_TRIFECTA = {
    "untrusted_input": re.compile(
        r"(request\.(json|data|form|args|body)|flask\.request|fastapi|\.retrieve\(|\.search\(|"
        r"similarity_search|web_?fetch|requests\.get\(|httpx\.get\(|BeautifulSoup|load_url|"
        r"read\(\)|input\(|sys\.argv|os\.environ\.get\(.*(prompt|query|message))"),
    "sensitive_data": re.compile(
        r"(SECRET|PASSWORD|API_?KEY|TOKEN|PRIVATE_KEY|\.ssh|\.env|credentials|customer|ssn|"
        r"patient|salary|SELECT\s+.*FROM|os\.environ\[|getenv\()"),
    "external_comms": re.compile(
        r"(requests\.(post|put)\(|httpx\.(post|put)\(|smtplib|send_email|sendmail|\.send\(|"
        r"webhook|slack|telegram|boto3|urlopen|fetch\(|aiohttp)"),
}
_LLM_CALL = re.compile(
    r"(openai|anthropic|\.chat\.completions|\.messages\.create|\.generate\(|\.invoke\(|"
    r"ChatOpenAI|ChatAnthropic|llm\(|agent\.run|AgentExecutor|\.predict\()")


def _run_trifecta(rule: Dict, target: Target) -> List[model.Finding]:
    out: List[model.Finding] = []
    for rel in target.files:
        if _lang_of(rel) not in ("python", "javascript", "typescript"):
            continue
        lines = target.read_lines(rel)
        text = "\n".join(lines)
        if not _LLM_CALL.search(text):
            continue
        hits = {k: rx.search(text) for k, rx in _TRIFECTA.items()}
        if all(hits.values()):
            # anchor on the LLM call line
            anchor = 1
            for i, ln in enumerate(lines, 1):
                if _LLM_CALL.search(ln):
                    anchor = i
                    break
            msg = ("Lethal Trifecta: this file combines untrusted input, sensitive-data access, "
                   "and external communication around an LLM/agent call — an exfiltration path "
                   "via (indirect) prompt injection. Apply the Rule of Two.")
            out.append(make_finding(rule, target, rel, anchor, message=msg))
    return out


_DISPATCH = {
    "regex": _run_regex,
    "unsafe_deser": _run_regex,
    "config_mcp": _run_config_mcp,
    "dependency_cve": _run_dependency_cve,
    "trifecta": _run_trifecta,
}


_IGNORE_RE = re.compile(r"maroon:\s*ignore(?:\[([^\]]*)\])?", re.IGNORECASE)


def _comment_only(line: str) -> bool:
    s = line.strip()
    return s.startswith(("#", "//", "/*", "*", "<!--"))


def _suppressed(target: Target, f: model.Finding) -> bool:
    """Honor `# maroon: ignore` / `# maroon: ignore[RULE-ID]` as an inline trailing comment
    on the finding's own line, or on a COMMENT-ONLY line immediately above it (so an inline
    ignore on the previous statement does not leak onto the next line)."""
    if not f.line:
        return False
    lines = target.read_lines(f.file)
    own_idx = f.line - 1           # 0-indexed: the finding's own line
    above_idx = f.line - 2         # the line above
    candidates = []
    if 0 <= own_idx < len(lines):
        candidates.append(lines[own_idx])
    if 0 <= above_idx < len(lines) and _comment_only(lines[above_idx]):
        candidates.append(lines[above_idx])
    for text in candidates:
        m = _IGNORE_RE.search(text)
        if m and (not m.group(1) or f.rule_id in {x.strip() for x in m.group(1).split(",")}):
            return True
    return False


def analyze(target: Target) -> List[model.Finding]:
    findings: List[model.Finding] = []
    for rule in _load_rules():
        det = rule.get("detector", "regex")
        if det == "python_ast_taint":
            findings.extend(taint.run(rule, target, make_finding))
        else:
            fn = _DISPATCH.get(det)
            if fn:
                findings.extend(fn(rule, target))
    return [f for f in findings if not _suppressed(target, f)]
