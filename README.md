<!-- Polished landing visuals land in Phase 4; this README is functional and will be upgraded. -->
<div align="center">

# 🐘 Maroon Elephant

**AI-era threat modeling & repository scanning — OWASP-2026 aligned, deterministic-first, zero-dependency core.**

Detect the AI/agentic/MCP components in a repo, infer its architecture, and produce
evidence-backed threat findings mapped to the OWASP **LLM Top 10**, **Agentic (ASI) Top 10**,
**GenAI Data Security (DSGAI)**, and **MCP** security guidance — worst-first, across a whole org.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)
[![Core deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen.svg)](pyproject.toml)
[![OWASP 2026](https://img.shields.io/badge/OWASP-2026-b0313f.svg)](Findings.md)

**[Live site & docs →](https://dibakshya01.github.io/maroon-elephant/)**

</div>

> **Status:** 🚧 Alpha / under active construction. The design is specified in
> [Findings.md](Findings.md) (research) and [Build Plan.md](Build%20Plan.md) (engineering spec).

---

## Why

LLMs collapse the control plane and the data plane into one flat token namespace — the root cause
behind prompt injection, data exfiltration, excessive agency, and memory poisoning. The security
market is crowded with **runtime** products but thin on **open-source, repo-driven, design-time**
threat modeling for AI systems. Maroon Elephant fills that gap.

It stands on top of **[grey-panda](https://github.com/dibakshya01/grey-panda)** (the deterministic,
in-the-file AI-security scanner) and adds architecture inference, multi-repo orchestration, a
governance verdict, GitHub integration, and a local UI.

> **Grey Panda** = the calm deterministic guardian.
> **Maroon Elephant** = the orchestrating, design-time, multi-repo threat-modeler on top of it.

## Principles

- **Deterministic-first.** Every finding has `file:line` evidence. The LLM is optional and only
  *enriches* an existing deterministic finding — it can never invent one.
- **Zero runtime dependencies.** The core is Python standard library only; everything heavier is an
  optional extra (`[polyglot]`, `[llm]`, `[github]`, `[subscanners]`).
- **Local-first & BYOK.** Your source never leaves your machine by default; air-gapped mode makes
  zero external calls.
- **Standards-anchored.** Every finding carries a cross-framework tuple (LLM / ASI / DSGAI / MAESTRO
  layer / AIVSS / MITRE ATLAS / CWE / NIST / regulatory).

## Quick start (target UX)

```bash
pip install maroon-elephant
maroon scan .                      # scan the current repo
maroon scan https://github.com/org/repo
maroon scan ./app --format sarif -o results.sarif
maroon scan ./app --format html  -o report.html   # shareable threat-model report
maroon serve                       # Enterprise: local dashboard on http://localhost:7879
```

Exit codes and `--fail-on {low,medium,high,critical}` make it CI-ready; `--baseline old.sarif`
scans diff-aware (fail only on *new* findings).

> **Grey Panda** (the deterministic sub-scanner) is optional: `pip install maroon-elephant[subscanners]`
> (or `pip install grey-panda`). Without it, Maroon Elephant's native rules still run.
> **LLM enrichment** is off by default and BYOK — enable with `--explain` after setting
> `MAROON_LLM_PROVIDER` (`anthropic`/`openai`/`google`/`ollama`/`lmstudio`). With no provider, or
> with `ollama`, the scan makes **zero external calls**.

## What it produces

1. **Vulnerability findings** → SARIF 2.1.0 (GitHub/Azure code scanning, VS Code).
2. **A design-time threat model** → component graph → MAESTRO layers → threat-model-as-code + diagram.
3. **An AI inventory / AI-BOM** → CycloneDX AI/ML-BOM ("what AI are we even running?").

Plus, in the Enterprise edition: crown-jewels **P0→P1→P2** multi-repo prioritization and an
**AT×L governance verdict** (adoption tier × maturity → "raise maturity or reduce tier").

## What it can and cannot do

See **[docs/CAN_AND_CANNOT.md](docs/CAN_AND_CANNOT.md)**. In short: static analysis only; Python-first
deep analysis (other languages via `[polyglot]`); governance checks are partly presence/absence
("needs attestation"); live GitHub App hosting and package publishing need your own accounts.

## Documentation

- [Findings.md](Findings.md) — the research synthesis (threat corpus, competitive landscape).
- [Build Plan.md](Build%20Plan.md) — the engineering spec (architecture, FRs, roadmap).
- [docs/](docs/) — how-to guides, architecture, "What is BYOT?", and honest limits.

## Contributing

Issues and rule contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). The knowledge pack
(`maroon/knowledge/`) is versioned JSON, designed to be extended as OWASP/ATLAS/AIVSS evolve.

## License

Apache-2.0 — see [LICENSE](LICENSE). OWASP source documents referenced in the knowledge pack are
CC BY-SA 4.0 and are credited in [NOTICE](NOTICE).
