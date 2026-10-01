# What Maroon Elephant can and cannot do

Honesty is a feature. Written before the code, kept current.

## Can
- Detect AI/agentic/MCP/data components in a repo and produce an **AI inventory / AI-BOM**.
- Run **deterministic** rules producing findings with `file:line` evidence, mapped to OWASP 2026
  (LLM / ASI / DSGAI / MCP), MAESTRO layers, AIVSS severity, MITRE ATLAS, CWE, and regulatory tags.
- Infer a **component + dataflow graph** and emit a design-time threat model (threat-model-as-code).
- Emit **SARIF 2.1.0** and **CycloneDX AI/ML-BOM**; run in CI with exit codes and diff-aware baselines.
- Place a repo on the **AT×L governance matrix** with a "raise maturity or reduce tier" recommendation.
- Orchestrate **grey-panda** and other scanners as optional deterministic sub-scanners.

## Cannot (by design, for now)
- **Run your code.** Static analysis only — no runtime/behavioral findings.
- **Guarantee a complete DFD.** Architecture inference yields a component+dataflow graph, not a proof.
- **Deep-analyze every language.** Python-first in the core; other languages get config/secret/dependency
  coverage in core and fuller coverage via the `[polyglot]` extra.
- **Prove governance from code alone.** Some controls can't be seen in source; they are reported as
  **"needs attestation,"** never as a pass.
- **Guarantee redaction.** BYOK redaction is **best-effort** (the reliable guarantee is: enrichment off
  or air-gapped ⇒ zero external calls; keys never logged).
- **Register/host a GitHub App or publish packages for you.** Those need your accounts → handoff.
