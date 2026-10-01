# Maroon Elephant — Findings

**Research synthesis for an open-source, AI-era threat-modeling & repo-scanning platform.**
Date: 2026-09-30 · Status: research complete, pre-build · License intent: Apache-2.0 (OSI-approved, OWASP-eligible)

> This document consolidates five parallel research streams: the OWASP GenAI **LLM Top 10 (2026)**, the OWASP **Top 10 for Agentic Applications (2026, ASI01–10)** + **State of Agentic AI Security & Governance v2**, the OWASP **GenAI Data Security 2026 (DSGAI01–21)**, the two OWASP **MCP** security guides, and a web sweep of the competitive/framework landscape. It is the evidence base for [Build Plan.md](Build%20Plan.md).

---

## 1. Thesis (the one-paragraph version)

Every framework we studied converges on the same structural truth: **LLMs collapse the control plane and the data plane into a single flat token namespace with no internal access control.** A system prompt, a retrieved RAG chunk, a tool's output, and untrusted user text all sit in the context window with equal trust weight, and there is no "parameterized query" equivalent to separate instructions from data. Every AI-era risk — prompt injection, data exfiltration, excessive agency, memory poisoning, tool misuse — is a consequence of that fusion, amplified the moment the model gains **agency** (tools, memory, autonomy). The security industry has responded with a wave of *runtime* products (guardrails, red-teaming, inline enforcement) but there is a conspicuous gap: **no strong open-source, repo-driven, design-time threat-modeling tool that detects AI/agentic/MCP components in a codebase, infers the architecture, and maps concrete code signals to the 2026 OWASP taxonomies with auditable, deterministic findings.** That gap is Maroon Elephant's reason to exist.

---

## 2. Market gap & competitive landscape

### 2.1 What already exists (and why none of it fills the gap)

| Tool | OSS | AI-aware | Repo scan | Threat model | Gap for us to beat |
|---|---|---|---|---|---|
| **STRIDE GPT** (mrwadams, ~1k★) | ✅ | ✅ | ✅ (agentic repo analysis) | ✅ STRIDE + attack trees | LLM-dependent → **non-deterministic**; STRIDE-only (not MAESTRO 7-layer); no SARIF/AI-BOM; no DSGAI/MCP depth. **The closest OSS peer.** |
| **securityscripting/ai-threat-model-assistant** (your ref) | ✅ | ✅ | ❌ | ✅ deterministic rules | **Manual questionnaire**, not a scanner; narrow; no MCP/agentic/MAESTRO; Streamlit toy (~3★). Adopt its *determinism philosophy*, exceed its scope. |
| **OWASP Threat Dragon / pytm / Threagile** | ✅ | ⚠️ partial | ❌ | ✅ (as-code / diagram) | No auto-inference from code; no AI rulepacks. Great *output* patterns to emulate (threat-model-as-code). |
| **IriusRisk + ThreatModeler** (merged) | ❌ | ✅ aggressively ("Jeff" AI, built-in MCP server) | partial | ✅ enterprise | Closed, expensive. **The AI-native enterprise incumbent to displace on the OSS side.** |
| **Semgrep** (+ Guardian, 27 AI rules, MCP server) | ✅ core | ✅ | ✅ | ❌ (detection, not modeling) | Most AI-forward SAST; **emulate its extensibility & SARIF/CI story**, but it does not do architecture-level threat inference. |
| **NVIDIA Garak / Giskard / ART** | ✅ | ✅ | ❌ | ❌ | Model/runtime *testing*, not design-time modeling. Complementary, not competing. |
| **mcp-scan (Invariant), MCP-Scanner (academic), mcp-watch** | ✅ | ✅ MCP-only | partial | ❌ | Narrow to MCP tool-poisoning/rug-pull. **Integrate/emulate as one module, not the whole product.** |
| **Lasso / Straiker / HiddenLayer / NeuralTrust** | ❌ | ✅ | — | runtime | Commercial runtime ASPM. The market is **crowded at runtime, thin at design-time OSS.** |

### 2.2 The white space (our niche, in one line)

> **Open-source, repo-driven, design-time agentic threat modeling with deterministic-first findings, full MAESTRO 7-layer + OWASP 2026 coverage, SARIF + AI-BOM output, and native CI/CD — the "Semgrep/Trivy for AI threat models."**

### 2.3 What makes an OSS security project "award-winning" (lessons from Semgrep, Trivy, Trufflehog, ZAP, Checkov)

- **The 5-minute wow.** Runs on a laptop in seconds, zero-config, no server. Grassroots adoption precedes enterprise.
- **CI/CD-native from day one.** GitHub Action + exit codes + **diff-aware scanning** (fail only on *new* findings).
- **Low false positives = the #1 trust factor.** Deterministic core; LLM only for enrichment behind evidence gates.
- **Extensibility without a DSL tax.** Semgrep won because rules read like code. A large community rulepack becomes the moat.
- **Standard outputs** (SARIF 2.1.0, CycloneDX) so one run feeds both security and governance pipelines.
- **Distribution surfaces**: GitHub Action, VS Code extension, container image, pre-commit hook, and **its own MCP server** (so agents can call Maroon Elephant).
- **Credibility path**: OSI license → OWASP project (Incubator → Lab → Flagship), alignment badges with OWASP GenAI / MITRE ATLAS / NIST AI RMF, strong docs, fast patch cadence.

---

## 3. The threat corpus (what the scanner must know)

Maroon Elephant's knowledge base is the union of four OWASP 2026 taxonomies plus MCP. Each finding is tagged with **stable IDs across all frameworks** so reports are interoperable and auditable.

### 3.1 The scoping decision that structures everything

The **top-level branch** of every scan: *does this repo give the model agency (tools / memory / autonomy)?*
- **Model-as-component** → OWASP **LLM Top 10** owns the risk.
- **Model-as-actor** (tools, cross-session memory, downstream consequences) → risk shifts to the **Agentic Top 10 (ASI)**; LLM entries explicitly *defer their agentic amplification to ASI*.
- **Data at rest/in motion** (training, RAG, embeddings, logs, multimodal) → **DSGAI**.
- **Tool/agent interconnect via MCP/A2A** → MCP guides + ASI04/06/07.

### 3.2 OWASP LLM Top 10 (2026) — with primary scannable signals

Scoring anchor: **OWASP AIVSS v0.8** (LLM08 has its own informational→critical ladder). Ranking is now 75% practitioner vote + 25% incident data (7,714 incidents).

| ID | Risk | Highest-signal repo detections |
|---|---|---|
| **LLM01** | Prompt Injection (now incl. multimodal, invisible-Unicode, memory-persisted) | Multi-source prompt concatenation with no provenance/trust tagging; **no invisible-Unicode stripping** at ingest/render (U+E0000–E007F, U+FE00–FE0F, zero-width); multimodal input with no modality-specific filter; unpinned/unaudited MCP servers; high-priv DB roles in MCP connstrings (e.g. Supabase `service_role`); markdown/image auto-fetch of model output. |
| **LLM02** | Sensitive Information Disclosure | Secrets in prompt templates/tool descriptions; observability SDKs (Langfuse, LangSmith, Helicone, Datadog LLM Obs) logging full prompts/completions/reasoning **without redaction**; **post-retrieval** ACL filtering (should be inside the index query); endpoints returning `logprobs`/`confidence`; regex-only PII redaction. |
| **LLM03** | Excessive Agency (climbed to #3) | Broad tools (`shell`/`exec`/`delete_*`/`send_email`) when app scope is narrower; DB identity beyond `SELECT`; IAM `"*"`; shared high-priv service creds for per-user actions; **no human-in-the-loop** on irreversible actions; authz decided in prompt text, not a deterministic **policy decision point**. |
| **LLM04** | Supply Chain (now incl. artifact substitution, slopsquatting) | `pickle.load` / `torch.load` without `weights_only=True` / `trust_remote_code=True`; **mutable model refs** (`from_pretrained` with no `revision=`, `:latest`, name-only resolution → namespace reuse); no SBOM/AIBOM; unpinned deps & GitHub Actions `@main`; no Sigstore/cosign verification. |
| **LLM05** | Data & Model Poisoning (now incl. fine-tune subversion) | Non-sandboxed `jinja2.Environment` for chat templates (SSTI); unverified `chat_template`/`tokenizer_config.json`/GGUF/LoRA `adapter_config.json` load; RAG mixing trust tiers in one index; no data versioning (DVC); no post-fine-tune trigger/backdoor red-team. |
| **LLM06** | Unbounded Consumption (rose 4 places) | LLM calls with **no `max_tokens`/cost cap**; only request-rate limiting or none; agent executors without `max_iterations`/recursion/time caps (`while True` tool loops); extended-thinking with no thinking-token budget; exposed `logprobs`; unauth serving endpoints (vLLM/Triton/Ray/Ollama). |
| **LLM07** | Misinformation (pulled up by incident data) | Model output driving a decision/tool-call/state-check with **no grounding or verification**; no structured-output schema / mandatory-field validation (omission detection); no **claim-check-act** separation; auto-install of model-named packages (slopsquat). |
| **LLM08** | Hidden Context Exposure (was System Prompt Leakage) | Hard-coded creds/tokens/connection strings in system prompts, prompt templates, tool schemas (CWE-798); authz/refusal logic present **only** as prompt text (no independent guardrail); output-format schema described in prompt but not enforced downstream. |
| **LLM09** | Vector & Embedding Weaknesses | **Post-retrieval tenant/ACL filtering** (definitional finding); single shared index across tenants/trust tiers; **raw similarity scores returned to client** (membership oracle); no ingest normalization (zero-width/homoglyph) before `embed()`; vuln vector-DB versions (Milvus CVE-2025-64513, RAGFlow CVE-2025-69286); unencrypted embedding backups. |
| **LLM10** | Improper Output Handling (fell to #10) | Model output → `os.system`/`subprocess(shell=True)`/`exec`/`eval`/string-built SQL/file paths; unescaped render (`dangerouslySetInnerHTML`, `innerHTML`, `v-html`, Jinja `\| safe`); auto-fetch of markdown-image/link-preview URLs; raw ANSI/OSC control chars to terminal/log (OSC 52 clipboard); auto-deploy of generated code with no SAST gate. |

**Definitional CWEs to anchor rules:** CWE-1427 (Improper Neutralization of Input Used for LLM Prompting, LLM01), CWE-1426 (Improper Validation of Generative AI Output, LLM07/LLM10), CWE-798 (hard-coded creds, LLM08).

### 3.3 OWASP Agentic Top 10 (2026, ASI01–10) — with primary scannable signals

Cross-cutting principle introduced: **Least-Agency** (don't deploy autonomy where not needed) + mandatory observability. Each ASI maps to LLM Top 10, the **T1–T17** agentic threat taxonomy, an **AIVSS** core risk, and the **NHI Top 10**.

| ID | Risk | Highest-signal repo detections |
|---|---|---|
| **ASI01** | Agent Goal Hijack | System prompts as mutable, un-versioned, unsigned strings; retrieved content (web/email/calendar/RAG) feeding the planner with no sanitization/CDR boundary; scheduled-trigger prompts (cron/calendar webhooks) into an agent; no intent/plan-divergence check. |
| **ASI02** | Tool Misuse & Exploitation | Tools with broad scopes (full CRUD, `*` object access, send/delete on a "summarizer"); tools without version pin or fully-qualified name (typosquat/alias); `autoApprove`/auto-run with no per-invocation auth; unrestricted `requests`/`httpx`/`fetch` egress inside tools; missing rate/cost/token budgets. |
| **ASI03** | Identity & Privilege Abuse | Agents under a **shared service account / single static API key**; long-lived secrets in code/`.env`/prompts; parent forwarding full credential/context to sub-agents; OAuth client-credentials with static scopes (no RFC 8693 token-exchange/intent binding); no re-auth between workflow start and tool execution (TOCTOU). |
| **ASI04** | Agentic Supply Chain | MCP deps from npm/PyPI without pinning/signature; `mcp.json`/agent config referencing untrusted remote servers/registries; unpinned/floating deps (`^`, `latest`, `*`); runtime remote prompt-template fetch; no SBOM/AIBOM; `.well-known/agent.json` cards; auto-install-on-discovery. |
| **ASI05** | Unexpected Code Execution (RCE) | `eval`/`exec`/`pickle.loads`/`yaml.load`/`subprocess`/`os.system`/template-engine on model output; code-exec tools (Python REPL, shell, `run_code`) with no sandbox/container; agent running as root / no `--network none`; no codegen↔exec separation; direct write to prod DB/infra. |
| **ASI06** | Memory & Context Poisoning | Vector/memory writes with no validation or provenance; **shared memory namespace across users/tenants**; RAG retrieval with no similarity/tenant filter or trust weighting; agent re-ingesting its own outputs ("bootstrap poisoning"); persistent memory files (`SOUL.md`, `MEMORY.md`, agent JSON) writable by tools; no TTL/decay. |
| **ASI07** | Insecure Inter-Agent Communication | A2A/ACP calls over plain HTTP / no mTLS; no message signing/verification; discovery/registry connections without agent-card attestation; no nonce/timestamp/session-ID (replay); unpinned MCP/A2A protocol version (downgrade). |
| **ASI08** | Cascading Failures | Planner→executor where executor auto-acts without validation; no circuit breaker/progress cap/quota between agents; agents consuming each other's outputs in a loop with no dampening; orchestrator auto-propagating config to all agents; missing tamper-evident lineage logging. |
| **ASI09** | Human-Agent Trust Exploitation | High-impact/irreversible actions with **no confirmation**; "preview"/read-only flows that trigger network/state-changing calls (consent laundering); model-generated rationale presented as authoritative justification; no risk-badging/provenance; HITL that shows only the model's summary, not raw action details. |
| **ASI10** | Rogue Agents | Agents able to spawn/replicate (provisioning API, self-invocation loops, "Ralph Wiggum" unattended loops); no signed behavioral manifest validated before action; missing kill-switch/credential-revocation; no watchdog/anomaly monitoring; reward objectives satisfiable by destructive shortcuts; long-lived keys accessible to agent code. |

### 3.4 OWASP GenAI Data Security (2026, DSGAI01–21) — the data plane

Root-cause thesis (same as §1): **context window = flat trust namespace.** Six data classes to inventory: *source, derived (embeddings/indexes/summaries), model artifacts, runtime (prompts/tool-calls/KV-cache), operational exhaust (logs/traces), agent state/delegation.* The doc's **AI-DSPM 13 capability categories** map directly onto scanner modules.

**Two highest-signal, most machine-detectable clusters** (prioritize for MVP):
- **Vector-DB / RAG cluster** — DSGAI11 (cross-context bleed), DSGAI13 (vector-store platform), DSGAI17 (RAG resilience/staleness), DSGAI18 (inversion/membership inference), DSGAI09 (multimodal derivatives). Concrete client fingerprints: Pinecone, Chroma, Weaviate, Qdrant, Milvus, pgvector, Redis-vector, FAISS, LanceDB, Vespa, ES/OpenSearch kNN. Flags: client-supplied tenant filter vs **server-enforced**; shared index across tenants; unbounded top-k; raw-embedding export enabled; snapshot/import endpoints exposed; unencrypted backups; embedding-API keys treated as non-secrets; deletion not propagating to snapshots.
- **Supply-chain / artifact cluster** — DSGAI04 (data/model/artifact poisoning), DSGAI05 (integrity/validation, incl. **snapshot path-traversal** — Qdrant CVE-2024-3584/-3829). Flags: `pickle`/`torch.load` unsafe; `trust_remote_code=True`; unpinned model names; DP-SGD silently disabled in a preprocessing diff; `tarfile.extractall`/`zipfile` without member validation (symlink/path-traversal).

**Governance risks** (DSGAI03 Shadow-AI, DSGAI07 lifecycle/classification, DSGAI08 compliance, DSGAI15 prompt over-sharing, DSGAI19 labeler overexposure) are **hard to detect from code alone** → implement as **presence/absence + policy-as-code checklist** (Is there a lineage system? Classification metadata on embeddings? DPIA docs? redaction middleware in the outbound path? deletion that also purges embeddings/backups?).

Other notable DSGAI entries with code signals: **DSGAI02** (agent identity/credential exposure — NHI sprawl, operator-token forwarding), **DSGAI06** (tool/plugin/agent data-exchange — MCP without auth, elevated local privileges, full-context forwarding), **DSGAI12** (**unsafe NL→SQL/Graph gateways** — LangChain `SQLDatabaseChain`/`create_sql_agent`/`GraphCypherQAChain`, LlamaIndex text-to-SQL over a single high-priv connection, no row/column-level security, no result-set cap; CVE-2024-8309, CVE-2024-7042), **DSGAI14** (excessive telemetry leakage), **DSGAI16** (browser/IDE extension overreach — `manifest.json` with `<all_urls>`, `tabs`, `clipboardRead`, `nativeMessaging`, filesystem), **DSGAI20** (model exfiltration / CoT-trace exposure), **DSGAI21** (disinformation via RAG poisoning — no source trust-scoring, no write-access control on indexed stores).

### 3.5 MCP threats (server dev + third-party consumption)

**Named attack taxonomy** (canonical labels to key rules off): Tool Poisoning · Rug Pull (dynamic tool instability) · Prompt Injection (direct/indirect) · Confused Deputy · **Token Passthrough** · Credential Leakage · Code Injection/Unsafe Execution · Excessive Permissions · Insufficient Isolation · Memory Poisoning · Tool Interference · (broader: Tool Shadowing, Line Jumping).

**OWASP "MCP Security Minimum Bar"** → 5 rule families: (1) strong identity/auth (OAuth 2.1/OIDC, short-lived scoped tokens, **no token passthrough**), (2) strict isolation & lifecycle (per-session state, deterministic cleanup, quotas), (3) trusted controlled tooling (signed, pinned, approved; description-vs-behavior validation; minimal fields to model), (4) schema-driven validation everywhere (Pydantic/zod/JSON-Schema on tool I/O, size limits), (5) hardened deployment & oversight (non-root container, secrets in vault never reaching the LLM, CI gates, audit logs).

**Server-side signals:** SDK fingerprints (`mcp`, `FastMCP`, `@modelcontextprotocol/sdk`); transport discriminator (**stdio = lower risk** vs HTTP/SSE with `0.0.0.0` bind / missing `Origin` validation / no TLS / no auth middleware = RED); tool handlers with no schema; model args into exec/shell/SQL; `os.environ`/`process.env` as the *secret store*; inbound `Authorization` header forwarded downstream (→ confused deputy); global/singleton per-user state; root container.

**Client-side signals** (parse `mcp.json`, `.mcp.json`, `.cursor/mcp.json`, `claude_desktop_config.json`, `.vscode/mcp.json`, `.claude/settings.json` `mcpServers`): remote `http://`/raw-IP servers; **unpinned provenance** (`npx -y pkg@latest`, `uvx`, `curl … | sh`); secrets inline in `env`/`headers`; **HITL-bypass flags** (`autoApprove`, `alwaysAllow`, `--dangerously-skip-permissions`); many simultaneous third-party servers (tool interference); **registry drift** (server configured but not on the approved allowlist).

**Named tooling to integrate/detect:** Invariant **mcp-scan**, **mcp-watch**, Trail of Bits **mcp-context-protector**, Semgrep MCP rules, OSV-Scanner, OpenSSF Scorecard.

### 3.6 Cross-framework crosswalk (report interoperability)

Every finding carries a tuple so it's comparable across the ecosystem:

`(LLMxx, ASIxx, DSGAIxx, T-code, MAESTRO-layer, AIVSS-core-risk, NHI#, MITRE ATLAS technique, MITRE ATT&CK tactic, CWE, NIST AI 600-1 category, CSA AICM domain, AT-tier, regulatory-tags)`

- **MITRE ATLAS (v2026.06):** AML.T0010 (supply chain), **AML.T0070 (RAG Poisoning)**, AML.T0080.000 (memory context poisoning), plus tactics AML.TA0000–TA0013.
- **MITRE ATT&CK (v19.1):** Initial Access, Execution, Impact, Exfiltration, Priv-Esc, Credential Access, etc.
- **NIST:** AI 600-1 GenAI Profile (12 categories); AI RMF (Govern/Map/Measure/Manage); **Cyber AI Profile IR 8596** (first NIST agentic doc, maps to CSF 2.0).
- **CSA AICM v1.1** control domains (AIS, IAM, DSP, MDS, CEK, STA, TVM, LOG, BCR, IVS, CCC).
- **Regulatory tags:** GDPR (Arts 5/17/22/30/33), HIPAA, CCPA/CPRA, **EU AI Act** (Art 10 in force **Aug 2026**; Arts 13/14/25/26/72/73), Colorado AI Act, DORA (4h), NIS2 (24h), NY RAISE (72h), CA SB 53 (15-day), ISO 42001, Singapore MGF for Agentic AI.

---

## 4. Frameworks Maroon Elephant aligns to

- **MAESTRO (CSA, Feb 2025) — the agentic backbone.** 7 layers: (1) Foundation Models, (2) Data Operations, (3) Agent Frameworks, (4) Deployment Infrastructure, (5) Evaluation & Observability, (6) Security & Compliance (cross-cutting), (7) Agent Ecosystem. Its value: **layer decomposition + cross-layer propagation analysis**, exactly what an automated modeler needs to scope which threats apply once it detects components. We map every detected component to a MAESTRO layer.
- **STRIDE** — retained for the *general software* mode and for per-component trust-boundary analysis (spoofing/tampering/repudiation/info-disclosure/DoS/EoP).
- **Lethal Trifecta (Willison) & Rule of Two (Meta)** — cheap, high-signal automatable heuristics: flag any agent/session that simultaneously has **(A) untrusted input + (B) sensitive-data access + (C) external comms / state change**. This is one of the most valuable single checks we can ship.
- **AIVSS v0.8** — the pinned severity scoring system for agentic risks (with AARS fields). Our numeric severity comes from here, not a home-grown DREAD.
- **AI-DSPM (13 categories)** and the **Enterprise Adoption Maturity Model** (below) — the enterprise reporting spine.

### 4.1 The enterprise maturity model (a differentiator most tools lack)

The State-of-Agentic report gives a **Governance Posture Matrix**: **Adoption Tiers AT0–AT8** (AT0 Shadow AI → AT8 Federated/Cross-Boundary) × **Governance Maturity L0–L4** (Ad Hoc → Adaptive/Self-Regulating). Cells are labelled from "Well-governed" to **"DO NOT DEPLOY."** Maroon Elephant can **classify a scanned repo into an AT tier** (from detected composition patterns) and, combined with what controls it finds present/absent, place it on this matrix and output a concrete "raise maturity or reduce tier" recommendation. This turns a scanner into a **governance decision tool** — the thing enterprises actually pay for.

---

## 5. How to automate threat modeling from a repo (technical strategy)

### 5.1 Deterministic-first, LLM-for-enrichment-only (the core design law)

The single most important decision, validated by both the `ai-threat-model-assistant` philosophy and the LLM-threat-modeling literature (hallucinated threats, irreproducibility, fake reasoning traces):

1. **Deterministic rule engine is the backbone.** Component detection, taint/dataflow, config parsing, dependency analysis → produce findings with **file:line evidence**.
2. **LLM is optional and gated.** It only *enriches* (narrates a threat, drafts a mitigation, labels an inferred data flow) *behind* a deterministic finding, at `temperature=0`, pinned model + seed, prompts snapshotted, and **every LLM claim must cite a code artifact or it's rejected.**
3. **Every finding maps to a stable framework ID** (the §3.6 tuple) so output is comparable and auditable across runs and across the ecosystem.
4. **Provenance on every finding**: which rule/model/version produced it. Diff-based re-runs keep noise down; human-in-the-loop confirmation for high-impact findings.

This is the property that lets us claim "no hallucinated threats" — the thing that makes security teams trust the output.

### 5.2 The pipeline (five stages)

1. **Ingest** — clone/scan a GitHub repo (URL or local path), respect `.gitignore`, handle monorepos.
2. **Detect & inventory** — fingerprint AI/agentic/MCP/data components (see §5.3) → build an **AI-BOM** and a component graph. This *is* the AI-DSPM "asset discovery first" step.
3. **Infer architecture** — from imports, entry points, tool registrations, network/DB/vector call-sites, IaC, and MCP wiring, build a component + data-flow graph and assign each node a **MAESTRO layer** and **trust tier**. (Deterministic graph first; LLM only to *label/narrate*.)
4. **Analyze** — run the rule packs (LLM/ASI/DSGAI/MCP/STRIDE) against code, configs, deps, and the inferred graph; run the Lethal-Trifecta/Rule-of-Two heuristic on each agent/session; compute AIVSS severity; place the repo on the AT×L maturity matrix.
5. **Report** — emit **SARIF 2.1.0** (for GitHub/Azure code scanning), **CycloneDX AI/ML-BOM (ECMA-424 v1.7)**, a threat-model report (Markdown/HTML/PDF) with the full crosswalk + compliance tags, and a machine-readable **threat-model-as-code** file (YAML/JSON) that is diffable in PRs.

### 5.3 Component detection catalog (the fingerprint library)

- **Agent/orchestration frameworks** (inventory + CVE tracking + hook-point audit): `langchain`, `langgraph`, `crewai`, `autogen`/`ag2`, `llama-index`, `semantic-kernel`, `openai-agents`, `claude-agent-sdk`, `dify`, `google-adk`, `autogpt`, `open-interpreter`, `openhands`, `cline`, `aider`, `browser-use`, `n8n`.
- **Lightweight/harder-to-inventory** (security is builder-owned): `litellm`, direct `openai`/`anthropic` SDK calls, `baml`, `instructor`.
- **Model SDKs:** `openai`, `anthropic`, `google-generativeai`, `mistralai`, `cohere`, `ollama`, `transformers`.
- **MCP / A2A:** `mcp` SDK, `@modelcontextprotocol/*`, `mcp.json`/`.mcp/`, `.well-known/agent.json`, A2A/ACP/NANDA/ANS clients.
- **Vector DBs / RAG:** Pinecone, Weaviate, Chroma, Qdrant, Milvus, pgvector, Redis-vector, FAISS, LanceDB, Vespa, ES/OpenSearch kNN; RAG frameworks (LangChain/LlamaIndex/Haystack).
- **Training/fine-tune:** `peft`/`LoraConfig`, `trl`, HF `Trainer`, DP libs (`opacus`, `dp-transformers`).
- **Observability:** LangSmith, Langfuse, Helicone, Datadog LLM Obs, Arize/Phoenix, W&B, OpenLLMetry.
- **Low-code/platform** (highest shadow-AI risk): Copilot Studio, Agentforce, Power Automate/AI Builder, Zapier, ServiceNow AI manifests.
- **Agentic-ness signals:** tool/function registration, autonomous loops, memory stores, multi-agent orchestration, code-execution tools, external comms — these flip the scan into ASI mode and trigger the trifecta check.

### 5.4 Output formats (table stakes + differentiators)

- **SARIF 2.1.0** — primary; native GitHub/Azure code-scanning integration.
- **CycloneDX AI/ML-BOM (ECMA-424 v1.7)** + optional **SPDX 3.0 AI/Dataset profiles** — one document carries SBOM + AI-BOM (+ our extension: RAG corpus versions, embedding-model-per-store, classification-tag propagation → a **Data Bill of Materials**).
- **Threat-model-as-code** (YAML/JSON, pytm/Threagile-style) — reviewable in PRs, re-runnable, the basis for *continuous* threat modeling.
- **Governance report** — the AT×L matrix placement + compliance crosswalk (reuse DASF-style mappings), the enterprise deliverable.

---

## 6. Key design principles (carried into the Build Plan)

1. **Deterministic-first; LLM strictly optional and evidence-gated.** No finding without file:line evidence. Air-gapped mode must be fully functional with zero LLM.
2. **Detection ≠ modeling — do both.** Signals (SAST-style) *feed* an architecture/threat model (design-time). This is the core differentiator vs Semgrep et al.
3. **Everything maps to stable framework IDs.** The §3.6 crosswalk tuple on every finding.
4. **Enterprise from the first commit:** SARIF, CI exit codes, diff-aware scanning, policy-as-code, air-gapped, compliance tags — not bolted on later.
5. **The 5-minute wow:** `pipx install` / `npx` / Docker one-liner; `maroon scan <repo>` prints a ranked, evidence-backed report in seconds.
6. **Extensibility as a moat:** a clear, contribution-friendly rule format (rules read like code / declarative YAML) so the community grows the knowledge pack — *and* so it stays current as OWASP updates.
7. **Low false positives > coverage** at low effort levels; a tunable effort dial (like `/code-review`) for broader-but-noisier scans.
8. **Ship its own MCP server** so agents/IDEs can invoke Maroon Elephant (dogfooding the ecosystem it secures).

---

## 7. Risks, uncertainties & open questions

- **Framework churn.** OWASP GenAI, MITRE ATLAS, and AIVSS are all versioning fast (ATLAS counts differ across sources; AIVSS is v0.8/pre-1.0). → Version-pin the knowledge pack; make it independently updatable from the engine; verify ATLAS counts against `atlas.mitre.org` before publishing.
- **Architecture inference is hard.** LLM-only DFD generation is error-prone. → Deterministic graph first; LLM only labels. Manage expectations: v1 infers a *component + dataflow graph*, not a perfect DFD.
- **Governance checks are presence/absence.** Many DSGAI/ASI governance risks can't be proven from code (Is there a DPIA? Real classification?). → Ship as checklist/policy-as-code with honest "unknown/needs-attestation" states, not false confidence.
- **False-positive trust.** One noisy release can kill adoption. → Curated, tested rule corpus; confidence scores; diff-aware defaults; a public benchmark repo suite.
- **Licensing of reference material.** OWASP docs are CC BY-SA 4.0 (attribution + share-alike) — fine to build on with attribution; don't copy text verbatim into code/UI without credit. The `ai-threat-model-assistant` repo has **no visible license** — treat as inspiration only, don't reuse its code.
- **PDF ingestion dependency.** This environment lacked `poppler`/`pdftoppm`; `pypdf` was the working fallback. If Maroon Elephant ingests OWASP/policy PDFs, document `pypdf` (and/or `poppler`) as a dependency and sanity-check extraction (a corrupted extract silently swapped documents mid-file in our own research).
- **Scope creep between "AI-era" and "general".** → Two modes sharing one engine: `--profile ai` (LLM/ASI/DSGAI/MCP packs) and `--profile general` (STRIDE + classic SAST/secrets/IaC). Default auto-detects from component inventory.

---

## 8. Ecosystem finding: Grey Panda as the deterministic engine

The user's own OSS tool, **[grey-panda](https://github.com/dibakshya01/grey-panda)** (`dibakshya01/grey-panda`, Apache-2.0), turns out to be an almost-perfect fit for the "deterministic core" this project needs — and it already exists, tested and shipping (v1.0.7, 2026-09-30).

- **What it is:** *"a zero-dependency, standards-anchored AI security toolkit for developers and security reviewers."* Pure Python ≥3.9, **stdlib-only**, deterministic by design (regex + AST + a JSON standards pack — explicitly **no LLM in the loop**: same code → same verdict). The stated philosophy — *"the calling LLM does the fuzzy reasoning; Grey Panda supplies reproducible, standards-cited ground truth"* — is exactly Maroon Elephant's deterministic-first design law (§6).
- **What it ships:** (1) a **static scanner** — 27 rules (7 critical / 13 high / 7 medium), Python AST taint pass for model-output→sink, output as Markdown / JSON / **SARIF 2.1.0**; (2) a **guardrail SDK** (PromptGuardrail, DLPScanner, OutputGuardrail, AgentSecurityWrapper, McpServerGuard, AuditLogger…); (3) a **working 6-tool stdio MCP server** (`gp mcp`); plus **`gp verify`** (AISVS L1/2/3), **`gp agbom`** (Agent Bill of Materials), and a standards knowledge pack.
- **Standards anchoring:** every rule cites a control ID across **OWASP LLM Top 10 2026 / Agentic (ASI) / DSGAI 2026 / AISVS / MCP-security** — the same taxonomies catalogued in §3.
- **MCP tools exposed** (stdio JSON-RPC, protocol `2025-06-18`): `greypanda_scan_path` (path/profile/format→report), `greypanda_review_snippet`, `greypanda_verify`, `greypanda_explain_risk` (control_id→description+remediation), `greypanda_list_standards`, `greypanda_checklist`. Register with `{"mcpServers":{"grey-panda":{"command":"gp","args":["mcp"]}}}`.
- **Honest, self-documented gaps** (from its own `WHAT_IT_CAN_AND_CANNOT_DO.md`): static-only, **Python-centric** (other languages partial), pattern-based (FP/FN on obfuscation), MCP tool-poisoning detection is heuristic, **MCP transport is stdio-only**, and **SARIF is not exposed over MCP** (CLI `gp scan --format sarif` only). Maturity is early (solo author, ~1★, beta).

**Architectural consequence — this is the most important update to the plan:** Maroon Elephant does **not** rebuild the deterministic rule layer. It **orchestrates Grey Panda as a pluggable deterministic sub-scanner** (via its MCP server for JSON findings; via CLI for SARIF; or by importing `greypanda.scanner.engine` directly) and layers on top the things Grey Panda explicitly is *not*: multi-repo orchestration, architecture/dataflow inference, cross-language coverage, the threat-model synthesis, the AT×L governance verdict, the GitHub integration, and the local UI. Two complementary Apache-2.0 tools, same author:

> **Grey Panda = the calm, deterministic, in-the-file guardian. Maroon Elephant = the orchestrating, design-time, multi-repo threat-modeler that stands on top of it.**

Integration guardrails: keep Grey Panda an **optional, detect-or-invoke** sub-scanner with graceful fallback (it's young, stdio-only, Python-centric) — never a hard dependency. ME supplies its own SARIF (Grey Panda's isn't exposed over MCP) and its own cross-language engine. ME can also *reuse Grey Panda's standards JSON* as a shared control vocabulary via `greypanda_list_standards`/`greypanda_explain_risk`, and reuse/extend **`gp agbom`** for the AI inventory requirement.

## 9. Enterprise platform finding: GitHub integration

For the "integrate with GitHub" requirement, the official guidance (docs.github.com, Oct 2026) is unambiguous:

- **Build a GitHub App, not an OAuth App.** Fine-grained permissions, per-repo installation control, **short-lived (1h) installation tokens**, a bot identity (`@maroon-elephant[bot]`), rate limits that scale with org size, and — critically for enterprise — **a GitHub App installed by an org owner is not blocked by a user's SAML/SSO session** the way an OAuth token is.
- **Least-privilege permission set:** `metadata:read`, `contents:read` (needed to clone over HTTPS), `code scanning alerts:write` (SARIF upload), `checks:write` (PR-diff annotations/gating), `pull requests:read`. Nothing more.
- **SARIF is the integration spine.** `POST /repos/{owner}/{repo}/code-scanning/sarifs` — SARIF **2.1.0**, gzip+Base64, with `commit_sha`, `ref` (`refs/pull/N/merge` on PRs), a distinct **`category: maroon-elephant`** (so our results don't collide with CodeQL), and **we must emit our own `partialFingerprints`** (the raw API won't compute them). Limits: 10 MB gzip, 25k results/run, 1,000 SARIF uploads/hr/repo. Findings then render in the repo's **Security → Code scanning** tab and inline on PRs.
- **The commercial gate to design around:** third-party SARIF on **private** repos requires the customer to hold a **GitHub Code Security** license (the 2025 GHAS unbundling); **public repos are free**. The **Checks API** (`POST .../check-runs`, ≤50 annotations/request, pass/fail `conclusion`) produces inline PR annotations and gating **on any repo without that license** — so ship *both*: SARIF for the full alert experience, Checks for universal gating.
- **Distribution:** a thin **GitHub Action** (Docker or composite) that emits `results.sarif` and reuses `github/codeql-action/upload-sarif@<SHA>` is the lowest-friction path; Actions publish to Marketplace immediately (no GitHub review), whereas paid **Apps are reviewed**. Pin all third-party actions by full commit SHA.
- **Webhooks:** subscribe to `installation`/`installation_repositories` (build repo inventory), `push`/`pull_request` (enqueue scans), `check_run.rerequested` (re-run). Verify `X-Hub-Signature-256` HMAC with a constant-time compare; dedupe on `X-GitHub-Delivery`.
- **Cloning at scale:** `git clone https://x-access-token:<IAT>@github.com/OWNER/REPO.git`, shallow/partial (`--depth 1 --filter=blob:none`), fresh token per batch (1h expiry), respect `x-ratelimit-*` headers, prefer webhooks over polling.
- **AI-aware GitHub surfaces:** SBOM export is **SPDX 2.3** (`GET .../dependency-graph/sbom`; CycloneDX is *not* a native export but can be ingested via the Dependency Submission API). **No official AI-BOM/ML-BOM GitHub format exists yet (Oct 2026)** — opportunity for ME to define/contribute one. **GitHub ships its own MCP server** (`github/github-mcp-server`, MIT) with `code_security`/`secret_protection`/`dependabot` toolsets — ME can *consume* it to read a customer's existing scan state as context, **and** ship its own MCP server so Copilot/agents/IDEs query ME findings in-editor (the emerging agent-native distribution channel).

**Security posture for the App (bake in from day one):** private key in a KMS/secrets-manager (never env/repo), 1h tokens cached until near-expiry, webhook-secret HMAC verification, least-privilege `GITHUB_TOKEN` in the Action, don't retain customer source longer than a scan needs.

## 10. Enterprise UX findings: orchestrator, crown jewels, BYOK, live-agent

- **Multi-agent orchestrator (dogfooding).** The enterprise edition is itself an agentic application: an **Orchestrator** agent ingests targets + a natural-language **crown-jewels** description, classifies repos into a **P0→P1→P2** priority queue, and fans out specialist workers (Recon/Inventory, AI/agentic detector, classic-vuln/SAST, data-security/RAG, threat-model synthesizer, and a **verifier/critic** to suppress false positives). This must follow ME's *own* Least-Agency + deterministic-first rules — the agents orchestrate and narrate; **findings still come from the deterministic engine (incl. Grey Panda) with file:line evidence.** A tool that threat-models agentic apps should pass its own scan — a powerful credibility demo.
- **Crown jewels → risk-based prioritization.** "Crown jewels" is the classic threat-modeling notion of highest-value assets. Letting the user describe them in plain language (e.g., *"the payments service, the auth service, the customer-data pipeline"*) lets the orchestrator rank what to scan first. This is a genuine differentiator: most scanners treat every repo equally; ME scans **by business blast-radius**, mapping onto the AIVSS/AT×L severity model.
- **BYOK / BYOT as a trust feature, not just config.** For a tool scanning crown-jewel repos, *where does my code go?* is the first enterprise question. **Local-first + BYOK** answers it: the deterministic engine runs entirely locally; only (optionally) **redacted** snippets go to the user's **own** LLM via their **own** key, which is **stored locally and never sent to our servers**. Support Anthropic/OpenAI/Google/Azure + **local Ollama/LM Studio** (which also delivers the air-gapped mode for free). Ship a plain-language **"What is BYOT?"** onboarding guide (what it is, why it protects their data, per-provider key steps, cost expectations, spend caps) for users who've never heard the term.
- **Live Browser-Agent mode vs clone/API (the design call):** scraping source code through a browser is slower and more brittle than cloning. So ME uses a **hybrid**: the robust **clone/API data path** does the actual analysis; a visible **Live Browser-Agent mode** (opens Chrome, enumerates/authenticates, shows the agent working) serves demos, first-run onboarding before the GitHub App is installed, and targets only reachable via the web UI. The user gets the "watch the agent scan" experience *and* enterprise reliability/scale.
- **Three inputs, three outputs.** Inputs: **paste URL(s)** · **upload repo(s)** (zip/drag-drop/local path) · **connect GitHub App** (preferred). Deliverables (all three, not just vuln detection): **(1) vulnerability findings**, **(2) a design-time threat model** (architecture graph → MAESTRO → OWASP taxonomies → AIVSS), and **(3) an AI inventory / AI-BOM** ("do you even know what AI you're running?" — AI-DSPM category 1, extensible from `gp agbom`).

## 11. Source corpus

**Local (project root, OWASP GenAI Security Project, CC BY-SA 4.0):**
- OWASP GenAI LLM Top 10 2026 v1.0 (122 pp)
- OWASP Top 10 for Agentic Applications 2026 (ASI01–10, 57 pp)
- State of Agentic AI Security and Governance v2.01 (139 pp)
- OWASP GenAI Data Security 2026 v1.0 (DSGAI01–21, 103 pp)
- A Practical Guide for Secure MCP Server Development v1.0 (17 pp)
- Cheat Sheet: Securely Using Third-Party MCP Servers v1.0 (16 pp)

**External:** Lasso Security "AI Threat Modeling Frameworks for Agentic AI"; `github.com/securityscripting/ai-threat-model-assistant`; CSA MAESTRO (`cloudsecurityalliance.org` + `github.com/CloudSecurityAlliance/MAESTRO`); MITRE ATLAS (`atlas.mitre.org`); NIST AI RMF / AI 600-1 / IR 8596; Google SAIF 2.0; Databricks DASF 2.0; CycloneDX ML-BOM (ECMA-424); SARIF 2.1.0 (OASIS); Semgrep, Trivy, STRIDE GPT, Garak, Invariant mcp-scan (competitive/tooling references).

**Ecosystem & platform (added 2026-10-02):** `github.com/dibakshya01/grey-panda` (the deterministic engine — Apache-2.0, v1.0.7, verified by source inspection); GitHub developer platform docs (docs.github.com) — GitHub Apps, Code Scanning SARIF API, Checks API, GitHub Actions, webhooks, rate limits, Marketplace, SBOM/Dependency Submission, `github/github-mcp-server`.

→ Continue to **[Build Plan.md](Build%20Plan.md)**.
