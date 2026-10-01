# Maroon Elephant — Build Plan

**An open-source, AI-era threat-modeling & repository-scanning platform.**
Derived from [Findings.md](Findings.md) · Date: 2026-09-30 (rev. 2026-10-02) · Target license: Apache-2.0

> *"The Semgrep/Trivy for AI threat models."* Point it at GitHub; it detects AI/agentic/MCP components, infers the architecture, and produces deterministic, evidence-backed threat findings mapped to the OWASP 2026 taxonomies, MAESTRO, MITRE ATLAS, and your compliance obligations — across a whole org, worst-first.

---

## 1. Product vision & positioning

**Who it's for (priority order):**
1. **Enterprise AppSec / AI governance teams** — need org-wide scanning, crown-jewels prioritization, a UI, CI/CD gates, SARIF, compliance crosswalks, air-gapped runs, and the AT×L maturity verdict.
2. **Solo devs & "vibecoders"** — need a `maroon scan .` that gives a ranked, plain-language report and a VS Code squiggle in seconds.
3. **The OWASP/security community** — need a clean rule-contribution model to keep the knowledge pack current.

**Positioning:** the only open-source, **repo-driven, design-time** threat modeler with **deterministic-first** findings, **full MAESTRO 7-layer + OWASP 2026 (LLM/ASI/DSGAI/MCP)** coverage, **SARIF + AI-BOM** output, native CI/CD, and an **agentic, crown-jewels-first org scanner with a local UI** — filling the white space between crowded runtime products and code-only SAST.

**The ecosystem play (two complementary Apache-2.0 tools, same author):**
> **Grey Panda** (`dibakshya01/grey-panda`) = the calm, deterministic, in-the-file guardian (regex+AST, OWASP-tagged, ships a 6-tool MCP server).
> **Maroon Elephant** = the orchestrating, design-time, multi-repo threat-modeler that **stands on top of Grey Panda** and adds architecture inference, multi-agent org scanning, the governance verdict, the GitHub integration, and the UI.

Maroon Elephant consumes Grey Panda as its deterministic sub-scanner (detect-or-invoke, never a hard dependency) rather than rebuilding the rule layer. See §8.

**Non-goals (v1):** runtime/inline enforcement; live red-teaming/fuzzing of a deployed model (Garak/Giskard territory — we *integrate*); a pixel-perfect auto-DFD (we produce an honestly-scoped component + dataflow graph).

---

## 2. Design laws (non-negotiable, from Findings §6)

1. **Deterministic-first.** Every finding carries `file:line` evidence and comes from the deterministic engine (ME's own rules + Grey Panda). Air-gapped mode is fully functional with zero LLM.
2. **LLM is optional & evidence-gated.** `temperature=0`, pinned model+seed, prompts snapshotted; enrichment only, behind a deterministic finding; any claim without a cited code artifact is dropped. **This applies to the enterprise orchestrator agents too — they orchestrate and narrate; they never invent vulnerabilities.**
3. **Detection feeds modeling.** SAST-style signals are inputs to a design-time architecture/threat model — that dual nature is the moat.
4. **Every finding carries the full crosswalk tuple** (Findings §3.6).
5. **Enterprise-grade from commit #1:** SARIF, exit codes, diff-aware, policy-as-code, compliance tags.
6. **Low false positives beat coverage** at default effort; effort is a dial.
7. **Knowledge pack is versioned & independently updatable** from the engine.
8. **Local-first & BYOK.** Source code never leaves the user's machine by default; only redacted snippets, only to the user's own LLM via their own key, only if they opt in. (See §12.) Maroon Elephant must be able to pass its own scan.

---

## 3. Two editions, one engine

| | **Core (OSS)** | **Enterprise (OSS, self-hosted)** |
|---|---|---|
| Surface | CLI, GitHub Action, VS Code ext, pre-commit, MCP server | Everything in Core **+ local-host web UI + multi-agent orchestrator** |
| Scan scope | one repo / path / diff | **whole org, many repos, crown-jewels-first (P0→P1→P2)** |
| Input | path / URL | path / **upload** / URL / **GitHub App connect** / **Live Browser-Agent** |
| AI usage | optional enrichment | orchestrator agents + optional enrichment (BYOK) |
| Deliverables | SARIF, AI-BOM, TM-as-code, report | + live dashboards, inventory explorer, threat-model diagram, AT×L governance verdict, PDF board report |
| Who runs it | devs, CI | AppSec / governance teams |

Both editions share the same deterministic engine, knowledge pack, and output formats. Enterprise is a **superset**, self-hostable and air-gappable — no SaaS required. (An optional hosted control-plane is a *later, open-core* consideration, never a gate on the OSS core.)

---

## 4. Architecture

```
 INPUTS                         ENTERPRISE ORCHESTRATION                         OUTPUTS
┌──────────────┐   ┌──────────────────────────────────────────────┐   ┌────────────────────────┐
│ paste URL(s) │   │           ORCHESTRATOR AGENT                   │   │ SARIF 2.1.0            │
│ upload repo  │──▶│  crown-jewels NL → P0/P1/P2 priority queue     │   │ CycloneDX AI/ML-BOM    │
│ GitHub App   │   │  dispatch · budget/BYOK · least-agency guard   │──▶│ TM-as-code (YAML)      │
│ Live Browser │   └───────┬───────────┬───────────┬───────────────┘   │ Governance report (PDF)│
│   -Agent     │           ▼           ▼           ▼                   │ AI inventory explorer  │
└──────────────┘   ┌───────────┐ ┌───────────┐ ┌───────────────┐       └──────────┬─────────────┘
       │           │ Recon /    │ │ Analyzer  │ │ Threat-model  │                  │
       ▼           │ Inventory  │ │ workers   │ │ synthesizer   │                  ▼
┌──────────────┐   │ (AI-BOM)   │ │ (parallel)│ │ + Verifier    │        ┌────────────────────────┐
│ 1. INGEST     │  └───────────┘ └─────┬─────┘ └───────────────┘        │ Local-host Web UI       │
│ git/clone/zip │                      │  each worker calls ↓            │ (stdlib http.server+SSE)│
└──────┬───────┘                       ▼                                 │ live board · diagrams   │
       ▼            ┌────────────────────────────────────────────┐      └────────────────────────┘
┌──────────────┐    │  DETERMINISTIC ANALYSIS CORE                │
│ 2. DETECT     │──▶ │  · ME rule packs (LLM/ASI/DSGAI/MCP/STRIDE) │◀── KNOWLEDGE PACK (versioned)
│  AI-BOM/inv.  │    │  · taint / dataflow / config / secret / IaC │     rules · crosswalk · CVE DB
└──────┬───────┘    │  · Grey Panda (MCP/CLI) — det. sub-scanner   │     AIVSS · AT×L · compliance
       ▼            │  · Lethal-Trifecta / Rule-of-Two heuristic   │
┌──────────────┐    │  · AIVSS severity + AT×L maturity placement  │     SUB-SCANNERS (detect-or-invoke)
│ 3. GRAPH      │──▶ │  · (optional) LLM enrichment, evidence-gated │◀── grey-panda · semgrep · osv
│  arch+MAESTRO │    └────────────────────────────────────────────┘     gitleaks/trufflehog · mcp-scan
└──────────────┘
 GitHub integration: App (installation tokens) · SARIF upload + Checks annotations · Action · webhooks · ME's own MCP server
```

### 4.1 Module responsibilities

| Module | Responsibility |
|---|---|
| `ingest` | Repo acquisition (URL / **upload zip** / local / **GitHub App clone**), monorepo walk, language detect, `.gitignore`, PDF/policy ingestion (`pypdf`). |
| `detect` | Component fingerprint library (Findings §5.3) → inventory + **AI-BOM** (extends `gp agbom`). |
| `graph` | Component + dataflow graph from imports, entry points, tool registrations, call-sites, IaC, MCP wiring; MAESTRO layer + trust tier per node. |
| `analyze` | ME rule-pack execution, taint/dataflow, config parsers (`mcp.json`, `manifest.json`, Dockerfile, Terraform), secret detection, trifecta heuristic. |
| `subscan` | **detect-or-invoke** adapters: Grey Panda (MCP/CLI), Semgrep, OSV-Scanner, Gitleaks/Trufflehog, Invariant mcp-scan — normalized into ME findings. |
| `score` | AIVSS v0.8 severity; AT-tier classification; L-maturity from present/absent controls; posture-matrix placement. |
| `orchestrator` (Enterprise) | Crown-jewels → priority queue; dispatch worker agents; BYOK budget/rate-limit; least-agency enforcement; result aggregation. |
| `enrich` (optional) | Evidence-gated LLM narration/mitigation; BYOK provider-agnostic; **off by default**. |
| `report` | SARIF, CycloneDX AI/ML-BOM, TM-as-code, HTML/PDF/MD governance report. |
| `ui` (Enterprise) | stdlib `http.server` + Server-Sent Events + vanilla JS; live scan board, inventory explorer, threat-model diagram, governance verdict, BYOK setup + "What is BYOT?" guide. |
| `github` (Enterprise) | GitHub App: installation tokens, org repo enumeration, clone, **SARIF upload + Checks annotations**, webhooks, the ME Action. |
| `knowledge` | Versioned rule + crosswalk + CVE + scoring + compliance packs, loadable independently. |
| `serve-mcp` | Expose ME scan/report as MCP tools so agents/IDEs/Copilot call Maroon Elephant. |

---

## 5. The enterprise multi-agent orchestrator

Maroon Elephant Enterprise is **itself an agentic + MCP application** — deliberately, so it dogfoods the very architecture it audits and must pass its own scan. The orchestration obeys ME's own Least-Agency and deterministic-first laws: **agents plan, prioritize, dispatch, and narrate; the deterministic core produces every finding with evidence.**

| Agent | Role | Agency budget |
|---|---|---|
| **Orchestrator** | Parse input + crown-jewels NL → classify repos into **P0/P1/P2** → build scan queue → dispatch workers → aggregate → place on AT×L matrix. Enforces BYOK spend caps, rate limits, step/time ceilings (ASI08/LLM06 controls — applied to *itself*). | Plan + dispatch only; no code exec. |
| **Recon / Inventory** | Enumerate repos (GitHub API or Live Browser-Agent), build the **AI-BOM/inventory** (extends `gp agbom`), tag crown-jewels, assign priority scores. | Read-only. |
| **Analyzer workers** (parallel, per-repo/per-domain) | Run the deterministic core + `subscan` adapters (incl. Grey Panda) + `graph` inference on **cloned** code. Specializations: AI/agentic/MCP, classic-vuln/SAST/secrets/IaC, data-security/RAG. | Deterministic engine only. |
| **Threat-model synthesizer** | Assemble component graph → MAESTRO layers → applicable threats → AIVSS severity → AT×L verdict → report. | LLM narration, evidence-gated. |
| **Verifier / critic** | Adversarially re-check findings against evidence to suppress false positives (mirrors `/code-review` verify pass). | Read + reason; can only downgrade/drop, never invent. |

**Crown-jewels prioritization (the differentiator):** the user describes highest-value assets in plain language (*"payments, auth, the customer-data pipeline"*); the Orchestrator maps repos/services to P0/P1/P2 by **business blast-radius**, and scans worst-first. Most scanners treat every repo equally; ME scans by consequence, aligned to the AIVSS/AT×L severity model. Priority is overridable in the UI.

**Agency safety for the orchestrator itself:** hard step/recursion/time/cost caps; no repo write access (read + clone only); no secret ever reaches an LLM (redaction middleware); a visible kill-switch; tamper-evident run log. These are the exact ASI/LLM controls ME checks for — proving them on itself is a headline demo.

---

## 6. Local-host UI & the scan workflow

`maroon serve` boots a local server and opens `http://localhost:7879` (configurable). No cloud account; everything runs on the user's machine.

**Workflow (first run):**
1. **Choose a target:** paste GitHub URL(s) · **upload** a repo (drag-drop zip / local path) · **Connect GitHub** (install the App) · or **Live Browser-Agent** (opens Chrome, enumerates, authenticates visibly).
2. **Describe your crown jewels** in a text box (optional but recommended) → Orchestrator builds the P0/P1/P2 queue, shown and editable.
3. **Set up BYOK** (if enrichment/agents are enabled) — provider picker + the **"What is BYOT?"** guide (see §12). Skippable entirely: deterministic-only mode needs no key.
4. **Run.** The **live scan board** streams over Server-Sent Events: the priority queue, each agent's status, repos completing, findings accumulating.
5. **Review:** four dashboards — **Findings** (SARIF-backed, filter by OWASP/ASI/DSGAI/severity), **AI Inventory** (the AI-BOM explorer), **Threat Model** (component graph → MAESTRO, Mermaid), **Governance** (AT×L placement + compliance crosswalk + "raise maturity or reduce tier" guidance).
6. **Export:** SARIF · CycloneDX AI/ML-BOM · TM-as-code YAML · PDF board report.

**Live Browser-Agent mode (the "watch it work" experience):** uses an automated browser to open the target in Chrome, log in (user-driven for anything sensitive — never auto-entering credentials), enumerate the org's repos, and visibly drive discovery. The **actual code analysis still happens on cloned code** via the deterministic core — the browser is the live/visible enumeration + onboarding + demo surface, and the fallback for targets only reachable through the web UI. Honest trade-off stated in-product: clone/API is the default for reliability and scale; browser mode is for demos, pre-install onboarding, and web-only targets.

**UI tech (authoritative = §10):** stdlib **`http.server`** backend (same Python engine) + a small JSON API + **Server-Sent Events** for live progress; frontend is **vanilla JS + CSS**, no node build step, served as static files. Zero runtime deps, works air-gapped. A polished "award-winning" visual identity is achieved in plain HTML/CSS (design pass in Phase 4), not a heavy SPA framework.

---

## 7. GitHub integration (Enterprise, from Findings §9)

**Ship a GitHub App** (not OAuth) + a thin **Marketplace Action**.

- **GitHub App** — least-privilege permissions: `metadata:read`, `contents:read`, `code scanning alerts:write`, `checks:write`, `pull requests:read`. Server-to-server via **1h installation tokens** (JWT-signed by the app key, cached until near-expiry, scoped to specific repos when possible). Bot identity `@maroon-elephant[bot]`. Survives SAML/SSO (App install isn't blocked by a user's SAML session — key enterprise win).
- **Findings back to GitHub:**
  - **SARIF upload** `POST /repos/{o}/{r}/code-scanning/sarifs` — 2.1.0, gzip+Base64, `ref=refs/pull/N/merge` on PRs, **`category: maroon-elephant`**, **our own `partialFingerprints`**. → Security tab + inline PR alerts. *(Private repos require the customer's GitHub Code Security license; public repos free.)*
  - **Checks API** `POST .../check-runs` — inline PR-diff annotations + pass/fail gating, ≤50 annotations/request (paginate via PATCH). **Works on any repo without a Code Security license** → universal gating path. Ship *both*.
- **GitHub Action** (Docker or composite): emits `results.sarif`, reuses `github/codeql-action/upload-sarif@<SHA>`; `permissions: {contents: read, security-events: write}`. Publishes to Marketplace immediately.
- **Webhooks:** `installation`/`installation_repositories` → build/refresh inventory; `push`/`pull_request` → enqueue scans; `check_run.rerequested` → re-run. Verify `X-Hub-Signature-256` (HMAC-SHA256, constant-time), dedupe on `X-GitHub-Delivery`.
- **Org scanning at scale:** `GET /installation/repositories`; clone `https://x-access-token:<IAT>@github.com/...` shallow (`--depth 1 --filter=blob:none`); fresh token per batch; respect `x-ratelimit-*`; prefer webhooks over polling.
- **AI-aware GitHub surfaces:** pull **SPDX SBOM** (`GET .../dependency-graph/sbom`) for inventory; optionally submit ME's own component snapshot via the Dependency Submission API; **consume `github/github-mcp-server`** (`code_security`/`secret_protection`/`dependabot` toolsets) to read existing scan state as context; **ship ME's own MCP server** for in-editor/agent consumption. *No official GitHub AI-BOM format exists yet (Oct 2026) — ME can help define one.*
- **App security:** private key in KMS/secrets-manager; least-privilege `GITHUB_TOKEN`; SHA-pinned actions; don't retain customer source past a scan.

---

## 8. Grey Panda & sub-scanner integration (from Findings §8)

ME treats deterministic scanners as **pluggable sub-scanners** (detect-or-invoke, graceful fallback, normalized into ME's finding model + crosswalk tuple). **Grey Panda is the flagship adapter.**

- **Invocation (three paths, pick per environment):**
  1. **MCP (default):** spawn `gp mcp` (stdio JSON-RPC), call `greypanda_scan_path(path, profile="enterprise", format="json")` → ingest `findings[]` (already OWASP-2026-tagged) as hard, citeable evidence.
  2. **CLI (for SARIF):** `gp scan <path> --format sarif` (SARIF isn't exposed over MCP) when ME wants Grey Panda's native SARIF.
  3. **Direct import:** `from greypanda.scanner.engine import AISecurityScanner` for in-process use (fastest, no subprocess).
- **What ME uses it for:** deterministic ground-truth findings under ME's threat model; **`greypanda_explain_risk` / `greypanda_list_standards`** as a shared control vocabulary; **`greypanda_verify` (AISVS L1/2/3)** in the enterprise governance report; **`gp agbom`** as the seed for ME's AI inventory.
- **Guardrails:** optional, never a hard dependency (Grey Panda is young, stdio-only, Python-centric). ME supplies its own SARIF, its own cross-language coverage (tree-sitter), and its own architecture/threat-model layer — the things Grey Panda explicitly is *not*. If `gp` is absent, ME's native rules still run.
- **Contribution loop:** gaps ME finds (e.g., SARIF-over-MCP, more languages) are upstreamable to Grey Panda — strengthening both tools in the ecosystem.

Other adapters (Phase 3): Semgrep (cross-language SAST), OSV-Scanner (deps), Gitleaks/Trufflehog (secrets), Invariant **mcp-scan** / **mcp-watch** (MCP runtime), OpenSSF Scorecard (posture), Checkov/Trivy (IaC/containers).

---

## 9. The knowledge pack (the crown jewels)

Separately-versioned data the engine loads; independently updatable as OWASP/ATLAS/AIVSS evolve.

All knowledge-pack files are **JSON** (the zero-dep core reads `json`; YAML is an optional authoring convenience only). Shipped inside the package (`maroon/knowledge/`) as package data, read via `importlib.resources`.
```
maroon/knowledge/
  frameworks.json           # control-id catalog (LLM/ASI/DSGAI/MAESTRO/AIVSS/NHI/T-codes/MCP/CWE)
  crosswalk.json            # §3.6 tuple per control id (fields optional/nullable except the core set)
  cve_fingerprints.json     # known-exploit DB (Findings §3.4/3.5 CVE tables)
  detectors/components.json # component fingerprint -> category/MAESTRO layer/trust tier/AT signals
  rules/{llm,asi,dsgai,mcp,general}/*.json   # JSON rule objects (+ optional .py taint plugins)
  scoring/aivss.json        # AIVSS v0.8 factors + pinned AARS defaults
  scoring/llm_prices.json   # per-provider price table for orchestrator cost caps
  maturity/at_x_l.json      # AT-tier classifier + L-maturity classifier + posture matrix
  compliance/*.json         # GDPR/HIPAA/CCPA/EU AI Act/ISO 42001/DORA/NIS2 maps
  vocab/greypanda.json      # Grey Panda control-id -> ME canonical id + consumed schema
```

Rule schema + the **12 highest-value seed rules** are unchanged from the prior revision (dangerous-sink taint; unsafe deserialization; Lethal-Trifecta; vector tenant-filter; MCP client-config risks; secrets-in-prompt; token/cost caps; over-broad tools/no-HITL; unpinned model refs; observability-without-redaction; unsafe NL→SQL; snapshot path-traversal). Where Grey Panda already covers a rule, ME's adapter *reuses* it and ME's own rule focuses on the architecture/dataflow dimension Grey Panda doesn't do.

---

## 10. Tech stack (zero-dependency core — the grey-panda ethos)

**Design rule: the core installs with `pip install maroon-elephant` and pulls in _zero_ runtime dependencies** (Python **standard library only**, like grey-panda). Everything heavier is an **optional extra** so the base installs cleanly everywhere and air-gapped. This is a strength (supply-chain surface, install friction) not a compromise.

- **Engine: Python 3.9+** — matches grey-panda and the install base (broad compatibility; the dev machine runs 3.9). 3.9-safe code: `from __future__ import annotations`, no `match`, no `tomllib`.
- **Parsing (core, stdlib):** Python `ast` for Python source + a regex/line engine for configs/IaC/secrets/Dockerfiles (same approach grey-panda proves works). Deterministic, zero-dep.
- **Parsing (optional extra `[polyglot]`):** `tree-sitter` grammars for JS/TS, Go, Java — loaded only if the extra is installed; the base degrades to Python+config coverage without it.
- **Knowledge pack: JSON** (stdlib `json`) so the core stays zero-dep; a YAML authoring convenience is accepted only if `PyYAML` is present. Crosswalk, CVE DB, AT×L matrix, rules — all JSON.
- **Graph:** hand-rolled adjacency model in stdlib; **Mermaid**/DOT text export (no `networkx` dependency).
- **Rules:** declarative **JSON** rule objects + a Python plugin escape hatch for complex taint rules.
- **Output:** SARIF 2.1.0 and CycloneDX AI/ML-BOM emitted as **hand-built JSON** (both are JSON schemas — no `cyclonedx-python-lib`); HTML/Markdown report via stdlib string templating; PDF is an optional extra.
- **UI (`maroon serve`, Enterprise):** stdlib **`http.server`** backend + a small JSON API + **Server-Sent Events** for live progress (no `FastAPI`/WebSocket dep); frontend is **vanilla JS + CSS**, no node build step, served as static files → works air-gapped, zero-dep. (A richer SPA is an optional future build.)
- **Orchestrator (Enterprise):** ME's own small, auditable agent loop with hard step/time/cost caps and MCP tool-calling; **no agent-framework lock-in**; must be inventory-able by ME itself.
- **Browser automation (Live Agent mode):** a driven browser session for enumeration/onboarding, behind the `[browser]` extra; credential entry stays user-driven.
- **LLM (optional, BYOK, `[llm]` extra):** provider-agnostic HTTP client (Anthropic/OpenAI/Google/Azure/**Ollama/LM Studio**); `temperature=0`, seed pinned, prompts snapshotted. Off by default; core is fully functional with zero LLM.
- **GitHub (Enterprise):** App via JWT (RS256) + installation tokens; SARIF/Checks REST clients over stdlib `urllib`; the Action lives in its own path. `cryptography`/`PyJWT` ride in the `[github]` extra.
- **Dev tooling:** `venv` + `pip`; `pytest` for tests (dev-only, not a runtime dep); `ruff` optional for lint.

**Optional extras summary:** `[polyglot]` (tree-sitter), `[llm]` (BYOK providers), `[github]` (App/JWT), `[browser]` (live-agent), `[pdf]` (report export), `[all]`. Core = stdlib only.

---

## 11. Output formats & the three deliverables

Every scan produces all three (Findings §10):
1. **Vulnerability findings** → SARIF 2.1.0 (GitHub/Azure code scanning; VS Code), exit codes, diff-aware baseline.
2. **Design-time threat model** → component graph → MAESTRO → OWASP taxonomies → AIVSS → **TM-as-code YAML** (diffable in PRs) + diagram + governance report.
3. **AI inventory / AI-BOM** → CycloneDX AI/ML-BOM (+ optional SPDX), extending `gp agbom`; the "what AI are we even running" answer.

---

## 12. Security & trust model (BYOK / local-first)

For a tool scanning crown-jewel repos, trust *is* the product.

- **Local-first:** ingest, detect, graph, deterministic analysis, and report generation run entirely on the user's machine. **No source code leaves the machine by default.**
- **BYOK / BYOT:** optional LLM enrichment and the orchestrator agents use the user's **own** API key, **never transmitted to any Maroon Elephant server** (there isn't one in self-hosted mode) and **never written to logs/telemetry**. Key storage is honest about the zero-dep core: the default is a **local file with `0600` permissions** (restricted, *not* encrypted — stated plainly in the UI); **encrypted-at-rest storage and OS-keychain integration are available via the `[llm]`/`[secure]` extra** (`cryptography`/`keyring`). Only **best-effort redacted** snippets are sent, only to the provider the user chose, only when enrichment is on — and redaction is explicitly **best-effort, not a guarantee** (a zero-dep redactor is regex/entropy-based, the same class of control ME flags as weak under LLM02; stronger NER/classifier redaction rides the `[llm]` extra). The reliable guarantee is the *default*: enrichment off ⇒ **zero external calls**, and air-gapped/Ollama ⇒ zero calls even when on.
- **Air-gapped mode:** select a local model (Ollama/LM Studio) or disable the LLM entirely → zero external calls; full deterministic functionality.
- **The "What is BYOT?" guide** (shipped in-product): plain-language explainer — *what a token/API key is, why BYOK keeps your code and data under your control, how to get a key for each provider, rough cost per scan, and how to set a spend cap* — written for people who've never heard the term.
- **GitHub secrets:** App private key in KMS; 1h tokens; webhook HMAC verification; source not retained past a scan.
- **Dogfooding:** ME runs its own scanner on itself in CI and publishes the AT×L result — the ultimate trust signal.

---

## 13. Roadmap

Two tracks share the engine; Core ships first, Enterprise builds on it.

### Phase 0 — Foundations (weeks 1–3)
Repo scaffold, Apache-2.0, governance/security/DCO; `maroon` CLI skeleton (`scan`/`report`/`rules`); knowledge-pack schema + crosswalk + CVE DB seeded from Findings; `ingest` (git/local/**zip upload**) + `pypdf`; **`subscan` adapter for Grey Panda** (MCP + CLI + import); **benchmark suite** of deliberately-vulnerable AI repos (precision/recall harness).

### Phase 1 — Core MVP "detect + rank" (weeks 4–9) → `v0.1`
`detect` fingerprint library → inventory/AI-BOM; deterministic engine (**Python `ast` + config/regex core, zero-dep**; tree-sitter polyglot deferred to the `[polyglot]` extra) with the 12 seed rules + Grey Panda findings normalized in; Lethal-Trifecta heuristic; AIVSS severity; SARIF + terminal report (the **5-minute wow**); `pipx`/Docker; **GitHub Action** + diff-aware `--baseline`; docs site. *Success: `maroon scan <repo>` → ranked, evidence-backed, OWASP-mapped report in <10s (ME-native core; opt-in sub-scanners add their own time) with low FPs.*

### Phase 2 — "model + govern" (weeks 10–18) → `v0.3`
`graph` architecture inference + MAESTRO layers + Mermaid; full LLM01–10/ASI01–10/MCP + priority DSGAI rules; **AT×L governance report** + compliance crosswalk; **TM-as-code** YAML; VS Code extension; optional evidence-gated LLM enrichment (BYOK, Ollama for air-gap).

### Phase 3 — Enterprise edition (weeks 19–30) → `v0.6`
**Local-host UI** (`maroon serve`): inputs (URL/upload/live-agent), crown-jewels box, live scan board, four dashboards, exports. **Multi-agent orchestrator** with P0→P1→P2 queue + least-agency caps + verifier agent. **BYOK** setup + "What is BYOT?" guide. **Live Browser-Agent mode.** More `subscan` adapters (Semgrep, OSV, Gitleaks, mcp-scan).

### Phase 4 — GitHub-native + ecosystem (weeks 31–40) → `v1.0`
**GitHub App** (org enumeration, installation-token clone, **SARIF upload + Checks annotations**, webhooks); publish the **Action** + **App** to Marketplace; **ME's own MCP server** (`serve-mcp`); consume `github-mcp-server`; SPDX/dependency-submission; policy-as-code + exception workflow; full DSGAI incl. governance checklist; air-gapped bundle; **submit to OWASP as an Incubator project**; alignment badges.

### Phase 5 — sustaining
Knowledge-pack cadence tracking OWASP/ATLAS/AIVSS; community rules; language expansion; optional open-core hosted control-plane (only if it doesn't starve the OSS core).

---

## 14. Enterprise requirements checklist

- [x] **SARIF 2.1.0** → GitHub/Azure (Phase 1) · [x] **Checks API** gating without a Code Security license (Phase 4)
- [x] **CI/CD-native**, diff-aware, fail-on-new (Phase 1) · [x] **GitHub App** org scanning (Phase 4)
- [x] **CycloneDX AI/ML-BOM + inventory explorer** (Phase 1–3)
- [x] **Crown-jewels P0 prioritization** (Phase 3) · [x] **Multi-agent orchestrator** (Phase 3)
- [x] **Local-host UI**, upload + URL + GitHub + live-agent inputs (Phase 3)
- [x] **BYOK multi-provider + air-gapped** (Phase 2–3) · [x] **"What is BYOT?" guide** (Phase 3)
- [x] **AT×L governance verdict** + compliance crosswalk (Phase 2)
- [x] **Grey Panda / sub-scanner integration** (Phase 0 onward)
- [x] **Policy-as-code + exception workflow** (Phase 4) · [x] **Low-FP discipline** via benchmarks (Phase 0+)
- [ ] **SSO/RBAC** — only for an optional hosted control-plane (Phase 5; not a v1 blocker)

---

## 15. Community & governance strategy (the "award-winning" path)

- **License:** Apache-2.0 (matches Grey Panda; OSI/OWASP-eligible; avoids AGPL adoption chill).
- **Attribution:** OWASP docs are CC BY-SA 4.0 → credit in the knowledge pack; do not reuse `ai-threat-model-assistant` code (no license). Grey Panda is the user's own (Apache-2.0) — co-market the two as an ecosystem.
- **OWASP project path:** Incubator → Lab → Flagship; OSI license, ≥2 leaders, DCO, open governance from Phase 0.
- **Adoption flywheel:** 5-min wow → Action + VS Code + pre-commit → the UI demo (crown-jewels live scan) → MCP server → community rulepack. Publish a verifiable benchmark.
- **Trust signals:** self-hosted/air-gapped, BYOK local-first, transparent security policy, ME scanning itself, alignment badges (OWASP GenAI/MITRE ATLAS/NIST AI RMF), honest "what we can't detect from code."

---

## 16. Success metrics

- **Precision ≥ 0.9 / recall ≥ 0.8** on the benchmark suite at default effort.
- **Cold scan of a medium repo < 15s**; **org scan** streams P0 results first.
- **Time-to-first-value < 5 min** (install → first report; or `maroon serve` → first live board).
- Coverage: 100% LLM01–10 + ASI01–10 + MCP minimum-bar; ≥80% DSGAI by v1.0.
- Ecosystem: Action + App on Marketplace; VS Code ext; ME MCP server; Grey Panda integrated; OWASP Incubator submitted.
- Community: contribution-ready rule format; ≥10 external rule contributions by 6 months post-v0.1.

---

## 17. Immediate next actions (first PR-sized chunks)

1. `git init`, Apache-2.0, scaffold (`maroon/`, `knowledge/`, `benchmarks/`, `docs/`), CI; add ME-scans-itself CI job.
2. Encode **crosswalk + CVE fingerprint DB + AT×L matrix** as YAML from Findings (pure data, high value, low risk) — plus `vocab/greypanda.yaml` mapping to Grey Panda control IDs.
3. CLI skeleton + SARIF emitter + `ingest` (incl. zip upload).
4. **Grey Panda `subscan` adapter** (spawn `gp mcp`, call `greypanda_scan_path` JSON; CLI SARIF fallback) — fastest path to real, citeable findings on day one.
5. `detect` fingerprint library (LangChain/LangGraph/CrewAI/MCP/vector DBs/model SDKs) → AI-BOM (extend `gp agbom`).
6. First 3 ME-native seed rules end-to-end (dangerous-sink taint, unsafe deserialization, Lethal-Trifecta) + benchmark fixtures.
7. `maroon scan` prints a ranked report merging ME-native + Grey Panda findings → tag `v0.1.0-alpha`.

> Build order: **deterministic core + Grey Panda adapter + knowledge pack first** (real findings fast), then architecture inference, then the enterprise UI/orchestrator, then GitHub-native. The LLM and the browser agent are garnishes on a deterministic meal. Everything traces to [Findings.md](Findings.md).

---

## 18. Engineering spec addendum (testable requirements, test strategy, DoD)

### 18.1 Functional requirements (numbered, testable)
- **FR-1 Ingest.** `maroon scan <path|url|zip>` acquires the target (local dir, git URL shallow-clone, or uploaded zip), respecting `.gitignore` and skipping vendored dirs. *Check:* scanning a fixture dir, a public git URL, and a zip all yield a populated file set.
- **FR-2 Component detection / AI-BOM.** Detect AI/agentic/MCP/data components (frameworks, model SDKs, vector DBs, MCP wiring) and emit a CycloneDX AI/ML-BOM. *Check:* a fixture using LangChain + Chroma + an MCP server is inventoried with all three + correct MAESTRO layers.
- **FR-3 Deterministic rules.** Run ME-native rules; every finding has `rule_id`, `file`, `line`, evidence span, severity, and the full crosswalk tuple. *Check:* each seed rule fires on its positive fixture and is silent on its negative fixture.
- **FR-4 Grey Panda adapter.** If `gp` is importable/on PATH, ingest its JSON findings (MCP or CLI) and merge/dedupe into ME findings; if absent, ME-native rules still run and the run succeeds. *Check:* run with and without grey-panda installed; both succeed, the former adds grey-panda-sourced findings.
- **FR-5 Lethal-Trifecta heuristic.** Flag any agent/component holding untrusted-input + sensitive-data + external-comms simultaneously. *Check:* trifecta fixture flags; each 2-of-3 fixture does not.
- **FR-6 Architecture + threat model.** Build a component/dataflow graph, assign MAESTRO layers + trust tiers, and emit threat-model-as-code YAML/JSON + a Mermaid diagram. *Check:* fixture graph has expected nodes/edges and layer tags.
- **FR-7 Severity + governance.** Score findings via AIVSS v0.8 tables; place the repo on the AT0–AT8 × L0–L4 matrix with a "raise maturity / reduce tier" recommendation. *Check:* a known fixture lands in the expected cell.
- **FR-8 Outputs.** Emit SARIF 2.1.0 (schema-valid, with `partialFingerprints`, `category`), CycloneDX AI/ML-BOM (schema-valid), TM-as-code, and an HTML/MD report. *Check:* SARIF validates against the 2.1.0 schema; CycloneDX validates.
- **FR-9 CLI UX + CI.** Ranked human report in the terminal; exit codes + `--fail-on`; diff-aware `--baseline`. *Check:* exit code reflects `--fail-on`; baseline suppresses pre-existing findings.
- **FR-10 MCP server.** `maroon serve-mcp` exposes scan/report as MCP tools (stdio JSON-RPC). *Check:* an MCP handshake + `tools/list` + a scan tool call round-trips.
- **FR-11 Enterprise UI.** `maroon serve` opens a local dashboard: inputs (URL/upload/connect), crown-jewels box, live SSE scan board, and four result views (Findings, AI Inventory, Threat Model, Governance). *Check:* a scan driven from the UI streams progress and renders all four views.
- **FR-12 Orchestrator + crown jewels.** Multi-repo scan ranks targets P0/P1/P2 from a crown-jewels description and scans worst-first, under hard agency caps. *Check:* given 3 repos + a crown-jewels string, P0 is scanned first and caps are enforced.
- **FR-13 BYOK + local-first.** LLM enrichment is off by default; when on, keys are read from a local `0600` file (or the `[secure]`/`[llm]` extra's encrypted store/keychain) and **never written to logs/telemetry**; **best-effort redaction runs** before any LLM call; air-gapped/Ollama mode makes zero external calls. *Check:* enrichment off → zero network; on with a fake provider → redaction runs on the payload and the key is never present in any log/telemetry output (the reliable guarantee is "redaction runs + key never logged + air-gapped = zero calls," not "secrets guaranteed stripped").
- **FR-14 GitHub integration.** GitHub App client mints installation tokens, enumerates org repos, clones, uploads SARIF, and posts Checks annotations; webhook handler verifies `X-Hub-Signature-256`. The GitHub Action emits+uploads SARIF. *Check:* signature verification unit test; SARIF-upload request shape matches the API (mocked); Action workflow lints.

### 18.2 Test strategy
- **Unit:** every rule has a positive + negative fixture; detectors, graph, scoring, SARIF/CycloneDX emitters, SSE server, signature verification, redaction.
- **Integration:** end-to-end `scan` on a bundled **vulnerable sample app** → assert finding set, AI-BOM, SARIF validity, governance cell.
- **Adversarial / attack-tests (Phase 5):** regression tests for every hardening fix so it can't come back; redaction bypass attempts; SARIF-injection/oversize; path-traversal on zip upload.
- **Dogfood:** `maroon scan .` runs in CI on ME itself; the self-scan must be clean (no unsuppressed High/Critical) and publishes ME's AT×L tier.
- **"Self-checks clean"** = `pytest` green + `maroon scan .` clean + README commands reproduce.

### 18.3 Honest limits (written before building)
- Static analysis only — ME never executes target code; no runtime/behavioral findings.
- Architecture inference yields a *component + dataflow graph*, not a guaranteed-complete DFD; LLM narration is enrichment, never the source of a finding.
- Core deep-analysis is **Python-first**; other languages get config/secret/dependency coverage in core and fuller coverage via `[polyglot]`.
- Governance (AT×L, DSGAI lifecycle) is partly **presence/absence** — some controls can't be proven from code and are reported as "needs attestation," not pass.
- GitHub **App registration & hosting**, SARIF-on-private-repos licensing, package publishing, and the live Browser-Agent against real orgs require the user's accounts/auth → handoff, not done autonomously.
- Grey Panda, Semgrep, etc. are optional; coverage is reduced (not broken) without them.

### 18.4 Definition of Done (Phase 3 exit)
1. FR-1…FR-14 implemented and each FR's acceptance check passes.
2. `pytest` green; `maroon scan .` self-scan clean; both wired into CI.
3. SARIF + CycloneDX outputs validate against their schemas; a bundled vulnerable sample produces the expected findings end-to-end.
4. Core installs with **zero runtime dependencies**; extras install independently; air-gapped mode makes zero external calls.
5. README quick-start commands reproduce exactly; `finding`/Findings + `build-plan`/Build Plan, `BUILD_LOG.md`, `HANDOFF.md` present.
6. Spec reviewed (≤3 cycles) and adversarially hardened (≥3 rounds); site + deck live-verified.

> Note on filenames: the user's chosen `Findings.md` + `Build Plan.md` are the canonical research + spec docs (they satisfy the builder's `finding.md`/`build-plan.md` roles); they are kept, not renamed.

---

## 19. Determinism & integration contracts (spec-review cycle 1 revisions)

These pin the determinism-defining functions and resolve the contradictions an independent reviewer flagged. They are normative — the build implements exactly these.

### 19.1 Finding identity: two keys (B1/BL-1 — drives cross-source dedup, `--baseline`, SARIF `partialFingerprints`)
Both keys are **line-number-independent** and **host-FS-independent**, and computed the same way for every finding class (Python, config, IaC, Dockerfile, secret, and Grey Panda findings alike) — purely lexical, **no AST required**.

```
normalized_path = repo-relative POSIX path, case PRESERVED (never lowercased)   # host-independent

evidence_digest:
  if the finding has a line:
     span_text = exact text of file lines [line-2 .. line+2], re-extracted FROM THE FILE
                 (NOT from any tool-provided snippet — so every source hashes identical input)
     evidence_digest = sha256( normalize(span_text) )
  else (no line: dependency/CVE/config-key findings):
     evidence_digest = sha256( normalize(evidence_token) )   # e.g. "pkg@1.2.3" or "mcpServers.foo.command"

normalize(t) = per line: strip leading/trailing whitespace, collapse internal whitespace runs to one
               space; drop blank lines; join with "\n". (Lexical only — no comment-strip, no AST.)

# Cross-source correlation key — rule_id EXCLUDED, so ME-native and Grey Panda findings on the
# same span collide and MERGE:
correlation_key = sha256( normalized_path + "\x00" + evidence_digest )   # first 32 hex chars (128-bit)

# Per-alert fingerprint — computed AFTER merge from the merged finding's canonical rule_id, so
# distinct rules on the same line stay distinct alerts, and the id is stable across commits:
fingerprint = sha256( canonical_rule_id + "\x00" + normalized_path + "\x00" + evidence_digest )[:32 hex]
  canonical_rule_id = the ME-native rule_id if the merged finding has one, else the Grey Panda rule_id
```
- **Dedup/merge (used by §19.3):** group all findings by `correlation_key`; each group becomes one finding with merged `sources[]`. rule_id is **not** in this key, so cross-source merge actually fires.
- **Per-alert identity:** `fingerprint` is emitted in SARIF as `partialFingerprints.maroonElephant/v1`; absolute line numbers live only in `locations[]`.
- **Baseline:** `--baseline old.sarif` suppresses any finding whose `fingerprint` is in the baseline set.
- **Acceptance (strengthens FR-3/FR-4/FR-9):** reformatting a fixture (reindent, blank lines, move the block within ±2 lines of unchanged context) MUST NOT change `correlation_key`/`fingerprint`; an ME-native and a Grey Panda finding on the same line MUST share a `correlation_key` and merge; editing the matched code or changing the canonical rule MUST change the `fingerprint`.

### 19.2 AT×L governance classifier (B2 — the enterprise differentiator, made deterministic)
Two **versioned knowledge-pack classifiers** (`knowledge/maturity/at_x_l.json`), not just the matrix cells:
- **AT-tier classifier (composition → AT0–AT8):** ordered rules over the detected-component inventory. E.g. *no AI components* → AT0/AT1 baseline; *single agent + tools* → AT3/AT4; *code-execution tool present* → ≥AT4; *external MCP/third-party servers* → ≥AT6; *multi-agent orchestration* → AT7; *cross-org/federated agents* → AT8. The repo's tier = the **highest** triggered rule (worst-case). Each rule names the exact detector signal(s) that fire it.
- **L-maturity classifier (control presence/absence → L0–L4):** a checklist of detectable controls (HITL gates, kill-switch, pinned deps, redaction middleware, audit logging, policy-as-code, per-agent identity, SBOM/AIBOM present, …). Each control is `present | absent | needs-attestation`. L-level = highest level whose **required control set** is fully `present`; `needs-attestation` never counts as present. **Levels are cumulative** — each level's required set includes all lower levels' controls — so the classifier is monotonic. Thresholds are listed explicitly per level in `at_x_l.json`.
- **Verdict** = matrix cell (AT-tier × L-level) → label (Well-governed … DO NOT DEPLOY) + the single highest-leverage "raise maturity or reduce tier" action.
- **AIVSS determinism caveat:** AIVSS v0.8 severity is computed from code-derivable factors (sink reachability, privilege, external-comms, data sensitivity) **plus documented defaults** for AARS/agentic factors that are not code-derivable (autonomy level, oversight). Defaults are pinned in `knowledge/scoring/aivss.json`; the score is deterministic *given* those defaults, and the report states which factors were derived vs defaulted.
- **Not to be conflated:** Grey Panda `gp verify` **AISVS L1/2/3** is a *verification-depth* axis and is reported separately from the governance **L0–L4** maturity axis.
- **Acceptance (strengthens FR-7):** three pinned fixtures (a benign CLI, a single-agent RAG app, a multi-agent MCP system) land in explicitly expected cells.

### 19.3 Grey Panda adapter contract (B3 — pinned)
- **Version floor:** `grey-panda >= 1.0.6` (MCP launch-ready); tested against **1.0.7**; **MCP protocol `2025-06-18`** (negotiate down to `2025-03-26`/`2024-11-05`). Detected via `gp --version`; skew below floor ⇒ adapter disables itself with a logged warning, native-only run proceeds.
- **Consumed schema** (`greypanda_scan_path` with `format="json"`): `findings[]` where each finding = `{rule_id, owasp_id, severity, title, description, remediation, file, line, snippet, sdk}`. The adapter maps this into ME's finding model and recomputes ME's own fingerprint (§19.1) from `file`+`snippet`.
- **Invocation order:** (1) in-process import `greypanda.scanner.engine` if importable; else (2) `gp mcp` stdio JSON-RPC; else (3) CLI `gp scan --format json`. First available wins. SARIF is taken only from CLI (`--format sarif`) when ME needs grey-panda's native SARIF; otherwise ME emits its own.
- **Dedup precedence:** on equal **`correlation_key`** (§19.1, rule_id-free; Grey Panda's `evidence_digest` is recomputed from the file at `line`, not from GP's `snippet`, so inputs are identical), the findings merge into one; **ME-native rule metadata is authoritative for the crosswalk tuple** and provides the `canonical_rule_id`, Grey Panda is recorded as a corroborating entry in `sources[]` and contributes its `owasp_id` into the tuple's union. Neither is dropped.
- **Tag reconciliation:** `knowledge/vocab/greypanda.json` maps Grey Panda control ids → ME canonical ids. On disagreement, take the **union** and tag each id with its source; never silently overwrite.
- **Failure path (new acceptance, strengthens FR-4):** `gp` present-but-broken — subprocess timeout (default **60s**, configurable), non-zero exit, malformed/empty JSON, or protocol error — is caught; the adapter logs and the run completes **native-only and successfully**. Tested with a stub `gp` that hangs and one that emits garbage.
- **Timing:** sub-scanners (incl. Grey Panda) are **opt-in and run alongside** the native core; their time is **reported separately** and is **not** counted in the §16 "<15s cold scan" target, which measures the ME-native core only. `--no-subscanners` runs native-only for the fast path.

### 19.4 DoD ↔ roadmap reconciliation (B4i)
The **Phase 3 Definition of Done covers FR-1…FR-13 fully, plus the *unit-testable* pieces of FR-14** (webhook signature verification, installation-token/JWT minting, SARIF-upload and Checks request **shapes** verified against mocked endpoints, and the Action workflow linting). **Live GitHub App registration, hosting the webhook endpoint, SARIF-on-private-repo licensing, and a real org scan are Phase 4 + handoff items** (they need the user's accounts/auth) and are explicitly **out of the Phase 3 DoD**. §18.4 item 1 is read as "FR-1…FR-13 implemented+passing; FR-14 implemented with mocked acceptance; live external auth deferred to handoff."

### 19.5 Folded-in non-blocking pins
- **Enrichment citation gate (the "no hallucinated threats" mechanism):** an LLM enrichment is **rejected** unless every `file:line` it cites is already in the backing deterministic finding's `evidence[]` set. Enrichment can only *describe* a deterministic finding; it can never add a location or a finding.
- **Component→MAESTRO-layer & →trust-tier maps:** shipped as `knowledge/detectors/components.json` (each fingerprint → `maestro_layer`, default `trust_tier`). Assignment is table-driven and deterministic.
- **Schema validation = dev-only:** SARIF 2.1.0 and CycloneDX schemas are bundled under `tests/schemas/`; `jsonschema` is a **dev/test dependency only** — the runtime core stays zero-dep.
- **CycloneDX AI-BOM mapping:** documented field map from `gp agbom` / ME detectors → CycloneDX `components[]` (`type: machine-learning-model | data | library`), `properties[]` for MAESTRO layer + control ids. Emitted as hand-built JSON validated in tests.
- **Orchestrator caps (defaults, pinned):** `max_steps=40`, `max_recursion=5`, `wall_clock=1800s/run`, `cost_ceiling=$5/run` (overridable). Cost accounting uses a per-provider price table (`knowledge/scoring/llm_prices.json`; Ollama/local = $0). The run log is **hash-chained** (each entry carries `sha256(prev_hash + entry)`) = "tamper-evident."
- **Benchmark credibility:** the vulnerable-fixture label set is **pre-registered** in `benchmarks/LABELS.json` before rules are tuned; recall denominator = the pre-registered positive set; precision/recall reported per framework. Teaching-to-the-test is mitigated by a held-out fixture subset not used during rule authoring.
- **Crosswalk tuple optionality:** all tuple fields except `rule_id`, `file`, `line`, `severity`, and ≥1 primary OWASP id are **optional/nullable**; a missing ATLAS/NHI/regulatory tag is valid, not an error.
- **Browser-agent (`[browser]`):** confirmed low-value/high-brittleness given the GitHub App path; it is the **first cut candidate** if any schedule pressure appears, and ships behind the extra with a clear "demo/onboarding only" label.
