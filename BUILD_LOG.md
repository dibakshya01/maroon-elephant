# Build Log — Maroon Elephant

Running log of the autonomous build. Newest first.

## Phase 2 — Spec review (ExpertSpecReviewer)
- Cycle 1: **REVISE** — 5 blocking (B1 fingerprint, B2 AT×L classifier, B3 grey-panda contract, B4 DoD/UI contradictions, B5 key-storage/redaction vs zero-dep). All fixed → added §19 contracts, fixed §6/§10/§12.
- Cycle 2: **REVISE** — 4/5 resolved; 1 blocking (BL-1: rule_id-in-fingerprint blocked cross-source merge; digest not computable off the AST path). Fixed → split `correlation_key` (rule_id-free) vs `fingerprint` (post-merge), purely-lexical digest re-extracted from file, host-FS-independent path. Plus non-blocking cleanups.
- Cycle 3: **APPROVE** — no blocking issues. Two stale-wording cleanups applied (§19.3 consumed-schema, §17 JSON).

## Phase 3 — Build (in progress)
- M0 Foundation: repo scaffold, Apache-2.0 + NOTICE, pyproject (zero-dep core + extras), governance docs, README, `docs/CAN_AND_CANNOT.md`. Committed `1b4634c`.
- M0 Knowledge pack (JSON, inside package): frameworks, crosswalk, cve_fingerprints, scoring/aivss, scoring/llm_prices, maturity/at_x_l (classifiers), detectors/components, vocab/greypanda. Committed `1b4634c`.
- M1 Core identity (`model.py`): Finding model + §19.1 `correlation_key`/`fingerprint`/lexical `evidence_digest` + cross-source `merge_findings`. **Verified**: stable under reindent & distant line-shift; changes on code change; native+grey-panda merge to one finding. 
- M1 Knowledge loader (`kb.py`): importlib.resources JSON loader + crosswalk tuple helpers. Verified.
- M1 Ingest (`ingest.py`): local/git/zip acquisition; zip extraction refuses traversal + symlinks (dogfood).
- M1 Detect (`detect.py`): table-driven component detection → inventory/AI-BOM + AT-signal set.
- M2 MCP server (`maroon serve-mcp`): stdio JSON-RPC 2025-06-18, 4 tools; smoke-tested round-trip.
- M3 Enterprise edition: deterministic orchestrator (crown-jewels P0/P1/P2, hard agency caps,
  hash-chained tamper-evident run log), local-host UI (`maroon serve`, stdlib http.server + SSE,
  vanilla JS, maroon dark theme). Visually verified in-browser: live board + Findings/Inventory/
  Threat-Model/Governance tabs render; crown-jewels prioritization works; governance verdict shown.
- 30 tests green; self-scan clean.
