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

## Phase 5 — Adversarial hardening
### Round 1 (fresh devil's-hat reviewer, empirical)
Verdict going in: strong (determinism/zero-dep/robustness/zip-guards all reproduced), but real bugs found. Fixes + attack-tests:
- 🔴 **--baseline suppressed NEW duplicate vulns** (fingerprint collision: identical blocks at different lines shared a fingerprint → merge collapsed them + baseline hid new ones). FIX: occurrence disambiguator in correlation_key/fingerprint (`assign_occurrences`). Tests: identical-blocks-not-merged, baseline-doesn't-suppress-new-duplicate.
- 🔴 **"self-scan clean" was dishonest** (CI native-only; .maroonignore excluded core engine files). FIX: CI self-scan is explicitly `--no-subscanners` with a precise claim; un-excluded analyzer/taint/detect — now scanned, with only the genuine pattern-definition lines inline-suppressed; grey-panda findings now honor `.maroonignore`.
- 🟡 **git-clone arg injection + SSRF** → scheme allowlist, reject `-`-leading, `--` separator, `protocol.ext.allow=never`, block cloud-metadata/link-local hosts. Tests: 5 reject + 2 allow.
- 🟡 **UI CSRF / DNS-rebinding / DoS** → per-process CSRF token, Host allowlist, JSON content-type required, body-size cap, bounded runs, non-loopback warning. Test: UI rejects missing-token/bad-host/bad-content-type.
- 🟡 **Taint bypasses** (for/with/comprehension targets) → now carried. Test covers all three.
- 🟡 **Zip-bomb** (no decompression cap) → total-size + ratio + member-count caps before extract. Test with a compressible bomb.
- 🟡 **Inline-suppression over-suppressed** (matched inside strings) → directive must be in a real comment. Tests: in-string-not-honored, real-comment-honored.
- ⚪ Claims reconciled: **implemented the optional BYOK LLM enrichment layer** (evidence/citation-gated, off by default, Ollama = air-gapped) so the "LLM can only describe a finding" claim holds; removed the unbuilt `[browser]` extra from README, added a `[subscanners]` extra; governance now reads positive control signals (vault/pydantic/OPA) so the AT×L maturity axis isn't permanently flat; line-length cap for ReDoS safety; grey-panda path clamped to scan root.
- Result: **54 tests green** (16 new attack-tests), native self-scan clean, vuln fixture fires all 14 rules.
