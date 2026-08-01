# STATUS

_Working memory. Update at the end of each session._

**Now (post-submission, building for real use):** the v0.2 Credibility & integration milestone — SARIF (#32) + Ed25519 (#31) + HTTP/SSE proxy (#33) — is fully landed on public `main`, and local validation is green. Focus has shifted from the competition submission (archived under [`docs/archive/`](archive/)) to production hardening: CI depth, test coverage, detection breadth, and a first real deployment.

The docs are being reframed around the claim hierarchy the new evidence supports: **Tier 1 — continuous tool-contract integrity plus signed attestation** is the product (a hash comparison and a signature check, deterministic, zero false positives by construction); **Tier 2 — descriptor scanning** is a bounded best-effort first pass with real false negatives, never a guarantee and never the headline. Two measurements, never conflated: the new `make audit` suite of 9 attacks reproduced from **published security research** reports `4 blocked · 1 advisory · 3 missed · 1 out-of-scope`, with **2 of the 4 blocks coming from drift, not scanning** — the independent efficacy signal; while `make eval` reports `40/40 attacks blocked · 0 false-positive(s) on 12 clean tool(s)` on our own curated corpus, which is a **regression gate**, not an efficacy claim.

## Done
- E1 Core — `detection` (fingerprint + injection/poisoning + invisible/homoglyph), `engine` (trust loop: allow/block/quarantine/require-approval), `attestation` (alg-dispatching: HMAC default, Ed25519 via `[signing]` extra), `signing/` subpackage (HmacBackend + Ed25519Backend + env-driven resolvers + VerifyRegistry), `owasp` (MCP Top-10 map), `corpus` runner, `cli` (scan/verify [+ --pub] / ci / key gen / key pub).
- E2 Proxy — transparent stdio MCP bridge: two-task asyncio pump, `tools/list` filter + badge attach, live-tools cache, `tools/call` drift short-circuit (JSON-RPC error `-32001` with tripwire metadata), structured stderr log lines, end-to-end integration test against a subprocess fixture. Re-list now detects rug-pull on already-approved tools.
- Harness — `AGENTS.md` SSOT + `CLAUDE.md`/`GEMINI.md` symlinks; `.agents/skills` (+ `.claude`/`.gemini` adapters); `scripts/harness_guardrails.py`; `make check`; CI; docs taxonomy. Pre-commit active locally.
- Demo — A/B canary proof + rug-pull quarantine + tamper-evident badge.

## Next (hardening — see [ROADMAP.md](ROADMAP.md))
- Wire the LLM-judge `explanation_quality` eval metric (#63).
- Lift `app/` coverage (deploy glue at ~68-70%) so the `fail_under` floor can be raised.
- Release automation: changelog + tag flow, stale-branch pruning (#67).

## Open
- Cloud Run remains optional/staged; local Docker and local demos are the current operator proof.
- The `fail_under` floor is 85 against a ~88% total — the headroom is `app/` deploy glue (`fast_api_app.py` 68%, `sse_adapter.py` 70%) plus `proxy.serve()` wiring. Raise the floor as those close.

## Resolved
- Real-world attack suite (published-research efficacy audit) — `corpus/real_world/attacks.jsonl` reproduces 9 attacks from public security research (Invariant Labs tool poisoning + WhatsApp rug-pull, MCPTox `arXiv:2508.14925`, Snyk's `postmark-mcp` supply-chain writeup), every case carrying its citation; `make audit` / `scripts/real_world_audit.py` prints the measured table and `tests/security/test_real_world_attacks.py` pins it as a contract. Result: `4 blocked · 1 advisory · 3 missed · 1 out-of-scope`, **2 of the 4 blocks from drift, not scanning**. Headline non-circular case `rw-09`: `scan_tool()` returns zero findings on the mutated descriptor (the scanner is provably blind) yet `evaluate_call()` returns `QUARANTINE`. `rw-04` is recorded `out_of_scope`, not missed — the real postmark-mcp compromise changed the server *implementation* while its published manifest stayed byte-identical. The 3 misses (`rw-02` shadowing, `rw-08` silent forwarding, `rw-07` keyword-avoiding exfil) are tracked in [#101](https://github.com/akoita/mcp-tripwire/issues/101) and are deliberately **not** to be fixed by pattern-matching those exact strings. Feature page: [features/real-world-attack-suite.md](features/real-world-attack-suite.md).
- Attack corpus expansion — landed per #64: `corpus/attacks.jsonl` now carries 52 data-driven cases (34 approval-time attacks, 6 drift attacks, 12 clean tools). The curated regression gate `make eval` reports `40/40 attacks blocked · 0 false-positive(s) on 12 clean tool(s)` — a no-regression signal on our own corpus, not an efficacy measurement (see the real-world audit above for that).
- Homoglyph detection on descriptions — landed per #65: SHADOW-HOMOGLYPH now scans descriptions via an intra-word (per-token) mixed-script heuristic, so an embedded `gеt`-style shadow fires while legitimate multilingual descriptions (each word single-script) stay clean. New unit tests + multilingual clean case + corpus `a9`; the curated regression gate `make eval` now reports `40/40 attacks blocked · 0 false-positive(s) on 12 clean tool(s)`. Implemented via Codex CLI under review.
- Coverage `fail_under` gate — landed per #87: `[tool.coverage.report] fail_under = 85` enforced on the CI `test-extras` leg and `make coverage` (a backslide fails the run); `make check`'s no-`--cov` fast path is unaffected. Regression floor, not a target — ~3pts below the ~88% total.
- Per-rule detection matrix — landed per #61: one triggering + one clean input for all 8 rule ids, plus a completeness assertion against a new `detection.RULE_IDS` registry so a rule can't be added or removed without a matrix entry. Non-behavioural refactor: named the two structural rule ids and enumerated the registry.
- Proxy error-path unit tests — landed per #62: in-memory (no-subprocess) tests for malformed frames, uncached/unnamed `tools/call`, upstream-closed / broken-pipe teardown, id-dispatch edges, cache invalidation, and `guard_*` edge cases. `proxy.py` 80% → 92%.
- Coverage reporting in CI — landed per #66: the `test-extras` leg runs `pytest --cov`, publishes a coverage table to the job summary, and uploads `coverage.xml`. Local mirror: `make coverage`. Advisory baseline ~87%.
- Full extras-gated suite in CI — landed per #60: the `test-extras` leg installs `[dev]+[agent]+[signing]` and fails if any test skips, so Ed25519 / SSE / HTTP-gateway / ADK tests actually execute in CI.
- `TECH_DEBT.md` refresh — landed per #59: shipped features (proxy, ADK agents, Ed25519) moved to a "Resolved" log; only genuine debt (rule-based injection #63, name-only homoglyph #65) remains listed.
- Signing scheme: HMAC now → Ed25519 — landed in [#31](https://github.com/akoita/mcp-tripwire/issues/31) per RFC-0002; HMAC remains the zero-deps default, Ed25519 ships behind `[signing]`.
- SARIF 2.1.0 output — landed in [#32](https://github.com/akoita/mcp-tripwire/issues/32) per RFC-0003 (`tripwire scan/ci --sarif`).
- RFC-0004 (HTTP/SSE proxy) — accepted 2026-06-28; implementation landed in [#33](https://github.com/akoita/mcp-tripwire/issues/33) (PR #46 slots 1-6 + follow-up slots 7-8: SseTripwireProxy, /mcp/sse mount, demo, end-to-end script test).
- GitHub repo: public at `akoita/mcp-tripwire` for judging (confirmed 2026-06-30).
