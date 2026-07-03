# STATUS

_Working memory. Update at the end of each session._

**Now (post-submission, building for real use):** the v0.2 Credibility & integration milestone — SARIF (#32) + Ed25519 (#31) + HTTP/SSE proxy (#33) — is fully landed on public `main`, and local validation is green. Focus has shifted from the competition submission (archived under [`docs/archive/`](archive/)) to production hardening: CI depth, test coverage, detection breadth, and a first real deployment. `make eval` reports `9/9 attacks blocked · 0 false-positives on 4 clean tools`.

## Done
- E1 Core — `detection` (fingerprint + injection/poisoning + invisible/homoglyph), `engine` (trust loop: allow/block/quarantine/require-approval), `attestation` (alg-dispatching: HMAC default, Ed25519 via `[signing]` extra), `signing/` subpackage (HmacBackend + Ed25519Backend + env-driven resolvers + VerifyRegistry), `owasp` (MCP Top-10 map), `corpus` runner, `cli` (scan/verify [+ --pub] / ci / key gen / key pub).
- E2 Proxy — transparent stdio MCP bridge: two-task asyncio pump, `tools/list` filter + badge attach, live-tools cache, `tools/call` drift short-circuit (JSON-RPC error `-32001` with tripwire metadata), structured stderr log lines, end-to-end integration test against a subprocess fixture. Re-list now detects rug-pull on already-approved tools.
- Harness — `AGENTS.md` SSOT + `CLAUDE.md`/`GEMINI.md` symlinks; `.agents/skills` (+ `.claude`/`.gemini` adapters); `scripts/harness_guardrails.py`; `make check`; CI; docs taxonomy. Pre-commit active locally.
- Demo — A/B canary proof + rug-pull quarantine + tamper-evident badge.

## Next (hardening — see [ROADMAP.md](ROADMAP.md))
- Make CI run the full extras-gated suite — Ed25519 / SSE / HTTP-gateway / ADK tests currently never run in CI (#60).
- Add coverage reporting to CI (#66).
- Deepen detection tests: per-rule matrix (#61), proxy error paths (#62), homoglyph on descriptions (#65).
- Grow the attack corpus to 50+ data-driven cases (#64).
- Wire the LLM-judge `explanation_quality` eval metric (#63).
- Refresh stale `TECH_DEBT.md` — shipped features still listed as stubs (#59).
- Release automation: changelog + tag flow, stale-branch pruning (#67).

## Open
- Cloud Run remains optional/staged; local Docker and local demos are the current operator proof.
- GitHub Actions runs are green on `main`, but only cover `[dev]` — extras-gated tests skip in CI until #60 lands. Local `make check` (with extras) + `make eval` remain the fullest gate.

## Resolved
- Signing scheme: HMAC now → Ed25519 — landed in [#31](https://github.com/akoita/mcp-tripwire/issues/31) per RFC-0002; HMAC remains the zero-deps default, Ed25519 ships behind `[signing]`.
- SARIF 2.1.0 output — landed in [#32](https://github.com/akoita/mcp-tripwire/issues/32) per RFC-0003 (`tripwire scan/ci --sarif`).
- RFC-0004 (HTTP/SSE proxy) — accepted 2026-06-28; implementation landed in [#33](https://github.com/akoita/mcp-tripwire/issues/33) (PR #46 slots 1-6 + follow-up slots 7-8: SseTripwireProxy, /mcp/sse mount, demo, end-to-end script test).
- GitHub repo: public at `akoita/mcp-tripwire` for judging (confirmed 2026-06-30).
