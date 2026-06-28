# STATUS

_Working memory. Update at the end of each session._

**Now (v0.2 substantively complete):** SARIF (#32) + Ed25519 (#31) + HTTP/SSE proxy (#33) all landed on main. v0.2.0 tag is reachable pending the operator-path proof (manual Code Scanning screenshot per `docs/runbooks/sarif-in-gh-actions.md`).

_Older milestones:_ Day 3 — CLI polish (#6) + drift eval (#7); 32 tests at that tag. `make eval` still reports `9/9 attacks blocked · 0 false-positives on 4 clean tools`.

## Done
- E1 Core — `detection` (fingerprint + injection/poisoning + invisible/homoglyph), `engine` (trust loop: allow/block/quarantine/require-approval), `attestation` (alg-dispatching: HMAC default, Ed25519 via `[signing]` extra), `signing/` subpackage (HmacBackend + Ed25519Backend + env-driven resolvers + VerifyRegistry), `owasp` (MCP Top-10 map), `corpus` runner, `cli` (scan/verify [+ --pub] / ci / key gen / key pub).
- E2 Proxy — transparent stdio MCP bridge: two-task asyncio pump, `tools/list` filter + badge attach, live-tools cache, `tools/call` drift short-circuit (JSON-RPC error `-32001` with tripwire metadata), structured stderr log lines, end-to-end integration test against a subprocess fixture. Re-list now detects rug-pull on already-approved tools.
- Harness — `AGENTS.md` SSOT + `CLAUDE.md`/`GEMINI.md` symlinks; `.agents/skills` (+ `.claude`/`.gemini` adapters); `scripts/harness_guardrails.py`; `make check`; CI; docs taxonomy. Pre-commit active locally.
- Demo — A/B canary proof + rug-pull quarantine + tamper-evident badge.

## Next (see ROADMAP.md and SPRINT-2026-06-27-to-2026-07-05.md)
- Day-2 leftover: wire `make demo` through the proxy bridge (#5).
- E3 (P1): flesh out ADK Scanner/Red-team/Attestor agents (#8) — timebox 8h.
- Cloud Run deploy via `app/` + `agents-cli-manifest.yaml` (#9) — timebox.
- README final pass + architecture image (#10), video (#11), writeup (#12), submission dry run (#13).

## Open
- Deploy: confirm GCP project/billing or fall back to documented local run.
- GitHub Actions billing blocked on private repo — CI workflows present but dormant; local `make check` + pre-commit are the active quality gate.

## Resolved
- Signing scheme: HMAC now → Ed25519 — landed in [#31](https://github.com/akoita/mcp-tripwire/issues/31) per RFC-0002; HMAC remains the zero-deps default, Ed25519 ships behind `[signing]`.
- SARIF 2.1.0 output — landed in [#32](https://github.com/akoita/mcp-tripwire/issues/32) per RFC-0003 (`tripwire scan/ci --sarif`).
- RFC-0004 (HTTP/SSE proxy) — accepted 2026-06-28; implementation landed in [#33](https://github.com/akoita/mcp-tripwire/issues/33) (PR #46 slots 1-6 + follow-up slots 7-8: SseTripwireProxy, /mcp/sse mount, demo, end-to-end script test).
- GitHub repo: published private at `akoita/mcp-tripwire` (2026-06-27).
