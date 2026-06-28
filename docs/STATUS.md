# STATUS

_Working memory. Update at the end of each session._

**Now:** Day 3 done — CLI polish (#6) + drift eval (#7) landed. 32 tests pass. `make eval` reports `9/9 attacks blocked · 0 false-positives on 4 clean tools` (the +1 is a rug-pull case caught by `evaluate_call`, not approval).

## Done
- E1 Core — `detection` (fingerprint + injection/poisoning + invisible/homoglyph), `engine` (trust loop: allow/block/quarantine/require-approval), `attestation` (HMAC signed badge, tamper-evident), `owasp` (MCP Top-10 map), `corpus` runner, `cli` (scan/verify/ci).
- E2 Proxy — transparent stdio MCP bridge: two-task asyncio pump, `tools/list` filter + badge attach, live-tools cache, `tools/call` drift short-circuit (JSON-RPC error `-32001` with tripwire metadata), structured stderr log lines, end-to-end integration test against a subprocess fixture. Re-list now detects rug-pull on already-approved tools.
- Harness — `AGENTS.md` SSOT + `CLAUDE.md`/`GEMINI.md` symlinks; `.agents/skills` (+ `.claude`/`.gemini` adapters); `scripts/harness_guardrails.py`; `make check`; CI; docs taxonomy. Pre-commit active locally.
- Demo — A/B canary proof + rug-pull quarantine + tamper-evident badge.

## Next (see ROADMAP.md and SPRINT-2026-06-27-to-2026-07-05.md)
- Day-2 leftover: wire `make demo` through the proxy bridge (#5).
- E3 (P1): flesh out ADK Scanner/Red-team/Attestor agents (#8) — timebox 8h.
- Cloud Run deploy via `app/` + `agents-cli-manifest.yaml` (#9) — timebox.
- README final pass + architecture image (#10), video (#11), writeup (#12), submission dry run (#13).

## Open
- Signing scheme: HMAC now → Ed25519 (P1).
- Deploy: confirm GCP project/billing or fall back to documented local run.
- GitHub Actions billing blocked on private repo — CI workflows present but dormant; local `make check` + pre-commit are the active quality gate.

## Resolved
- GitHub repo: published private at `akoita/mcp-tripwire` (2026-06-27).
