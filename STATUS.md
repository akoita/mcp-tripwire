# STATUS

_Working memory. Update at the end of each session._

**Now:** E2 stdio bridge landed (RFC-0001). 19 tests pass (1 new integration), 8/8 corpus attacks blocked, demo proof-moment runs.

## Done
- E1 Core — `detection` (fingerprint + injection/poisoning + invisible/homoglyph), `engine` (trust loop: allow/block/quarantine/require-approval), `attestation` (HMAC signed badge, tamper-evident), `owasp` (MCP Top-10 map), `corpus` runner, `cli` (scan/verify/ci).
- E2 Proxy — transparent stdio MCP bridge: two-task asyncio pump, `tools/list` filter + badge attach, live-tools cache, `tools/call` drift short-circuit (JSON-RPC error `-32001` with tripwire metadata), structured stderr log lines, end-to-end integration test against a subprocess fixture. Re-list now detects rug-pull on already-approved tools.
- Harness — `AGENTS.md` SSOT + `CLAUDE.md`/`GEMINI.md` symlinks; `.agents/skills` (+ `.claude`/`.gemini` adapters); `scripts/harness_guardrails.py`; `make check`; CI; docs taxonomy. Pre-commit active locally.
- Demo — A/B canary proof + rug-pull quarantine + tamper-evident badge.

## Next (see ROADMAP.md and SPRINT-2026-06-27-to-2026-07-05.md)
- Day 3 CLI polish: surface OWASP mapping in `scan`/`verify`/`ci` output.
- Eval polish: preserve 8/8 corpus, add drift eval if cheap.
- E3 (P1): flesh out ADK Scanner/Red-team/Attestor agents — timebox 8h.
- Cloud Run deploy via `app/` + `agents-cli-manifest.yaml` — timebox.
- Video + ≤2,500-word writeup.

## Open
- Signing scheme: HMAC now → Ed25519 (P1).
- Deploy: confirm GCP project/billing or fall back to documented local run.
- GitHub Actions billing blocked on private repo — CI workflows present but dormant; local `make check` + pre-commit are the active quality gate.

## Resolved
- GitHub repo: published private at `akoita/mcp-tripwire` (2026-06-27).
