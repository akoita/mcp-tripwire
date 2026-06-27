# STATUS

_Working memory. Update at the end of each session._

**Now:** Scaffold complete; deterministic spine green (18 tests pass · 8/8 corpus attacks blocked · demo proof-moment runs).

## Done
- E1 Core — `detection` (fingerprint + injection/poisoning + invisible/homoglyph), `engine` (trust loop: allow/block/quarantine/require-approval), `attestation` (HMAC signed badge, tamper-evident), `owasp` (MCP Top-10 map), `corpus` runner, `cli` (scan/verify/ci).
- Harness — `AGENTS.md` SSOT + `CLAUDE.md`/`GEMINI.md` symlinks; `.agents/skills` (+ `.claude`/`.gemini` adapters); `scripts/harness_guardrails.py`; `make check`; CI; docs taxonomy.
- Demo — A/B canary proof + rug-pull quarantine + tamper-evident badge.

## Next (see ROADMAP.md)
- E2: wire the real stdio subprocess bridge in `proxy.py` (guard logic already tested).
- E3 (P1): flesh out ADK Scanner/Red-team/Attestor agents.
- tests/eval datasets → `agents-cli eval` integration; OWASP mapping surfaced in CLI.
- Cloud Run deploy via `app/` + `agents-cli-manifest.yaml`.
- Video + ≤2,500-word writeup.

## Open
- Signing scheme: HMAC now → Ed25519 (P1).
- Deploy: confirm GCP project/billing or fall back to documented local run.
- GitHub repo name/visibility before publishing.
