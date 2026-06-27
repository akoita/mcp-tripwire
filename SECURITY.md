# Security Policy

MCP-Tripwire is a security tool; we hold our own code to the bar it enforces.

## Reporting a vulnerability
Please report privately via a GitHub Security Advisory (preferred) rather than a public issue.
We aim to acknowledge within 72 hours.

## AI-generated-code review checklist (Day-4 guidance)
Every change — especially AI-authored — is reviewed for:
- **Hallucinated dependencies / slopsquatting** — imports must resolve to real, pinned packages. The deterministic core takes **zero** runtime deps (enforced by `scripts/harness_guardrails.py`).
- **Silent stubs** — partial work must self-flag (`# STUB(Exx):`, `"stub": True`); unflagged stubs fail guardrails.
- **Secret leakage** — no keys/credentials in code, prompts, or logs; `.env` is git-ignored; `detect-private-key` runs in pre-commit.
- **Raw payload logging** — never log tool inputs/outputs; deployments set `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=NO_CONTENT`.

## Demo safety
Demonstrations use a clearly-labelled **canary** secret and a local in-memory sink only. No real
credential material (`~/.ssh`, env, tokens) is ever read or transmitted. This is a hard rule
(`AGENTS.md` #4) and is checked by the guardrails.

## Threat model
See [docs/runbooks/demo-proof-moment.md](docs/runbooks/demo-proof-moment.md) and the OWASP MCP
Top-10 mapping in `src/tripwire/owasp.py`.
