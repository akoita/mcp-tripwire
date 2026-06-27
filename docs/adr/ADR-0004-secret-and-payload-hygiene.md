# ADR-0004: Secret & payload hygiene

- **Status:** accepted
- **Date:** 2026-06-27

## Context
A security tool that leaks secrets or logs sensitive payloads is self-defeating. Demos that
touch real credentials are reckless and undermine the message.

## Decision
- Secrets only via env vars; `.env` is git-ignored; `detect-private-key` runs in pre-commit.
- Never log raw tool payloads; deployments force `OTEL_..._CAPTURE_MESSAGE_CONTENT=NO_CONTENT`.
- Demos use a clearly-labelled **canary** secret + a local fake sink — never real `~/.ssh`/env.

## Consequences
- Hard Rules #3 and #4, enforced by `scripts/harness_guardrails.py` (and CI).
- Observability captures structure/traces, not content — slightly less rich, far safer.
