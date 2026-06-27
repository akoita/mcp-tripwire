# Changelog

All notable changes to this project. Format: [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]
### Added
- Deterministic core: schema fingerprinting, injection/poisoning detection (incl. invisible-char & homoglyph), policy engine (allow/block/quarantine/require-approval), HMAC-signed tamper-evident attestations, OWASP MCP Top-10 mapping.
- `tripwire` CLI: `scan`, `verify`, `ci` (attack corpus → N/M attacks blocked).
- A/B proof-moment demo (canary secret, local fake sink) + rug-pull quarantine.
- Agent harness: `AGENTS.md` SSOT with `CLAUDE.md`/`GEMINI.md` symlinks, `.agents/skills/`, `harness_guardrails.py`, `make check`, CI, docs/ADR taxonomy.
- Transparent stdio MCP proxy (guard logic; `serve()` stubbed — E2).
- ADK multi-agent skeletons: Scanner · Red-team · Attestor (P1 — E3).
