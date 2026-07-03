# Changelog

All notable changes to this project. Format: [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]
### Fixed
- ADK agents no longer hard-code `gemini-3-pro` (a model id absent from the AI Studio `v1beta` endpoint — every live playground turn failed with `404 NOT_FOUND`). The model is single-sourced in `tripwire.agents.agent_model()`: default `gemini-3-pro-preview`, overridable via `TRIPWIRE_AGENT_MODEL`.

### Changed
- **Breaking:** OWASP taxonomy remapped from the early community numbering (`MCP-01` … `MCP-10`) to the official OWASP MCP Top 10 (2025) ids (`MCP01:2025` … `MCP10:2025`) across findings, SARIF metadata, eval datasets, and docs. The synthetic corpus rule `MCP04-DRIFT` is now `DRIFT-RUGPULL`. Old→new remap + coverage matrix: `docs/OWASP_MCP_COVERAGE.md`.

### Added
- Deterministic core: schema fingerprinting, injection/poisoning detection (incl. invisible-char & homoglyph), policy engine (allow/block/quarantine/require-approval), HMAC-signed tamper-evident attestations, OWASP MCP Top-10 mapping.
- `tripwire` CLI: `scan`, `verify`, `ci` (attack corpus → N/M attacks blocked).
- A/B proof-moment demo (canary secret, local fake sink) + rug-pull quarantine.
- Agent harness: `AGENTS.md` SSOT with `CLAUDE.md`/`GEMINI.md` symlinks, `.agents/skills/`, `harness_guardrails.py`, `make check`, CI, docs/ADR taxonomy.
- Transparent stdio MCP proxy (guard logic; `serve()` stubbed — E2).
- ADK multi-agent skeletons: Scanner · Red-team · Attestor (P1 — E3).
