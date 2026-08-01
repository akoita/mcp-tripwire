# Changelog

All notable changes to this project. Format: [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]
### Added
- Real-world attack suite — `corpus/real_world/attacks.jsonl` reproduces 9 attacks drawn from **published security research** (Invariant Labs tool-poisoning + WhatsApp rug-pull notifications, the MCPTox benchmark `arXiv:2508.14925`, Snyk's malicious `postmark-mcp` npm writeup), each case carrying a checkable `source` citation. `make audit` (`scripts/real_world_audit.py`) runs them through the real engine and reports **4 blocked · 1 advisory · 3 missed · 1 out-of-scope**, with **2 of the 4 blocks coming from drift, not scanning**; `tests/security/test_real_world_attacks.py` pins those outcomes as a contract, including the false negatives. Unlike `make eval` (a pass/fail regression gate on this project's own curated corpus) the audit is a report — it always exits 0 and the misses are published, not hidden. Headline case `rw-09`: `scan_tool()` returns zero findings on the mutated descriptor, yet `evaluate_call()` returns `QUARANTINE`. Docs: `docs/features/real-world-attack-suite.md`.
- `tripwire proxy -- <server-cmd> [args...]` CLI command — the drop-in wiring to guard a real MCP server. Point any MCP client's `mcpServers` config at it (`command: "tripwire", args: ["proxy", "--", "npx", ...]`) and every `tools/list` is vetted and every `tools/call` re-fingerprinted before it reaches the upstream. Wraps the already-tested `StdioTripwireProxy.serve()`; resolves its signing backend from the standard env vars. Docs: `docs/features/stdio-mcp-proxy.md#use-it-with-your-own-agent`.

### Fixed
- ADK agents no longer hard-code `gemini-3-pro` (a model id absent from the AI Studio `v1beta` endpoint — every live playground turn failed with `404 NOT_FOUND`). The model is single-sourced in `tripwire.agents.agent_model()`, overridable via `TRIPWIRE_AGENT_MODEL`. The default is the rolling alias `gemini-pro-latest`: the first pinned replacement (`gemini-3-pro-preview`) was retired upstream immediately after, proving pinned previews 404 the same way.

### Changed
- **Breaking:** OWASP taxonomy remapped from the early community numbering (`MCP-01` … `MCP-10`) to the official OWASP MCP Top 10 (2025) ids (`MCP01:2025` … `MCP10:2025`) across findings, SARIF metadata, eval datasets, and docs. The synthetic corpus rule `MCP04-DRIFT` is now `DRIFT-RUGPULL`. Old→new remap + coverage matrix: `docs/OWASP_MCP_COVERAGE.md`.

### Added
- Deterministic core: schema fingerprinting, injection/poisoning detection (incl. invisible-char & homoglyph), policy engine (allow/block/quarantine/require-approval), HMAC-signed tamper-evident attestations, OWASP MCP Top-10 mapping.
- `tripwire` CLI: `scan`, `verify`, `ci` (attack corpus → N/M attacks blocked).
- A/B proof-moment demo (canary secret, local fake sink) + rug-pull quarantine.
- Agent harness: `AGENTS.md` SSOT with `CLAUDE.md`/`GEMINI.md` symlinks, `.agents/skills/`, `harness_guardrails.py`, `make check`, CI, docs/ADR taxonomy.
- Transparent stdio MCP proxy (guard logic; `serve()` stubbed — E2).
- ADK multi-agent skeletons: Scanner · Red-team · Attestor (P1 — E3).
