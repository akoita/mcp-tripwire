# MCP-Tripwire — AI Agent Coding Standards

> Single source of truth for every coding agent (Claude Code · OpenAI Codex · Gemini/Antigravity).
> `CLAUDE.md` and `GEMINI.md` are **symlinks** to this file — edit only `AGENTS.md`.
> This file is paid on every interaction. Keep it lean; push detail into `docs/` and `.agents/skills/`.

## Mission
A lightweight OSS **trust gateway for MCP tools**: continuous schema-integrity enforcement
plus portable, cryptographically signed attestations. We answer the question others don't:
*"Can this agent keep trusting this tool during execution — and can we prove it?"*
Product spec → [docs/SPEC.md](docs/SPEC.md). Plan → [docs/ROADMAP.md](docs/ROADMAP.md). Methodology → [docs/AGENTIC_SDLC.md](docs/AGENTIC_SDLC.md).

## Stack
- **Language:** Python ≥3.12, managed by **`uv`** (never pip/poetry directly).
- **Deterministic core:** standard library only — no third-party imports under `src/tripwire/` (except the optional `agents/` package).
- **Agent layer (P1):** Google **ADK** (`google-adk`), behind the `[agent]` extra.
- **Protocol:** MCP / JSON-RPC 2.0 over stdio + SSE/HTTP, spec `2025-11-25`.
- **Quality:** `ruff` (lint+format) · `pytest` · deterministic `scripts/harness_guardrails.py`.
- **Deploy (P1):** Cloud Run via `agents-cli`; observability via OpenTelemetry → Cloud Trace.

## Hard rules (never violate — each maps to an ADR)
1. **Never trust an unsigned/unverified manifest.** All trust flows through `attestation.py`. → [ADR-0003](docs/adr/ADR-0003-signed-attestations.md)
2. **The deterministic core stays dependency-free.** No third-party imports in `src/tripwire/` except `agents/`. → [ADR-0001](docs/adr/ADR-0001-mcp-trust-gateway.md)
3. **No secrets/keys/credentials in code, prompts, or logs.** Env vars only; `.env` git-ignored; never log raw tool payloads. → [ADR-0004](docs/adr/ADR-0004-secret-and-payload-hygiene.md)
4. **Demos use a clearly-labelled CANARY secret + local fake sink.** Never touch real `~/.ssh`, env, or credentials. Say "canary secret" out loud.
5. **Tests/evals are the contract — write them before the code.** Both layers required: deterministic `pytest` + non-deterministic evals. → [ADR-0005](docs/adr/ADR-0005-two-layer-verification.md)
6. **Never report invented metrics.** `tripwire ci` reports real `N/M attacks blocked` from the actual corpus.
7. **Never commit to `main`.** Branch `feat/<id>-<kebab>` (or `chore/`, `docs/`, `fix/`); commits `<type>(#id): …`; AI commits carry a `Co-Authored-By` trailer. Enforced locally by the `no-commit-to-main` pre-commit hook (private repos can't use GitHub branch protection without Pro).
8. **`make check` must be green before any PR.** Single pre-PR gate = lint + test + guardrails.
9. **Partial work self-flags.** Mark stubs with `# STUB(Exx):` and `"stub": True` so nothing ships silently incomplete.

## Workflow (the loop)
`plan → branch → write test/eval → implement → make check → PR → AI review (/code-review) → human review → merge`

- Plans live in `docs/plans/` (from `_TEMPLATE.md`), one per epic, with explicit `Status:` slices.
- **Configure** the harness (rules, tools, evals) *before* running it; **observe** it (hooks, traces) *after*.

## Context map (six context types — keep static vs dynamic explicit)
| Type | Where it lives |
|---|---|
| Instructions | this `AGENTS.md` (always loaded) |
| Knowledge | `docs/` (ADRs, RFCs, architecture, runbooks) |
| Memory | `docs/STATUS.md`, `docs/ROADMAP.md`, `docs/BACKLOG.md`, `docs/TECH_DEBT.md` |
| Examples | `examples/`, `tests/eval/datasets/` |
| Tools | MCP server (`src/tripwire/proxy.py`, `cli.py`), `.agents/skills/` |
| Guardrails | `scripts/harness_guardrails.py`, `.claude/settings.json`, `security` policy |

## Conventions
- Core modules: `src/tripwire/{detection,engine,attestation,owasp,corpus,proxy,cli}.py`; optional ADK agents in `src/tripwire/agents/`.
- Skills: `.agents/skills/<snake_case>/SKILL.md` (name field = kebab-case gerund). `.claude/skills` + `.gemini/commands` adapt the same files.
- Docstrings + type hints on all public functions. Comments explain *why*, not *what*.
- Findings map to the **OWASP MCP Top 10** taxonomy (`src/tripwire/owasp.py`).
- **Repo root stays uncluttered.** Working memory (`STATUS.md`, `ROADMAP.md`, `BACKLOG.md`, `TECH_DEBT.md`, `SPEC.md`, `SUBMISSION_CHECKLIST.md`) lives under `docs/`. Only files with a tooling/ecosystem reason live at the root — the explicit allowlist is `ROOT_FILE_ALLOWLIST` in [`scripts/harness_guardrails.py`](scripts/harness_guardrails.py), enforced by `make check`. Adding a new root file means appending to the allowlist with a one-line justification (or finding the right subdir for it).
- **Feature catalog.** Every user-visible capability has a per-feature page under [`docs/features/`](docs/features/) indexed by [`docs/features/README.md`](docs/features/README.md). The catalog is the **precise reference** ("what specifically does Tripwire deliver to the agent / operator?"); the project root README is the **pitch**. Behaviour changes that affect any consumer of Tripwire must update the relevant feature page in the same PR. Index ↔ page consistency is verified by `check_features_catalog_consistent()` in `scripts/harness_guardrails.py` — orphan pages and dead links fail `make check`.

## When the agent makes a mistake
Fix the **harness**, not just the symptom: add a rule here (and an ADR if structural), or encode
the rule as a deterministic check in `scripts/harness_guardrails.py` so it can never recur silently.
