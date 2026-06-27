# The Agentic SDLC (how we build MCP-Tripwire)

This project is built as a **software factory**, per the course's Day-1 "Factory Model":
the primary output is *the system that produces the code* — the harness — not just the code.
`Agent = Model + Harness.`

## The harness mapped to the SDLC
| Phase | Harness activity | Where |
|---|---|---|
| Requirements / design | **Configure** the harness — rules, tools, evals | `AGENTS.md`, `SPEC.md`, `docs/adr/` |
| Implementation | **Run** the harness — agents + tools in a sandbox | `src/`, `.agents/skills/` |
| Test & QA | **Feedback loop** — failures route back | `tests/`, `tests/eval/`, `make check` |
| Review / deploy / maintain | **Observe** the harness — hooks + traces | `.github/`, `app/app_utils/telemetry.py` |

## Static vs dynamic context (a first-class decision)
- **Static** (always loaded): `AGENTS.md` (+ `CLAUDE.md`/`GEMINI.md` symlinks).
- **Dynamic** (loaded on task match): `.agents/skills/*` via progressive disclosure.
Keep `AGENTS.md` lean — it's paid every interaction.

## Two-layer verification (the contract)
1. **Deterministic tests** (`pytest`) — signing, fingerprinting, drift, decisions.
2. **Non-deterministic evals** (`tests/eval/`) — corpus + LLM-judge for explanation quality.
*Without both, it's just vibe coding.* Tests/evals are written **before** the code (Hard Rule #5).

## The Quality Flywheel
evaluate against the corpus → cluster failures → tighten rules/prompts → re-run regression →
monitor in production. New attacks become new corpus cases (`corpus/attacks.jsonl`).

## The loop
`plan → branch → write test/eval → implement → make check → PR → AI review → human review → merge`

## Guardrails as code, not prose
Every machine-checkable hard rule is enforced by `scripts/harness_guardrails.py` and re-run in
pre-commit + CI. When the agent errs, we fix the **harness** (add a rule/ADR/guardrail), not just the symptom.
