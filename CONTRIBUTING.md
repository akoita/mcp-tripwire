# Contributing

Read [AGENTS.md](AGENTS.md) first — it is the single source of truth for humans and agents alike.

## The loop
`plan → branch → write test/eval → implement → make check → PR → AI review (/code-review) → human review → merge`

- **Plan:** copy `docs/plans/_TEMPLATE.md` → `docs/plans/<epic>.md`; track `Status:` slices.
- **Branch:** `feat/<id>-<kebab>` (never commit to `main`). Commits: `feat(#id): …`.
- **Test first:** tests/evals are the contract (Hard Rule #5).
- **Gate:** `make check` (lint + test + guardrails) must be green before a PR.
- **AI commits** carry a `Co-Authored-By:` trailer.

## Setup
```bash
uv sync --extra dev
pre-commit install
make check
```

## Design rules that won't move
- The deterministic core (`src/tripwire/`, excluding `agents/`) stays **stdlib-only**.
- All trust flows through signed attestations (`attestation.py`).
- Findings map to the OWASP MCP Top 10 (`owasp.py`).
- Structural decisions get an ADR in `docs/adr/`.
