# Docs index

Knowledge context for humans and agents (the "Knowledge" row of the context map in [AGENTS.md](../AGENTS.md)).

- **[AGENTIC_SDLC.md](AGENTIC_SDLC.md)** — how we build: the Factory Model, the loop, the quality flywheel.
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — components, the trust loop, data flow.
- **adr/** — Architecture Decision Records (one per structural decision).
  - [ADR-0001](adr/ADR-0001-mcp-trust-gateway.md) — MCP trust gateway, not a scanner
  - [ADR-0003](adr/ADR-0003-signed-attestations.md) — signed, tamper-evident attestations (the wedge)
  - [ADR-0004](adr/ADR-0004-secret-and-payload-hygiene.md) — secret & payload hygiene
  - [ADR-0005](adr/ADR-0005-two-layer-verification.md) — two-layer verification (tests + evals)
- **rfc/** — proposals under discussion.
- **[features/](features/)** — **the precise reference** for what Tripwire delivers, per capability. One page per feature; index at [features/README.md](features/README.md). The catalog is the precise reference; the project root README is the pitch.
- **plans/** — per-epic delivery plans (from `_TEMPLATE.md`).
- **runbooks/** — operational guides ([demo proof-moment](runbooks/demo-proof-moment.md)).

State lives alongside this index: [STATUS.md](STATUS.md), [ROADMAP.md](ROADMAP.md), [BACKLOG.md](BACKLOG.md), [TECH_DEBT.md](TECH_DEBT.md), [SPEC.md](SPEC.md), [SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md). Only the working-memory docs and tooling-required files (README, LICENSE, AGENTS.md, etc.) live at the repo root — see the `check_root_clean()` allowlist in [`scripts/harness_guardrails.py`](../scripts/harness_guardrails.py).
