# Docs index

Knowledge context for humans and agents (the "Knowledge" row of the context map in [AGENTS.md](../AGENTS.md)).

- **[AGENTIC_SDLC.md](AGENTIC_SDLC.md)** — how we build: the Factory Model, the loop, the quality flywheel.
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — components, the trust loop, data flow.
- **[TRUST_MODEL.md](TRUST_MODEL.md)** — what you can verify vs must assume; threat model and non-goals.
- **[OWASP_MCP_COVERAGE.md](OWASP_MCP_COVERAGE.md)** — coverage matrix against the official OWASP MCP Top 10 (2025) + old→new id remap.
- **adr/** — Architecture Decision Records (one per structural decision).
  - [ADR-0001](adr/ADR-0001-mcp-trust-gateway.md) — MCP trust gateway, not a scanner
  - [ADR-0003](adr/ADR-0003-signed-attestations.md) — signed, tamper-evident attestations (the wedge)
  - [ADR-0004](adr/ADR-0004-secret-and-payload-hygiene.md) — secret & payload hygiene
  - [ADR-0005](adr/ADR-0005-two-layer-verification.md) — two-layer verification (tests + evals)
- **rfc/** — design proposals; all four (stdio proxy, Ed25519, SARIF, HTTP/SSE) are accepted and implemented.
- **[features/](features/)** — **the precise reference** for what Tripwire delivers, per capability. One page per feature; index at [features/README.md](features/README.md). The catalog is the precise reference; the project root README is the pitch.
- **plans/** — per-epic delivery plans (from `_TEMPLATE.md`).
- **runbooks/** — operational guides, one per job:
  - [deploy.md](runbooks/deploy.md) — local Docker · Cloud Run · hosted SSE gateway · Agent Runtime; env vars & secrets.
  - [real-world-agent-demo.md](runbooks/real-world-agent-demo.md) — Tripwire fronting real Playwright MCP; candidate real MCPs.
  - [adk-live-playground-demo.md](runbooks/adk-live-playground-demo.md) — live Gemini-driven ADK session, scripted acts.
  - [demo-proof-moment.md](runbooks/demo-proof-moment.md) — the 3-minute in-person demo checklist.
  - [sarif-in-gh-actions.md](runbooks/sarif-in-gh-actions.md) — landing findings in GitHub Code Scanning.
  - [pr-watchdog.md](runbooks/pr-watchdog.md) — local CI daemon when Actions is unavailable.

State lives alongside this index: [STATUS.md](STATUS.md), [ROADMAP.md](ROADMAP.md), [BACKLOG.md](BACKLOG.md), [TECH_DEBT.md](TECH_DEBT.md), [SPEC.md](SPEC.md), [SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md). Only the working-memory docs and tooling-required files (README, LICENSE, AGENTS.md, etc.) live at the repo root — see the `check_root_clean()` allowlist in [`scripts/harness_guardrails.py`](../scripts/harness_guardrails.py).
