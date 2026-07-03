# MCP-Tripwire — Roadmap

> **One-liner:** *"Can this agent keep trusting this tool during execution — and can I prove it?"*
> **Now:** hardening the shipped surface (CI depth, test coverage, detection breadth) and moving toward a first real deployment.
> **Direction:** from a sharp, well-tested primitive to a production-grade trust gateway teams actually run in front of their MCP servers.

## Shipped

Everything below is on `main`, implemented and covered by tests. The precise, file-by-file map lives in the [feature catalog](features/README.md).

| Area | What | Where |
|---|---|---|
| Core | detection · engine · attestation · OWASP map · corpus runner · CLI | `src/tripwire/*.py` |
| Signing | alg-dispatching attestation; HMAC default + Ed25519 backend behind `[signing]`; `key gen` / `key pub` / `verify --pub` | `src/tripwire/signing/`, `src/tripwire/attestation.py` |
| Proxy bridge | stdio **and** HTTP/SSE transports; `tools/list` rewrite · `tools/call` drift quarantine (JSON-RPC `-32001`) · structured stderr log | `src/tripwire/proxy.py` ([RFC-0001](rfc/RFC-0001-e2-stdio-proxy-bridge.md), [RFC-0004](rfc/RFC-0004-http-sse-proxy-transport.md)) |
| SARIF output | `scan`/`ci --sarif` + HTTP content-negotiation → GitHub Code Scanning / GitLab SAST | `src/tripwire/sarif.py` ([RFC-0003](rfc/RFC-0003-sarif-output.md)) |
| Multi-agent | Scanner / Red-team / Attestor + coordinator over the same deterministic engine | `src/tripwire/agents/`, `app/agent.py` |
| Proof moments | five demos: engine A/B, stdio proxy, ADK pipeline, HTTP/SSE proxy, **real Playwright MCP** | `examples/demo*.py`, `make demo*` |
| HTTP gateway | `/scan` `/verify` `/eval` `/healthz`; local Docker verified | `app/fast_api_app.py`, [`docs/runbooks/deploy.md`](runbooks/deploy.md) |
| Harness | hard rules machine-enforced; pre-commit no-commit-to-main; feature-catalog + root-clean guardrails | [AGENTS.md](../AGENTS.md), `scripts/harness_guardrails.py` |

Measured on `main`: **75 default tests pass / 46 optional-extra skips**, **139 pass with `[agent]` + `[signing]`**, **9/9 attacks blocked · 0 false positives on 4 clean tools** (`make eval`), deterministic core stdlib-only.

The **v0.2 — Credibility & integration** milestone (SARIF · Ed25519 · HTTP/SSE) is complete; design history is in the four accepted RFCs under [`docs/rfc/`](rfc/).

---

## Now — hardening

Making the shipped surface trustworthy to *run*, not just to demo. Tracked as GitHub issues:

| Theme | Issue | Why it matters |
|---|---|---|
| CI runs the full suite | [#60](https://github.com/akoita/mcp-tripwire/issues/60) | CI installs only `[dev]`, so the tests protecting Ed25519 / SSE / HTTP-gateway / ADK never run in CI — a regression there ships green. Highest-value gap. |
| Coverage reporting | [#66](https://github.com/akoita/mcp-tripwire/issues/66) | Make coverage visible so gaps are caught, not guessed. |
| Detection depth | [#61](https://github.com/akoita/mcp-tripwire/issues/61), [#62](https://github.com/akoita/mcp-tripwire/issues/62), [#65](https://github.com/akoita/mcp-tripwire/issues/65) | Per-rule positive/negative matrix; proxy error-path tests; extend homoglyph detection from names to descriptions. |
| Corpus breadth | [#64](https://github.com/akoita/mcp-tripwire/issues/64) | Grow the attack corpus to 50+ data-driven cases so the headline number means more. |
| Eval flywheel | [#63](https://github.com/akoita/mcp-tripwire/issues/63) | Wire the LLM-judge `explanation_quality` metric into the eval harness. |
| Honest docs | [#59](https://github.com/akoita/mcp-tripwire/issues/59) | Refresh `TECH_DEBT.md` — shipped features are still listed as stubs. |
| Release flow | [#67](https://github.com/akoita/mcp-tripwire/issues/67) | Changelog + tag automation and stale-branch pruning for a maintainable release cadence. |

---

## Next — v0.3 Scale & multi-upstream

One proxy fronting N MCP servers + a central tool registry + per-tool policy-as-code (YAML rules an operator edits without touching Python) + observability beyond stderr (Cloud Logging / a queryable audit store). Turns the single-host gateway into a fleet gateway. Credible only because v0.2 made the badges independently verifiable and the findings SARIF-portable.

## Then — v1.0 First real user

Published package, a hosted Docker image, a one-page "plug me in" guide, a production-bug issue label, and a feedback cadence. Find one team running real MCP servers and put Tripwire in front of their pipeline. Real usage — not internal planning — drives the v1.x backlog from there.

## Deliberately out of scope (until real pull)

- Sigstore / Rekor anchoring — interesting, premature without users asking.
- Multi-framework support beyond MCP (LangChain, Cursor, raw tools) — would dilute the wedge.
- Hosted dashboard / Tripwire-as-a-SaaS — the wrong shape; Tripwire is plumbing other people host.

---

## How this project is built

- Every commit on a feature branch; every PR closes or refs an issue.
- Structural decisions get an [ADR](adr/); non-trivial designs get an [RFC](rfc/) reviewed before code.
- `make check` must be green before any PR; the `no-commit-to-main` hook enforces the branch flow.
- **Hard Rule #6 — never invent metrics.** Every quoted number traces to a `make` command run.
- Full ruleset: [AGENTS.md](../AGENTS.md). Methodology: [AGENTIC_SDLC.md](AGENTIC_SDLC.md).
