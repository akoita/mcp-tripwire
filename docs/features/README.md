# MCP-Tripwire — Feature catalog

> **Status:** live · maintained per PR · structure verified by `check_features_catalog_consistent()` in [`scripts/harness_guardrails.py`](../../scripts/harness_guardrails.py)
> **Owner:** Aboubakar Koita (akoita)

This is the **precise reference** for what MCP-Tripwire actually does for the agent / LLM / operator that uses it. One row per capability, one page per row. Distinct from:

- **[README.md](../../README.md)** at the project root — the pitch / hero / wedge / quickstart.
- **[docs/SPEC.md](../SPEC.md)** — product specification.
- **[docs/ROADMAP.md](../ROADMAP.md)** — what gets built when.
- **[docs/ARCHITECTURE.md](../ARCHITECTURE.md)** — internal component diagram.
- **[docs/adr/](../adr/) / [docs/rfc/](../rfc/)** — *why* a thing exists and *how* it was designed.

This catalog answers: ***given a tool descriptor or an MCP connection, what concrete value does Tripwire deliver, on which surface, with which guarantees?***

## Status legend

| Symbol | Meaning |
|---|---|
| ✅ implemented | Shipped on `main`, covered by tests, listed in the README implementation-status table as `✅`. |
| 🟢 staged | Code exists and is callable, but the operator-path acceptance gate (real-world consumer, deploy, etc.) hasn't been ticked. |
| 🟡 partial | Some sub-features land; others tracked separately. Notes column explains the split. |
| 📝 design-locked | RFC accepted; no code yet. Linked from the row. |
| 🗓 planned | On the roadmap; design not yet written. |
| 🚫 retired | Removed from the product. Page kept for history with the removal commit. |

## Strategy entry points

- **What this project even is:** [SPEC.md](../SPEC.md).
- **What's built when:** [ROADMAP.md](../ROADMAP.md).
- **Hard rules every PR must obey:** [AGENTS.md](../../AGENTS.md).
- **Open issues by milestone:** [milestone v0.2.0](https://github.com/akoita/mcp-tripwire/milestone/1).

## Trust-loop features

The core value Tripwire delivers to the agent: "can I trust this tool, and can I prove it?"

| Feature | Status | Audience | Where to use / test | Notes |
|---|---|---|---|---|
| [Tool descriptor scanning](descriptor-scanning.md) | ✅ implemented | LLM agent · CI · operator | `tripwire scan <manifest.json>` · POST `/scan` · ADK Scanner agent · `src/tripwire/detection.py` · tests/unit/test_detection.py | Deterministic stdlib-only ruleset: instruction-override, invisible/zero-width, homoglyph, exfil & credential patterns, outbound URLs in metadata. Findings carry an OWASP MCP id. |
| [Signed trust badges (attestation)](signed-trust-badges.md) | ✅ implemented | LLM agent · downstream auditor · CI | `tripwire verify <badge.json>` · `tripwire verify --pub <public.pem>` · POST `/verify` · `engine.approve()` · `src/tripwire/attestation.py` · ADK Attestor (with `require_confirmation=True`) | HMAC-SHA256 remains the zero-deps default; Ed25519 via `[signing]` makes badges independently verifiable with only the public key. |
| [Drift quarantine (rug-pull defense)](drift-quarantine.md) | ✅ implemented | LLM agent · MCP gateway · CI | `engine.evaluate_call()` · stdio proxy `tools/call` short-circuit · `tripwire ci` corpus rug-pull case `d1` | An already-approved tool that mutates is caught both on the next `tools/call` AND on the next fresh `tools/list` (whichever the agent does first). |
| [OWASP MCP Top-10 taxonomy](owasp-mcp-mapping.md) | ✅ implemented | Security team · downstream auditor · LLM agent | `src/tripwire/owasp.py` · every finding's `owasp` field · `tripwire scan` grouped output | MCP-01 through MCP-10 IDs + human titles. Lets findings travel into existing AppSec workflows without re-derivation. |

## Surface features

Where the trust loop is reachable from. Same engine, different transport.

| Feature | Status | Audience | Where to use / test | Notes |
|---|---|---|---|---|
| [Transparent stdio MCP proxy bridge](stdio-mcp-proxy.md) | ✅ implemented | LLM agent · MCP client · operator | `StdioTripwireProxy.serve()` · `make demo-proxy` · `make demo-real-mcp` · `examples/demo_proxy.py` · `examples/demo_real_mcp_playwright.py` · `tests/integration/test_proxy_bridge.py` · design in [RFC-0001](../rfc/RFC-0001-e2-stdio-proxy-bridge.md) | Spawns the upstream MCP server as a subprocess; rewrites `tools/list` (poisoned stripped, clean badged); short-circuits `tools/call` on non-ALLOW with JSON-RPC error −32001 + tripwire metadata. Real Playwright MCP proof shows the same bridge against a published server. |
| [`tripwire` CLI (scan / verify / ci)](cli-scan-verify-ci.md) | ✅ implemented | LLM agent · CI · operator | `src/tripwire/cli.py` · `tests/unit/test_cli.py` | OWASP-grouped `scan` output, three distinct `verify` exit codes (0 valid / 2 tampered / 3 malformed), `ci --json` for machine consumption, `NO_COLOR` honored. |
| [HTTP gateway (`/scan` `/verify` `/eval` `/healthz`)](http-gateway.md) | ✅ implemented locally · 🟢 staged on Cloud Run | LLM agent · CI · centralized scanner · downstream auditor | `app/fast_api_app.py` · `tests/integration/test_http_endpoints.py` · `make` smoke via Docker · [`docs/runbooks/deploy.md`](../runbooks/deploy.md) | Same verdict shapes as the CLI and the ADK Scanner — single source of truth across the three surfaces. Cloud Run push tracked in [#9](https://github.com/akoita/mcp-tripwire/issues/9). |
| [ADK multi-agent layer (Scanner / Red-team / Attestor)](adk-multi-agent-layer.md) | ✅ implemented | LLM operator via `agents-cli playground` · LLM agent | `src/tripwire/agents/` · `app/agent.py` · `examples/demo_adk.py` · `make demo-adk` · `tests/unit/test_agents.py` · [.agents-cli-spec.md](../../.agents-cli-spec.md) | The LLM is the explainer and router; the verdict always comes from the deterministic engine. The Attestor's tool requires user confirmation (`FunctionTool(require_confirmation=True)`). |

## Quality & measurement features

| Feature | Status | Audience | Where to use / test | Notes |
|---|---|---|---|---|
| [Attack corpus + drift runner](attack-corpus-runner.md) | ✅ implemented | Operator · CI · LLM agent | `corpus/attacks.jsonl` · `src/tripwire/corpus.py` · `make eval` · `tripwire ci --json` · `tests/unit/test_corpus.py` | Real measured headline: **9/9 attacks blocked · 0 false-positive on 4 clean tools**. Rule #6 (never invent metrics) is enforced here. |

## v0.2 — Credibility & integration

| Feature | Status | RFC | Issue | Notes |
|---|---|---|---|---|
| [SARIF output for `scan` and `ci`](sarif-output.md) | ✅ implemented | [RFC-0003](../rfc/RFC-0003-sarif-output.md) | [#32](https://github.com/akoita/mcp-tripwire/issues/32) | Findings flow into GitHub Code Scanning / GitLab SAST / any SARIF consumer with zero integration code. Operator path: [docs/runbooks/sarif-in-gh-actions.md](../runbooks/sarif-in-gh-actions.md). |
| [Ed25519 third-party verifiable badges](ed25519-signing.md) | ✅ implemented | [RFC-0002](../rfc/RFC-0002-ed25519-signing.md) | [#31](https://github.com/akoita/mcp-tripwire/issues/31) | Any verifier with the public key audits without trusting Tripwire. Makes the README's "portable, independently verifiable" claim literally true. |
| [HTTP/SSE proxy transport](http-sse-proxy-transport.md) | ✅ implemented | [RFC-0004](../rfc/RFC-0004-http-sse-proxy-transport.md) | [#33](https://github.com/akoita/mcp-tripwire/issues/33) | Brokers MCP between a client and an SSE-transport upstream. Necessary for the v0.2 operator-path acceptance gate. |

## Maintenance rule

Every PR that changes a user-visible capability (anything an agent / operator / CI script can observe through `tripwire`, the HTTP gateway, the proxy bridge, the ADK agents, or the badge format) **must update the corresponding feature page** in this directory. The PR template carries a checkbox for this; the harness verifies that:

- Every per-feature `.md` file in `docs/features/` is linked from this index.
- Every link in this index resolves to an existing file.

Broken either way → `make check` fails with a clear message naming the offender. See `check_features_catalog_consistent()` in [`scripts/harness_guardrails.py`](../../scripts/harness_guardrails.py).

When adding a new feature:

1. Write the per-feature page (`docs/features/<kebab-name>.md`) from the template — at minimum: Status · Audience · Value · How it works today · Verification.
2. Add the row to one of the tables above with a one-line "Notes" summary.
3. Cross-reference the originating RFC or issue.

When deprecating a feature: flip status to 🚫 retired with the removal commit; keep the page for history.
