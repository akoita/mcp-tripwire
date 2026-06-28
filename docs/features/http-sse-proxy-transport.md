# HTTP/SSE proxy transport

> **Status:** 🗓 planned (design pending — RFC-0004 not yet drafted) · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)
> **Tracking:** [#33](https://github.com/akoita/mcp-tripwire/issues/33)

## Value (what this gives the agent / operator)

[`StdioTripwireProxy`](stdio-mcp-proxy.md) only fronts subprocess-spawned MCP servers. Real-world deployments — anything hosted, anything in a container, every "remote MCP" service in 2026 — speak the **HTTP+SSE** transport instead. Without this, Tripwire is a single-host tool with limited reach.

When this lands, Tripwire brokers MCP between an agent and an SSE-transport upstream URL, with the same guards: `tools/list` rewrite + `tools/call` short-circuit + drift quarantine + structured stderr log + the −32001 JSON-RPC error shape.

This is the **third piece** of v0.2 and the one that genuinely unlocks "drop Tripwire in front of an MCP server you don't fully trust" for cloud-hosted upstreams.

## Audience

- **LLM agent / MCP client** that talks SSE to a remote MCP server.
- **Operator** wrapping a SaaS / third-party MCP service.
- **CI / batch job** that needs to vet a remote MCP server's tool advertisements without spawning it locally.

## Tentative scope (to be pinned in RFC-0004)

| Surface | Expected |
|---|---|
| New class | `SseTripwireProxy` (sibling to `StdioTripwireProxy`) |
| Guard reuse | `guard_tools_list`, `guard_tool_call`, the `_live_tools` cache — already transport-agnostic |
| New `make` target | `make demo-proxy-sse` — same three-act story as `make demo-proxy` but against an SSE upstream |
| HTTP gateway integration | Optional `/mcp/sse` mount that proxies an operator-configured `TRIPWIRE_UPSTREAM_SSE_URL` |
| Tests | In-process SSE server fixture (sse-starlette or stdlib) so the integration test stays self-contained |

## Open design questions (for RFC-0004)

These need to be pinned before any implementation. They're the reason the RFC isn't drafted yet — the answers reshape the surface.

1. **Reconnect / resume semantics.** SSE connections drop. How does the proxy reconnect to the upstream and re-emit / re-populate the `_live_tools` cache on resume? Replay the last `tools/list`? Issue a fresh one and risk a "list changed under us" race?
2. **Multiple concurrent clients.** SSE is one-stream-per-client; stdio is one-pair-per-process. Lifecycle changes shape — does one `SseTripwireProxy` instance multiplex clients, or do we instantiate per-client?
3. **Auth header pass-through.** SSE upstreams often need bearer tokens / API keys in request headers. Hard Rule #3 says we never log raw payloads — auth headers must follow the same rule. How does the proxy let headers through without ever seeing them in logs?
4. **Streamable HTTP** — the newer experimental transport. In or out of scope?

## Acceptance gate

Per [v0.2 acceptance](../ROADMAP.md#exit-criteria-for-the-v020-tag): the **operator path** for v0.2 isn't met without a non-fixture MCP server in the picture. Most non-fixture MCP servers worth pointing Tripwire at use SSE. So this feature is on the critical path for the v0.2.0 tag.

## Status & next step

The next action is drafting **RFC-0004** with the open questions above pinned and a Day-N plan. After [SARIF (#32)](sarif-output.md) and [Ed25519 (#31)](ed25519-signing.md) implementations land, the credibility surface is settled enough to write the SSE design.

## Cross-references

- Companion (stdio sibling): [stdio-mcp-proxy.md](stdio-mcp-proxy.md) — same guard logic, different transport. The guard layer is already transport-agnostic.
- Companion (the HTTP service surface): [http-gateway.md](http-gateway.md) — distinct from this; HTTP gateway is policy-only (POST one descriptor, get a verdict), not a transparent MCP bridge.
- Design (stdio precedent): [RFC-0001](../rfc/RFC-0001-e2-stdio-proxy-bridge.md) — same authoring template will produce RFC-0004.
- Tracking: [#33](https://github.com/akoita/mcp-tripwire/issues/33), [milestone v0.2.0](https://github.com/akoita/mcp-tripwire/milestone/1).
