# HTTP/SSE proxy transport

> **Status:** ✅ implemented · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)
> **Design:** [RFC-0004 (accepted)](../rfc/RFC-0004-http-sse-proxy-transport.md) · **Tracking:** [#33](https://github.com/akoita/mcp-tripwire/issues/33)

## Value (what this gives the agent / operator)

[`StdioTripwireProxy`](stdio-mcp-proxy.md) only fronts subprocess-spawned MCP servers. Real-world deployments — anything hosted, anything in a container, every "remote MCP" service in 2026 — speak the **HTTP+SSE** transport instead. Without this, Tripwire is a single-host tool with limited reach.

`SseTripwireProxy` brokers MCP between an agent and an SSE-transport upstream URL with the same guards as the stdio bridge: `tools/list` rewrite + `tools/call` short-circuit + drift quarantine + structured stderr log + the −32001 JSON-RPC error shape. The third piece of v0.2 — the one that genuinely unlocks *drop Tripwire in front of an MCP server you don't fully trust* for cloud-hosted upstreams.

## Audience

- **LLM agent / MCP client** that talks SSE to a remote MCP server.
- **Operator** wrapping a SaaS / third-party MCP service behind Tripwire.
- **CI / batch job** that needs to vet a remote MCP server's tool advertisements without spawning it locally.

## Contract

| Surface | What's delivered |
|---|---|
| `src/tripwire/proxy.py::SseTripwireProxy` | Thin subclass of `StdioTripwireProxy`. New entry point `bridge_sse(*, client_stream, server_stream, log=None)`. All guard logic + state inherited. |
| `src/tripwire/proxy.py::StdioTripwireProxy.invalidate_cache()` | New public method — clears `_live_tools`. Wired by `SseServerStream.on_cache_invalidate` so every upstream drop forces a fresh `tools/list` (RFC-0004 §Reconnect, Decision #8). |
| `app/sse_adapter.py::SseClientStream` | Inbound side. `push_inbound(bytes)` feeds the reader; `iter_outbound()` drains the outbound queue for the SSE event stream. |
| `app/sse_adapter.py::SseServerStream` | Upstream side. Async-context-managed. Two callbacks: `on_cache_invalidate` (fires per drop) + `on_terminal` (fires once when connection is over). Reconnect-once on `httpx.HTTPError` / `OSError` per RFC Decision #2. Headers forwarded byte-for-byte (Decision #3). |
| HTTP gateway `GET /mcp/sse/events` | SSE subscription. First frame is `event: endpoint, data: /mcp/sse/messages?session=<uuid>` (MCP convention). Subsequent frames carry server→client JSON-RPC responses. Gated by `TRIPWIRE_UPSTREAM_SSE_URL`. |
| HTTP gateway `POST /mcp/sse/messages?session=<uuid>` | Inbound JSON-RPC frame. Routes to the open session's `SseClientStream`. 404 on unknown session; 503 (with a non-secret diagnostic) when env is unset (Decision #9). |
| `TRIPWIRE_UPSTREAM_SSE_URL` | Env var that gates the gateway mount. Absent → `/mcp/sse/*` returns 503; `/healthz` keeps reporting gateway-process liveness (Decision #9). |

## Verification

- `tests/unit/test_sse_adapter.py` — 12 cases. Framing/unframing, push/iter round-trip, EOF semantics, dual-callback signal model, idempotent terminal, callback-error hygiene, POST-loop terminal-on-transport-error (Codex round 1 finding #2).
- `tests/integration/test_proxy_sse_bridge.py` — 2 cases (test plan group 3). tools/list strips poisoned + attaches badge; tools/call short-circuits drift with `-32001`. Same guard semantics as the stdio bridge, proved over the SSE adapter shape.
- `tests/integration/test_http_sse_mount.py` — 4 cases (test plan group 7 — partial). /healthz independent of upstream env; /mcp/sse/* 503 when env unset; /messages 404 on unknown session.

End-to-end verification: [`examples/demo_proxy_sse.py`](../../examples/demo_proxy_sse.py) + [`tests/integration/test_demo_proxy_sse_script.py`](../../tests/integration/test_demo_proxy_sse_script.py) — drives the three-act proof (poisoning stripped, rug-pull quarantined, `-32001` short-circuit) over HTTP+SSE against the in-process `fake_sse_mcp_server` fixture. Run with `make demo-proxy-sse`.

## Guarantees and limitations

- **Shared engine, per-client proxy** (Decision #1). The engine carries deployment policy (approvals, badges) consistent across all clients connected to the same upstream. Each `/mcp/sse/events` connection gets its own `SseTripwireProxy` for per-client `_live_tools` isolation.
- **Reconnect-once, then give up** (Decision #2). The operator wraps with k8s / Cloud Run retry policy if longer recovery is wanted. The cache clears on **every** drop (including before the reconnect attempt) so a tool approved pre-drop must be re-vetted via the fresh stream's `tools/list` — no stale-state survives.
- **POST failures are terminal-equivalent.** When a `/messages` POST returns a transport error, the adapter signals terminal (cache clear + EOF) rather than dying silently. The client gets a `-32001` upstream error rather than a hung session.
- **No Hard Rule #2 widening.** All third-party SSE deps live in `app/sse_adapter.py`. `src/tripwire/proxy.py` stays stdlib-only — `SseTripwireProxy` references the adapter only by duck-typed shape.
- **Auth headers forwarded byte-for-byte** (Decision #3). The `headers` dict passed to `SseServerStream` is forwarded verbatim on both the SSE GET and each POST. Hard Rule #3 holds — nothing is logged.
- **Header logging stays off.** Structured stderr lines stay at the `tripwire { action, tool, reason }` shape. No header / payload bytes leak into the log.

## Operator path (v0.2 acceptance gate)

Per [v0.2 acceptance](../ROADMAP.md#exit-criteria-for-the-v020-tag): the operator path for v0.2 needs a non-fixture MCP server. With this feature in place, the path becomes:

```bash
docker run --rm -p 8080:8080 \
  -e TRIPWIRE_UPSTREAM_SSE_URL=https://your-mcp-host.example.com/mcp \
  -e TRIPWIRE_SIGNING_KEY="$(openssl rand -hex 32)" \
  ghcr.io/akoita/mcp-tripwire:v0.2.0
# Client points at http://localhost:8080/mcp/sse instead of the upstream URL.
```

## Cross-references

- Companion (stdio sibling): [stdio-mcp-proxy.md](stdio-mcp-proxy.md) — same guard logic, different transport.
- Companion (the HTTP service surface): [http-gateway.md](http-gateway.md) — policy-only; distinct from this transparent SSE bridge.
- Design: [RFC-0004 (accepted)](../rfc/RFC-0004-http-sse-proxy-transport.md).
- Stdio precedent: [RFC-0001](../rfc/RFC-0001-e2-stdio-proxy-bridge.md).
- Tracking: [#33](https://github.com/akoita/mcp-tripwire/issues/33), [milestone v0.2.0](https://github.com/akoita/mcp-tripwire/milestone/1).
