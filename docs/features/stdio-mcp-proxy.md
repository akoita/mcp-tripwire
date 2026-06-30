# Transparent stdio MCP proxy bridge

> **Status:** ✅ implemented · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)

## Value (what this gives the agent / LLM)

The proxy bridge is the **production transport** for the trust loop. An MCP client speaks line-delimited JSON-RPC to Tripwire on its `stdin`; Tripwire forwards vetted messages to a spawned upstream MCP server on the server's `stdin`; replies flow back the other way. From the client's view, it's talking to a normal MCP server — but every `tools/list` is filtered and every `tools/call` is checked against the approved fingerprint before it reaches the upstream.

The agent never sees a poisoned tool descriptor. A rug-pull never executes. And the agent doesn't have to know Tripwire exists — it just talks MCP.

## Audience

- **LLM agent** (Claude Code, agents-cli, custom) that talks MCP and wants trust enforced transparently.
- **MCP client** authors who want to drop Tripwire in as a sidecar without rewriting their session loop.
- **Operator** wrapping a third-party MCP server they don't fully trust.

## How it works today

`StdioTripwireProxy.serve(command: list[str])` spawns `command` as a subprocess and pumps line-delimited JSON-RPC in both directions with two concurrent asyncio tasks. The transport-agnostic core is `bridge(...)` — taking explicit `client_reader / client_writer / server_reader / server_writer` stream pairs — which makes the bridge testable with in-memory pipes (no subprocess required in unit tests).

```
                         ┌────────────────── proxy.bridge ───────────────────┐
 client.stdin   ────────▶│ pump_client_to_server:                              │
                         │   tools/call → guard_tool_call(cached descriptor)  │
                         │   non-ALLOW → JSON-RPC error −32001 (short-circuit)│
                         │   else → forward to server.stdin                   │
                         │                                                    │────▶ server.stdin
 client.stdout  ◀────────│ pump_server_to_client:                              │
                         │   response to tools/list → guard_tools_list,       │
                         │     replace result.tools with .approved,            │
                         │     refresh _live_tools cache                       │
                         │   else → forward                                   │◀──── server.stdout
                         │ stderr: one-line JSON per block/quarantine event   │
                         └────────────────────────────────────────────────────┘
```

The full design (request-id pairing, live-tools cache, JSON-RPC framing, the −32001 error shape, the request-method dispatcher) is in [RFC-0001](../rfc/RFC-0001-e2-stdio-proxy-bridge.md).

## Contract

```python
# src/tripwire/proxy.py
TRIPWIRE_ERROR_CODE = -32001   # JSON-RPC server-error range; Tripwire's reserved code

class GuardedListResult:
    approved: list[dict]   # tool descriptors with `_tripwire_badge` attached
    blocked: list[Decision]

class StdioTripwireProxy:
    def __init__(self, engine: TripwireEngine) -> None: ...
    def guard_tools_list(self, tools: list[dict]) -> GuardedListResult: ...
    def guard_tool_call(self, current_tool: dict) -> Decision: ...
    async def serve(self, command: list[str], *, log: IO[str] | None = None) -> int: ...
    async def bridge(self, *, client_reader, client_writer,
                     server_reader, server_writer, log: IO[str]) -> None: ...
```

A non-ALLOW `tools/call` becomes:

```json
{
  "jsonrpc": "2.0",
  "id": <request id>,
  "error": {
    "code": -32001,
    "message": "<decision.reason>",
    "data": { "tripwire": { "action": "quarantine|block|require_approval",
                            "tool": "<name>",
                            "findings": [...] } }
  }
}
```

The structured stderr log emits one JSON line per block / quarantine event so an operator can `grep` without parsing the JSON-RPC stream.

## Surfaces

| Surface | How to reach it |
|---|---|
| `make demo-proxy` | `examples/demo_proxy.py` spawns `examples/vulnerable_mcp_server.py` through the bridge with in-memory pipes (no real stdio attach required). The "operator runbook" version of the proof moment. |
| `make demo-real-mcp` | `examples/demo_real_mcp_playwright.py` starts Microsoft Playwright MCP through `npx`, routes it through Tripwire, badges the real browser tool catalog, and calls `browser_navigate` against `https://example.com`. |
| Production | `python -m tripwire.proxy …` (CLI wrapper in scope for v0.3 multi-upstream). For now, library use: `await StdioTripwireProxy(engine).serve(["python", "my_mcp_server.py"])`. |
| Tests | `proxy.bridge(...)` accepts in-memory streams, exercised by [`tests/integration/test_proxy_bridge.py`](../../tests/integration/test_proxy_bridge.py). |

## Verification

- Integration: [`tests/integration/test_proxy_bridge.py`](../../tests/integration/test_proxy_bridge.py) — spawns the fake MCP server, exercises both proof moments (poisoned stripped, rug-pull quarantined), runs in ~90ms with no orphan subprocesses.
- Integration (demo script): [`tests/integration/test_proxy_demo_script.py`](../../tests/integration/test_proxy_demo_script.py) — `make demo-proxy` exits 0 and prints the three labelled sections.
- Manual: `make demo-proxy` reads like the video opening — section A (no proxy → poisoned visible), B (with proxy → stripped + badged), C (rug-pull → quarantine).
- Manual real-upstream: `make demo-real-mcp` requires Node/npx and a Playwright browser install; it fronts a published MCP server and proves a real browser navigation through the proxy.

## Guarantees and limitations

- **One client, one server** per proxy instance. Multi-upstream is v0.3 (see [ROADMAP.md](../ROADMAP.md)).
- **stdio transport only.** HTTP/SSE upstreams need the v0.2 SSE bridge ([#33](https://github.com/akoita/mcp-tripwire/issues/33)).
- **Auth pass-through** to the upstream is opaque — the proxy doesn't introspect or log credentials in the JSON-RPC stream (Hard Rule #3). If your upstream needs an API key in a request header, configure it on the upstream subprocess; the proxy forwards the message bytes untouched.
- **Live-tools cache** is wholesale-refreshed on every `tools/list` response; if the agent never re-lists, between calls the cache is the last-seen snapshot. Drift between calls is caught only when the agent re-lists.
- **Notifications pass through** unchanged. `tools/list_changed` notifications from the server are forwarded; the agent's response (whether to re-list) is its call.

## Cross-references

- Design: [RFC-0001](../rfc/RFC-0001-e2-stdio-proxy-bridge.md) — full transport spec, error code rationale, day-2 implementation plan that produced this feature.
- Companions: [drift-quarantine.md](drift-quarantine.md) (what the `tools/call` check does), [descriptor-scanning.md](descriptor-scanning.md) (what the `tools/list` filter runs).
- Future: [http-sse-proxy-transport.md](http-sse-proxy-transport.md) — the same shape over the other MCP transport.
