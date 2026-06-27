# RFC-0001 — E2: stdio MCP proxy bridge

**Status:** draft (2026-06-27, sprint Day 1)
**Author:** Aboubakar Koita
**Targets:** Sprint Day 2 (2026-06-28), 8h timebox.
**Relates to:** [ADR-0001-mcp-trust-gateway](../adr/ADR-0001-mcp-trust-gateway.md), [src/tripwire/proxy.py](../../src/tripwire/proxy.py), [tests/integration/test_proxy.py](../../tests/integration/test_proxy.py).

## Why this exists

`StdioTripwireProxy.serve()` is currently a documented `NotImplementedError` stub. Without a real bridge, the README's MCP-gateway claim is half-honored (guard logic ✅, transport ❌) and the demo can't show end-to-end interception with a real subprocess. This RFC pins down the minimum viable bridge so day-2 coding is mechanical.

## Goals (in scope for E2)

1. Spawn an upstream MCP server as a subprocess and proxy line-delimited JSON-RPC between client and server over stdio.
2. Intercept `tools/list` **responses**: replace `result.tools` with `guard_tools_list(...).approved`, attach `_tripwire_badge` per tool.
3. Intercept `tools/call` **requests**: look up the cached schema for `params.name`, run `guard_tool_call(...)`. If the verdict is not `ALLOW`, short-circuit with a JSON-RPC error response instead of forwarding.
4. Pass every other frame through untouched (initialize, ping, resources/*, prompts/*, notifications, errors).
5. One integration test that spawns a real subprocess and observes both proof moments (poisoned tool stripped from `tools/list`; rug-pulled tool quarantined at `tools/call`).

## Non-goals (explicit cuts)

- SSE / HTTP / Streamable HTTP transports (E2 is stdio only).
- Concurrent multi-server proxying — one proxy guards one upstream.
- Authentication, rate-limiting, request-id rewriting, batched requests.
- Replaying or rewriting upstream notifications.
- Real `mcp` SDK dependency for the test double — keep core stdlib-only (Hard Rule #2).

If any of these creep in, defer to a follow-up RFC.

## Architecture sketch

```
                     ┌─────────── StdioTripwireProxy.serve ────────────┐
 client.stdin  ────▶ │ pump_client_to_server: parse → maybe-guard → fwd│ ────▶ server.stdin
 client.stdout ◀──── │ pump_server_to_client: parse → maybe-filter → fwd│ ◀──── server.stdout
                     │ shared: TripwireEngine, live_tools cache          │
                     └────────────────────────────────────────────────────┘
```

Two asyncio tasks running concurrently, sharing a `dict[str, dict]` cache keyed by tool name (the latest descriptor we saw on `tools/list`). The engine and the cache are the only shared state; no locks needed because each direction is single-task.

## Why a live-tools cache is necessary

`guard_tool_call(current_tool)` needs the full descriptor to fingerprint it and detect drift, but a `tools/call` request only carries `params.name` and `params.arguments` — not the schema. So:

- On every `tools/list` response we cache `{tool.name: tool}` for the descriptors that survived `guard_tools_list`.
- On `tools/call` we look up the live descriptor by name, and that is what we feed into `guard_tool_call`. (The rug-pull detection happens by re-running `fingerprint()` over what the **server** currently advertises, vs the approved fingerprint the engine holds — drift = the description we just re-saw doesn't match what we approved.)
- If the server never advertised the tool (`name not in cache`), short-circuit with `REQUIRE_APPROVAL`.

Cache invalidation: replace wholesale on each new `tools/list` response. No TTL.

## JSON-RPC framing

MCP over stdio is line-delimited JSON (one JSON object per `\n`-terminated line, no Content-Length framing). The pump is:

```python
async for line in stream:
    if not line.strip(): continue
    try: msg = json.loads(line)
    except json.JSONDecodeError: forward_raw(line); continue   # don't choke on noise
    transformed = handle(msg)                                   # may rewrite, drop, or pass through
    out.write((json.dumps(transformed) + "\n").encode()); await out.drain()
```

Reference: MCP spec, "Transports — stdio" (line-delimited UTF-8 JSON-RPC 2.0).

## Interception rules (decision table)

| Direction       | `method`         | Action                                                                                                |
|---|---|---|
| client → server | `tools/list`     | forward unchanged (request) — interception happens on the response                                    |
| server → client | response to `tools/list` | replace `result.tools` with `guard_tools_list(result.tools).approved`; refresh live-tools cache |
| client → server | `tools/call`     | lookup cached tool by `params.name`; run `guard_tool_call`; ALLOW → forward, else short-circuit error |
| client → server | anything else    | forward unchanged                                                                                     |
| server → client | anything else    | forward unchanged                                                                                     |

Pairing requests to responses uses JSON-RPC `id`. Maintain `pending_ids: dict[int, str]` mapping id → method so the server-side pump knows which response is a `tools/list` reply.

## JSON-RPC error shape on block/quarantine

When `guard_tool_call` returns non-ALLOW, the proxy fabricates a response to the original request:

```json
{ "jsonrpc": "2.0", "id": <request id>, "error": {
    "code": -32001, "message": "<decision.reason>",
    "data": { "tripwire": { "action": "quarantine", "tool": "<name>", "findings": [...] } } } }
```

Use a Tripwire-reserved error code in the `-32000..-32099` JSON-RPC server-error range. `-32001` is the working value; pin it once a second error case appears.

## Acceptance criteria

The new integration test `tests/integration/test_proxy_bridge.py` must:

1. Spawn a Python subprocess running a tiny test-double MCP server (a 30-line script in `tests/integration/_fixtures/` that speaks line-delimited JSON-RPC, advertises one clean + one poisoned tool, and supports a `mutate` admin command that flips the clean tool to rug-pulled).
2. Connect `StdioTripwireProxy.serve(...)` between an in-process JSON-RPC client and the subprocess.
3. Assert: a `tools/list` call returns *only* the clean tool, with `_tripwire_badge` attached.
4. Trigger `mutate`, then call the clean tool. Assert the response is a JSON-RPC error with `error.data.tripwire.action == "quarantine"`.
5. Run under `pytest -x` in <2s and leave no orphan subprocesses (use `async with`-style cleanup or `Process.kill()` in teardown).

## Out-of-band concerns

- **Notifications:** server-initiated notifications (`tools/list_changed`, `prompts/list_changed`) pass through. If the client re-issues `tools/list` we'll re-cache; that's enough for E2.
- **Logging:** every BLOCK and QUARANTINE goes to stderr as one structured JSON line. No stdout — stdout is the proxy's bidirectional channel.
- **Backpressure:** rely on asyncio stream buffering; do not introduce queues. If this turns into a problem, defer to a follow-up.
- **Crash semantics:** if the upstream subprocess dies, the proxy exits with that subprocess's return code so the client sees the disconnect.

## Day-2 order of operations (8h budget)

| Slot   | Step                                                                    | Exit signal                                                  |
|--------|-------------------------------------------------------------------------|--------------------------------------------------------------|
| 0.5h   | Write the test-double subprocess fixture                                | Standalone fixture can be talked to manually with `echo … | python` |
| 1.5h   | Wire `serve()` — two pumps, json-line parser, passthrough for everything | A `tools/list` round-trips unchanged when the engine is empty |
| 1.5h   | Add `tools/list` response rewrite + live-tools cache                    | Test (3) passes                                              |
| 1.5h   | Add `tools/call` short-circuit on non-ALLOW                             | Test (4) passes                                              |
| 1h     | Stderr logging + clean shutdown + error-code constant                   | `pytest -x` runs in <2s with no warnings                     |
| 1h     | Update README implementation-status table; flip STATUS Done entry       | E2 row in implementation status moves from "partial" to "done" |
| 1h     | Buffer for surprises                                                    | (use it or bank it)                                          |

## Open questions (resolve before coding)

1. **Test-double vs real MCP SDK** — going with test-double to keep core stdlib-only. The SDK is fine for `examples/`, not for the deterministic integration test.
2. **Error code pin** — `-32001` for now; revisit if the gateway grows a second class of refusal.
3. **`require_approval` semantics in the proxy** — for E2 treat REQUIRE_APPROVAL the same as BLOCK (short-circuit with the same error data, distinguishable by `action`). Real human-in-the-loop approval is an E3/P1 concern.
