# RFC-0004 — HTTP/SSE MCP proxy transport

**Status:** **draft — REVIEW REQUESTED**
**Author:** Aboubakar Koita (with Claude)
**Issue:** [#33](https://github.com/akoita/mcp-tripwire/issues/33)
**Relates to:** [RFC-0001 stdio bridge](RFC-0001-e2-stdio-proxy-bridge.md), [RFC-0002 Ed25519](RFC-0002-ed25519-signing.md), [`src/tripwire/proxy.py`](../../src/tripwire/proxy.py), [`app/fast_api_app.py`](../../app/fast_api_app.py)
**Targets:** v0.2 — **third piece** in ordering. Lands after SARIF (#32) and Ed25519 (#31) implementations because the v0.2 operator-path acceptance gate ("fresh clone → configure a real MCP server → SARIF in GH Code Scanning → badge verified externally") needs at least one non-fixture MCP server to point Tripwire at, and most real-world MCP servers speak SSE.

## Why this exists

[`StdioTripwireProxy`](../features/stdio-mcp-proxy.md) only fronts subprocess-spawned upstreams over stdio. That's the right primitive for local dev, sidecar architectures, and CI gating, but it leaves out the entire class of MCP servers that increasingly dominates real-world deployments: **hosted MCP services that expose an HTTP+SSE transport** instead of a stdio command.

Without an SSE bridge, an operator who wants Tripwire in front of (say) a hosted GitHub-MCP service, a SaaS retrieval-MCP, or any other cloud-hosted upstream has no clean path. The current HTTP gateway is *policy-only* (POST one descriptor, get a verdict) — it doesn't broker live MCP traffic.

This RFC pins down the minimum viable bridge for SSE upstreams. The guard layer (`guard_tools_list`, `guard_tool_call`, the `_live_tools` cache) is already transport-agnostic, so this is mostly a transport implementation, not a re-architecture.

## Goals (in scope for v0.2 #33)

1. New `SseTripwireProxy` class (sibling to `StdioTripwireProxy`) that brokers JSON-RPC between an MCP client and an upstream MCP server reachable at an SSE URL.
2. Same guard semantics: `tools/list` rewrite (poisoned stripped, clean badged) + `tools/call` drift quarantine + structured stderr log + `−32001` JSON-RPC error shape.
3. Reuses `guard_tools_list` / `guard_tool_call` unchanged — they don't know about transport.
4. Integration test against a tiny in-process SSE server fixture (no real upstream needed in the test suite).
5. `make demo-proxy-sse` target showing the same three-act story as `make demo-proxy` against an SSE upstream.
6. Optional HTTP gateway mount `/mcp/sse` that proxies an operator-configured upstream URL when `TRIPWIRE_UPSTREAM_SSE_URL` is set.
7. `docs/features/http-sse-proxy-transport.md` flips from 🗓 planned to ✅ implemented; the [v0.2 operator-path acceptance](../ROADMAP.md#exit-criteria-for-the-v020-tag) is reachable.

## Non-goals (cuts for v0.2)

- **Streamable HTTP** (the newer experimental MCP transport that uses chunked HTTP instead of SSE). Defer to v0.3 — landing two new transports in one milestone is too much. Documented in §"Streamable HTTP" below.
- **WebSocket transport** — not in the MCP spec yet.
- **Multi-upstream from one proxy instance** — that's v0.3 (scale & multi-upstream). One `SseTripwireProxy` instance = one upstream.
- **Auth credential storage** — operator configures auth on the upstream's side or passes a token via env; Tripwire forwards headers untouched and never logs them.
- **Compression / SSE-event-type negotiation beyond `message`** — MCP only uses the default `data:` event type today.

## Architecture

### The boundary stays where it is

The proxy layer already has a clean transport seam from RFC-0001. `bridge()` takes four explicit stream-like objects:

```python
async def bridge(self, *,
                 client_reader: asyncio.StreamReader,
                 client_writer: asyncio.StreamWriter,
                 server_reader: asyncio.StreamReader,
                 server_writer: asyncio.StreamWriter,
                 log: IO[str]) -> None
```

For SSE, the four streams are:
- `client_reader / client_writer` — same as today (client is still talking line-delimited JSON-RPC, just through an HTTP request/response pair instead of stdio).
- `server_reader / server_writer` — an SSE adapter that exposes the upstream's SSE event stream as a `StreamReader`-shaped object, and the client→server direction as a `StreamWriter`-shaped POST emitter.

This means the existing `bridge()` is reused **unchanged**. Only the SSE-side adapter is new.

```
                  ┌────── SseTripwireProxy.serve ───────┐
 client HTTP POST │  Inbound: JSON-RPC frame per request │
   /mcp/sse  ────▶│  → client_reader (in-mem queue)      │
                  │                                       │
 client SSE       │  Outbound: queue.get() →              │
   subscription ◀─│  framed as `data: <json>\n\n` SSE     │
                  │  events on client SSE stream          │
                  │                                       │
                  │  ┌───── proxy.bridge (RFC-0001) ────┐ │
                  │  │ same two-task pump,             │ │
                  │  │ same guards, same -32001 errors  │ │
                  │  └────────────────┬──────────────────┘ │
                  │                   │ writes JSON+\n     │
                  │                   ▼                     │
                  │  ┌─ SseClient (upstream side) ─┐       │
                  │  │ POST  endpoint /messages     │──────┼─▶ upstream MCP server
                  │  │ SSE   subscription on /sse   │◀─────┼── upstream MCP server
                  │  └──────────────────────────────┘      │
                  └──────────────────────────────────────────┘
```

### Lifecycle: one proxy = one client

> **Open question 2 (resolved):** SSE is one stream per client; stdio was one pair per process. Lifecycle differs. **Decision: one `SseTripwireProxy` instance per client connection.**

The HTTP layer (`/mcp/sse` mount) accepts a client connection, constructs a fresh `SseTripwireProxy(engine, upstream_url)` for that client, holds the connection open until either side disconnects, then tears the proxy down. This keeps the per-client state (the `_live_tools` cache, the JSON-RPC `id → method` map) isolated and avoids cross-client correlation bugs.

The cost: a new TripwireEngine isn't constructed per client — the engine carries approved-fingerprint state, which we want **per-operator-policy**, not per-client. Engine is shared (passed in at construction); proxy state is per-client (`_live_tools`, `pending_methods`).

### Reconnect / resume semantics

> **Open question 1 (resolved):** SSE connections drop. How does the proxy handle resume? **Decision: drop-and-recreate, NOT replay.**

When the SSE link to the upstream dies (read error, connection closed, HTTP 502/503):

1. The proxy emits a `−32001` JSON-RPC error with `data.tripwire.action == "upstream_disconnected"` for any in-flight client request whose response can't be paired.
2. The proxy's `_live_tools` cache is **invalidated** (cleared). Stale-cache rug-pull detection requires confidence in what the upstream *currently* advertises.
3. The proxy attempts **one** reconnect to the upstream URL. If it succeeds, the proxy issues a fresh `tools/list` to the upstream on its own (not as a client request) to repopulate the cache, then resumes normal operation. The cache is empty until the fresh `tools/list` round-trips, so any client `tools/call` that lands in that window short-circuits with `require_approval`.
4. If the reconnect fails, the proxy tears down the client connection too. The client's SSE subscription ends with a final `event: close` SSE frame, and the proxy is finalised.

No replay buffer; no message resequencing; no exponential backoff for now. Reconnect-once-then-give-up is intentionally simple — operators wrap the deployment in their own retry strategy (sidecar, init container, k8s liveness probe).

### Auth header pass-through (Hard Rule #3)

> **Open question 3 (resolved):** how does the proxy let auth headers through without logging them? **Decision: opaque forwarding, no introspection.**

- The client's POST to `/mcp/sse` may carry `Authorization` / `Cookie` / `X-API-Key` / any other request headers. Tripwire **forwards those headers byte-for-byte** to the upstream's `/messages` POST.
- The proxy never **logs** request headers in any code path. The structured stderr log records the JSON-RPC `method`, the `id`, the tripwire action — never the request body, never the headers.
- The HTTP gateway already enforces `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=NO_CONTENT` (see [`app/app_utils/telemetry.py`](../../app/app_utils/telemetry.py)). The SSE bridge inherits that posture: payload-blind by design.
- A configurable allow-list of forwarded headers is **out of scope** — Tripwire is a trust gateway, not an auth proxy. Operators who want header filtering put a reverse proxy (Cloud Run IAM, an API Gateway, nginx) in front.

This satisfies Rule #3 cleanly because:
1. Tripwire's logs never see the credential.
2. Tripwire's persistent state (cache, engine fingerprints) doesn't include the credential.
3. The credential lives in the in-memory request lifecycle only — same surface area as the JSON-RPC payload itself.

### Streamable HTTP (out of scope; here for clarity)

The MCP spec introduced **Streamable HTTP** as an alternative to SSE: a single bidirectional HTTP/2-chunked-body channel instead of `POST + SSE-subscription`. It's strictly more flexible but the spec is younger and ecosystem adoption is uneven.

For v0.2 we cut it. The architecture above doesn't preclude a future `StreamableHttpTripwireProxy` (same `bridge()` boundary, different adapter). RFC-0005 would handle that when there's demand.

## Library choice

| Need | Pick | Why |
|---|---|---|
| Server side (the `/mcp/sse` mount inside `app/fast_api_app.py`) | `sse-starlette` (`EventSourceResponse`) | Already idiomatic for FastAPI; works with the existing app shell; one extra wheel. |
| Client side (the proxy's upstream connection) | `httpx-sse` (`aconnect_sse`) | Async, well-maintained, ships with `httpx` ecosystem we already use indirectly. |
| Test fixture (in-process SSE server) | A 40-line FastAPI app inside `tests/integration/_fixtures/` — same pattern as `fake_mcp_server.py` from RFC-0001 | Keeps the test self-contained; no Docker / no network. |

Both `sse-starlette` and `httpx-sse` go into the `[agent]` extra (which already pulls FastAPI and uvicorn). No new third-party dep enters the deterministic core — `tripwire.proxy` keeps its current stdlib-only `SseTripwireProxy` import shape and lazy-imports the SSE adapters at construction time, behind the same `[agent]` gate the HTTP gateway uses today.

Wait — `tripwire.proxy.py` is core (Hard Rule #2). Can it import sse-starlette/httpx-sse? **No.** Same constraint as RFC-0002 hit with `cryptography`. Resolution:

- `SseTripwireProxy` itself stays in `src/tripwire/proxy.py` and depends only on `asyncio` + the `bridge()` interface that already exists. It accepts the SSE adapter streams the caller has already constructed.
- The **SSE adapter classes** (`_SseClientStream`, `_SseServerStream`) live in `app/sse_adapter.py` (under the deploy shell, which is already where third-party deps are allowed). They wrap the `sse-starlette` / `httpx-sse` machinery and expose `StreamReader`-shaped objects.
- The `/mcp/sse` mount in `app/fast_api_app.py` is the only call site that constructs both — adapter and proxy together — for an incoming client.

Net result: the core stays stdlib-only; the deploy shell wires in the third-party transports. **No widening of Hard Rule #2 needed.**

## Wire-format details

### Inbound (client → proxy)

The client opens an HTTP POST against `/mcp/sse/messages` with `Content-Type: application/json` and one JSON-RPC frame per request body. The proxy parses the frame and pushes it onto the in-memory queue that `client_reader` drains.

The client also opens an SSE subscription against `/mcp/sse/events` to receive responses. This matches the MCP spec's HTTP+SSE transport convention: two endpoints (one POST, one GET-with-text/event-stream).

### Outbound (proxy → client)

Every JSON-RPC frame the proxy needs to send to the client is framed as:

```
event: message
data: {"jsonrpc": "2.0", "id": ..., "result": ...}

```

(trailing blank line per SSE spec). On `−32001` short-circuit, the same framing carries the error response.

### Upstream side

The proxy as **client** of the upstream:

- POSTs each forwarded JSON-RPC frame to `{TRIPWIRE_UPSTREAM_SSE_URL}/messages`.
- Subscribes (via `httpx-sse.aconnect_sse`) to `{TRIPWIRE_UPSTREAM_SSE_URL}/events`, reads SSE frames as they arrive, parses each `data:` line as JSON-RPC, feeds into `server_reader`.

This is the MCP spec's canonical HTTP+SSE shape. Tripwire makes no SSE protocol decisions of its own.

## CLI / HTTP / config surface

```
# Environment
TRIPWIRE_UPSTREAM_SSE_URL=https://my-mcp.example.com/mcp
    Required to enable /mcp/sse on the gateway. Absent = endpoint
    not mounted.

TRIPWIRE_SIGNING_KEY=...               # honored same as today
TRIPWIRE_PRIVATE_KEY_PATH=...          # honored post-Ed25519 (#31)
TRIPWIRE_PUBLIC_KEY_PATH=...           # same
```

```
GET  /mcp/sse/events    SSE subscription for outbound frames (client → proxy)
POST /mcp/sse/messages  Inbound JSON-RPC frame (client → proxy)
```

No CLI subcommand for v0.2 — the proxy lives in the deployed HTTP gateway, not in a per-shell command. v0.3 may add `tripwire proxy --upstream-sse <url>` for ad-hoc operator use.

## Decisions table

| # | Decision | Rationale |
|---|---|---|
| 1 | One `SseTripwireProxy` instance **per client connection** | Per-client state isolation. Engine stays shared. |
| 2 | Reconnect once on upstream drop, then give up | Simple; operator wraps with k8s/Cloud-Run retry. No replay buffer (would let stale state survive cleanly-failed connections). |
| 3 | Forward request headers **byte-for-byte**, never log them | Satisfies Rule #3 (never log raw payloads incl. credentials). |
| 4 | Streamable HTTP **deferred to v0.3** (RFC-0005) | Two new transports in one milestone is too much; the boundary is reusable. |
| 5 | SSE adapter in `app/sse_adapter.py`; proxy class stays in `src/tripwire/proxy.py` | Keeps the core stdlib-only — no Rule #2 widening needed (unlike RFC-0002 which had to widen for crypto). |
| 6 | `sse-starlette` (server) + `httpx-sse` (client) under `[agent]` extra | Both idiomatic, both well-maintained, both already in the FastAPI/httpx ecosystem this project uses. |
| 7 | `TRIPWIRE_UPSTREAM_SSE_URL` env switches the `/mcp/sse` mount on | Off by default — operators opt in by configuring their upstream. |
| 8 | Cache invalidation on disconnect + fresh `tools/list` on resume | Stale-cache rug-pull detection requires confidence in current upstream advertisement. |

## Test plan

1. **In-process SSE upstream fixture** — `tests/integration/_fixtures/fake_sse_mcp_server.py`: a FastAPI app exposing `/messages` + `/events`, advertising the same clean + poisoned tools as the stdio fixture, with the same `_admin/mutate` admin command. Run it on an ephemeral port via uvicorn-in-thread.
2. **Adapter unit tests** — `_SseClientStream` and `_SseServerStream` framing/unframing in isolation.
3. **Bridge round-trip** — point the existing `proxy.bridge()` at the SSE adapter streams; assert `tools/list` rewrite + `tools/call` short-circuit work identically to the stdio integration test.
4. **Reconnect semantics** — kill the fixture mid-session, assert in-flight requests get `upstream_disconnected` error, assert cache is cleared, assert the proxy attempts one reconnect.
5. **Header pass-through** — fixture asserts on `Authorization: Bearer <token>` arriving intact; proxy log buffer asserts the token does NOT appear anywhere.
6. **`make demo-proxy-sse`** — standalone demo script in `examples/demo_proxy_sse.py`. Exit 0; output mirrors `demo-proxy` three-act structure.
7. **HTTP gateway integration** — `tests/integration/test_http_sse_mount.py` brings up the gateway with `TRIPWIRE_UPSTREAM_SSE_URL` set, drives an SSE client end-to-end.
8. **Schema parity with stdio path** — assert that the same poisoned descriptor yields the same `Decision` shape regardless of which transport it arrived through.

## Day-N implementation plan (~10h)

| Slot | Step | Exit signal |
|---|---|---|
| 1h | New `[agent]`-extra deps in `pyproject.toml`: `sse-starlette`, `httpx-sse`. Update `uv.lock`. | `uv sync --extra agent` resolves; nothing else changes. |
| 1h | `tests/integration/_fixtures/fake_sse_mcp_server.py` — FastAPI fixture; sibling pattern to the stdio fixture. | Test 1 fixture passes a manual smoke (curl against the ephemeral port). |
| 2h | `app/sse_adapter.py` — `_SseClientStream` + `_SseServerStream`, framing/unframing. | Tests 2 pass against the fixture. |
| 1.5h | `SseTripwireProxy` class in `src/tripwire/proxy.py` — thin orchestrator over `bridge()` with the adapter streams. | Test 3 passes (bridge round-trip via SSE). |
| 1h | Reconnect / cache-invalidate handling (the upstream-disconnected `−32001` path). | Tests 4 + 5 pass. |
| 1h | HTTP gateway: `/mcp/sse/events` + `/mcp/sse/messages` mounts in `app/fast_api_app.py`, gated by `TRIPWIRE_UPSTREAM_SSE_URL`. | Test 7 passes. |
| 1h | `examples/demo_proxy_sse.py` + `make demo-proxy-sse` target + `tests/integration/test_demo_proxy_sse_script.py`. | Demo runs cleanly, exits 0; the three-act narrative renders. |
| 0.5h | `docs/features/http-sse-proxy-transport.md` flips from 🗓 planned to ✅ implemented; `README` implementation-status row flips. | `make check` green from a fresh clone. |
| 0.5h | Buffer. | (use it or bank it) |

≈ 10h total — slightly longer than the stdio bridge (8h) because of the reconnect path and the in-process SSE fixture.

## Operator path (v0.2 acceptance gate)

The v0.2.0 tag requires a documented "operator path" reproducible end-to-end on a fresh clone. With this RFC's implementation in place, that path becomes:

```bash
git clone https://github.com/akoita/mcp-tripwire && cd mcp-tripwire
uv sync --extra agent
docker build -t mcp-tripwire:dev .

# Point Tripwire at a real SSE-transport MCP server you don't fully trust.
docker run -d --rm -p 8080:8080 \
  -e TRIPWIRE_UPSTREAM_SSE_URL=https://some-mcp.example.com/mcp \
  -e TRIPWIRE_PRIVATE_KEY_PATH=/secrets/tripwire.pem \
  -v /local/keys:/secrets:ro \
  mcp-tripwire:dev

# Connect any MCP client (Claude Code, agents-cli, custom) to
# http://localhost:8080/mcp/sse instead of the upstream URL directly.

# Watch the structured stderr log for blocks / quarantines.
docker logs -f mcp-tripwire
```

A judge / external verifier can:
- POST `/scan` with a tool descriptor and see findings.
- GET `/eval` for the live 9/9 number.
- Verify any badge minted by this instance using only its public key (post-Ed25519 #31).
- Watch the SSE proxy quarantine a rug-pulled tool in real time (the demo shows this).

That's the v0.2.0 tag's actual judgement — not three internal tests in a trench coat.

## Open questions for the reviewer

1. **`sse-starlette` + `httpx-sse` vs an alternative (e.g. `aiohttp` SSE)?** Recommended pair fits the existing FastAPI / httpx ecosystem this project already uses. Reviewer can push back if a different stack is in use.

2. **Reconnect-once vs configurable retry policy?** I chose simple. A `TRIPWIRE_UPSTREAM_RECONNECT_ATTEMPTS=N` env knob is easy to add later if operators ask. Recommend deferring until someone asks.

3. **Per-client engine vs shared engine?** Recommended shared (per-deployment policy). Per-client engine would give isolation but bloat memory and confuse the approval lifecycle (each client re-approves everything). Reviewer to confirm.

4. **`/mcp/sse` URL prefix vs configurable?** Recommended fixed. Configurability is a deploy-shell concern (reverse proxy can rewrite paths); making the mount path env-driven adds surface area for misconfiguration.

5. **Should `examples/demo_proxy_sse.py` use the same vulnerable_mcp_server fixture (extended to speak SSE) or get its own SSE fixture?** Recommend extending the existing — operators see one vulnerable model with two transport variants, which mirrors what they'll face in real deployments.

6. **Failure mode for `TRIPWIRE_UPSTREAM_SSE_URL` set but unreachable at startup?** Recommend: app starts (so `/healthz` works), `/mcp/sse` returns 503 with a clear body until upstream is reachable. Don't fail-fast at boot — Cloud Run readiness probes will then continue to retry-style health.
