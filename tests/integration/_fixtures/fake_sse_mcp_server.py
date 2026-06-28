"""Test-double MCP server over HTTP+SSE.

Sibling to ``fake_mcp_server.py`` (stdio). RFC-0004 Decision #5 calls for
"shared vulnerable model, separate SSE transport fixture" — the threat model
(clean + poisoned tools + ``_admin/mutate`` rug-pull) is reused verbatim from
the stdio fixture; only the transport changes.

Exposes two endpoints, mirroring the MCP HTTP+SSE convention:

- ``POST /messages`` — one JSON-RPC frame per request body. Pushed onto the
  in-memory event queue if it produced a response (initialize / tools/list /
  tools/call / _admin/mutate); notifications (``id`` absent) are accepted
  without queuing.
- ``GET /events`` — an SSE subscription. The server emits one ``event:
  message`` frame per response taken from the queue. The connection stays
  open until the client disconnects.

Spins up via uvicorn-in-thread inside the integration test — see
``tests/integration/test_proxy_sse_bridge.py`` (slot 4 of RFC-0004 day-N).
This module is purely the FastAPI app; lifecycle is the test's job.
"""

from __future__ import annotations

import asyncio
import json

from fastapi import FastAPI, Request
from sse_starlette.sse import EventSourceResponse

# Reuse the threat model from the stdio fixture (same clean / poisoned tools,
# same `_admin/mutate` rug-pull). RFC-0004 Decision #5.
from . import fake_mcp_server


def build_app() -> FastAPI:
    """Construct a fresh app + queue per test. State (the global `state` dict
    in the stdio fixture) is process-wide; each test should call
    `fake_mcp_server.state["get_weather"]["description"] = CLEAN_DESC` if it
    needs a clean baseline."""
    app = FastAPI(title="fake-sse-mcp")
    queue: asyncio.Queue[dict] = asyncio.Queue()

    @app.post("/messages")
    async def messages(request: Request) -> dict:
        body = await request.body()
        try:
            msg = json.loads(body)
        except json.JSONDecodeError:
            return {"jsonrpc": "2.0", "error": {"code": -32700, "message": "parse error"}}
        resp = fake_mcp_server.handle(msg)
        if resp is not None:
            await queue.put(resp)
            return {"queued": True}
        return {"queued": False}  # notification — no response queued

    @app.get("/events")
    async def events(request: Request) -> EventSourceResponse:
        async def stream():
            # MCP HTTP+SSE 2024-11-05 spec (Codex P1 round 2): first frame
            # is the `endpoint` event advertising the POST URL. Real
            # upstreams may use session-scoped URLs (e.g.
            # `/messages?sessionId=...`); the fixture stays simple with a
            # relative `/messages` — the adapter resolves it against the
            # SSE base URL.
            yield {"event": "endpoint", "data": "/messages"}
            while True:
                if await request.is_disconnected():
                    break
                try:
                    resp = await asyncio.wait_for(queue.get(), timeout=0.25)
                except TimeoutError:
                    continue  # heartbeat tick, no payload
                yield {"event": "message", "data": json.dumps(resp)}

        return EventSourceResponse(stream())

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    return app


# A module-level instance for ad-hoc uvicorn smoke runs:
#     uvicorn tests.integration._fixtures.fake_sse_mcp_server:app --port 0
app = build_app()
