"""JSON-RPC id-normalization tests — RFC-0001 + Codex P1 round 2 finding #2.

The bridge keys `pending_methods` (the request-id → method dispatch table) on
a CANONICAL form so an untrusted upstream can't bypass the tools/list rewrite
branch by replying with `id: "1"` to a `id: 1` request.
"""

from __future__ import annotations

import asyncio
import json

from tripwire import TripwireEngine
from tripwire.proxy import StdioTripwireProxy, _normalize_id


def test_normalize_id_string_and_int_collide_to_same_key():
    assert _normalize_id(1) == _normalize_id("1") == "1"


def test_normalize_id_none_stays_none():
    assert _normalize_id(None) is None


def test_normalize_id_float_collides_with_string():
    # Defensive: spec says id is string|number|null; treat any number same as str.
    assert _normalize_id(1.5) == _normalize_id("1.5") == "1.5"


def _make_stream_pair():
    """A pair of (reader, writer) backed by an in-memory queue."""
    reader = asyncio.StreamReader()

    class W:
        def __init__(self):
            self.lines: list[bytes] = []
            self.closed = False

        def write(self, b: bytes) -> None:
            self.lines.append(b)

        async def drain(self) -> None:
            await asyncio.sleep(0)

        def close(self) -> None:
            self.closed = True

        def is_closing(self) -> bool:
            return self.closed

    return reader, W()


def test_pending_methods_handles_string_response_to_numeric_request():
    """Codex P1 round 2: the bridge must rewrite the tools/list response even
    when the upstream replies with a string id to a numeric request id."""
    eng = TripwireEngine(signing_key="k")
    proxy = StdioTripwireProxy(eng)

    async def go():
        client_reader, client_writer = _make_stream_pair()
        server_reader, server_writer = _make_stream_pair()
        # Client sends tools/list with numeric id 7.
        client_reader.feed_data(
            (json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}) + "\n").encode()
        )
        # Bridge will forward the request, then start reading the upstream side.
        bridge_task = asyncio.create_task(
            proxy.bridge(
                client_reader=client_reader,
                client_writer=client_writer,
                server_reader=server_reader,
                server_writer=server_writer,
                log=__import__("io").StringIO(),
            )
        )
        # Give the c2s pump a tick to forward the request.
        for _ in range(20):
            await asyncio.sleep(0)
        # Upstream replies with STRING id "7" — a malicious / sloppy server.
        server_reader.feed_data(
            (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "7",
                        "result": {
                            "tools": [
                                {
                                    "name": "ok_tool",
                                    "description": "Return weather.",
                                    "inputSchema": {},
                                }
                            ]
                        },
                    }
                )
                + "\n"
            ).encode()
        )
        # Close both sides so the bridge can exit.
        client_reader.feed_eof()
        server_reader.feed_eof()
        await asyncio.wait_for(bridge_task, timeout=1.0)

        # The bridge MUST have rewritten the response — `ok_tool` should have a
        # `_tripwire_badge` attached. Pre-fix, the response slipped through
        # unrewritten because the id-type mismatch bypassed the dispatch.
        out_lines = [json.loads(b) for b in client_writer.lines if b.strip()]
        assert len(out_lines) == 1
        response = out_lines[0]
        assert "result" in response and "tools" in response["result"]
        tools = response["result"]["tools"]
        assert len(tools) == 1
        assert "_tripwire_badge" in tools[0], (
            "tools/list response not rewritten — id-type mismatch bypassed dispatch"
        )

    asyncio.run(go())
