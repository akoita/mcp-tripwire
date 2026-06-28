"""Adapter unit tests — slot 3 exit signal (RFC-0004 test plan group 2).

Exercises framing/unframing in isolation. Bridge round-trip via these
adapters is slot 4's integration test (against the SSE fixture).
"""

from __future__ import annotations

import asyncio
import json

import pytest


def _httpx_available() -> bool:
    try:
        import httpx  # noqa: F401
        import sse_starlette  # noqa: F401
    except ImportError:
        return False
    return True


requires_agent = pytest.mark.skipif(
    not _httpx_available(),
    reason="`[agent]` extra not installed (sse-starlette / httpx-sse missing)",
)


# Lazy module-level import — only attempt when [agent] is installed.
if _httpx_available():
    from app.sse_adapter import SseClientStream, _QueueWriter
else:  # pragma: no cover - import-guard branch
    SseClientStream = None  # type: ignore[assignment]
    _QueueWriter = None  # type: ignore[assignment]


# ----- _QueueWriter ---------------------------------------------------------


@requires_agent
def test_queue_writer_splits_on_newline_and_strips_empty_lines():
    q: asyncio.Queue = asyncio.Queue()
    w = _QueueWriter(q)
    w.write(b'{"jsonrpc":"2.0","id":1}\n')
    w.write(b'\n\n{"jsonrpc":"2.0","id":2}\n')
    items = []
    while not q.empty():
        items.append(q.get_nowait())
    assert items == [b'{"jsonrpc":"2.0","id":1}', b'{"jsonrpc":"2.0","id":2}']


@requires_agent
def test_queue_writer_buffers_partial_lines():
    q: asyncio.Queue = asyncio.Queue()
    w = _QueueWriter(q)
    w.write(b'{"jsonrpc":"2.0",')
    assert q.empty()
    w.write(b'"id":3}\n')
    assert q.get_nowait() == b'{"jsonrpc":"2.0","id":3}'


@requires_agent
def test_queue_writer_close_emits_sentinel_and_drops_further_writes():
    q: asyncio.Queue = asyncio.Queue()
    w = _QueueWriter(q)
    w.write(b'{"a":1}\n')
    w.close()
    assert q.get_nowait() == b'{"a":1}'
    assert q.get_nowait() is None  # sentinel
    assert w.is_closing()
    w.write(b'{"b":2}\n')  # post-close write is a no-op
    assert q.empty()


@requires_agent
def test_queue_writer_drain_is_awaitable_no_op():
    q: asyncio.Queue = asyncio.Queue()
    w = _QueueWriter(q)
    asyncio.run(w.drain())  # should not raise


# ----- SseClientStream ------------------------------------------------------


@requires_agent
def test_sse_client_stream_push_inbound_appends_newline_when_missing():
    """The bridge's readline() expects line-delimited frames."""

    async def go():
        s = SseClientStream()
        s.push_inbound(b'{"jsonrpc":"2.0","method":"initialize","id":1}')
        s.close_inbound()
        line = await s.reader.readline()
        assert line == b'{"jsonrpc":"2.0","method":"initialize","id":1}\n'

    asyncio.run(go())


@requires_agent
def test_sse_client_stream_writer_outbound_round_trip():
    """A bridge-shaped write of one full JSON-RPC frame appears verbatim on
    the outbound iterator (one line per frame)."""

    async def go():
        s = SseClientStream()
        payload = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        s.writer.write((json.dumps(payload) + "\n").encode())
        s.writer.close()
        collected = []
        async for line in s.iter_outbound():
            collected.append(json.loads(line))
        assert collected == [payload]

    asyncio.run(go())


@requires_agent
def test_sse_client_stream_writer_emits_two_distinct_frames():
    """Concatenated writes split into one queue entry per JSON-RPC frame."""

    async def go():
        s = SseClientStream()
        s.writer.write(b'{"a":1}\n{"b":2}\n')
        s.writer.close()
        out = [json.loads(line) async for line in s.iter_outbound()]
        assert out == [{"a": 1}, {"b": 2}]

    asyncio.run(go())


@requires_agent
def test_sse_client_stream_reader_eof_after_close_inbound():
    """The bridge stops reading after `feed_eof()` — close_inbound triggers it."""

    async def go():
        s = SseClientStream()
        s.push_inbound(b'{"jsonrpc":"2.0","id":99}')
        s.close_inbound()
        first = await s.reader.readline()
        empty = await s.reader.readline()
        assert json.loads(first) == {"jsonrpc": "2.0", "id": 99}
        assert empty == b""  # EOF

    asyncio.run(go())


# ----- SseServerStream cache-invalidate + terminal callbacks (Codex round 1) -


@requires_agent
def test_sse_server_stream_cache_invalidate_fires_on_every_drop():
    """Codex P1: on every upstream drop (including the one before reconnect),
    on_cache_invalidate must fire so the proxy's _live_tools is cleared and
    the fresh-stream tools/list rebuilds it. RFC-0004 §Reconnect + #8."""
    from app.sse_adapter import SseServerStream

    cache_clears = {"n": 0}
    terminal_hits = {"n": 0}

    async def go():
        stream = SseServerStream(
            "http://x",
            on_cache_invalidate=lambda: cache_clears.__setitem__("n", cache_clears["n"] + 1),
            on_terminal=lambda: terminal_hits.__setitem__("n", terminal_hits["n"] + 1),
        )
        # Simulate: drop, reconnect, drop again (terminal).
        stream._notify_cache_invalidate()
        stream._notify_cache_invalidate()
        stream._notify_terminal()
        assert cache_clears["n"] == 2  # one per drop
        assert terminal_hits["n"] == 1  # once at the end

    asyncio.run(go())


@requires_agent
def test_sse_server_stream_terminal_is_idempotent():
    """Once terminal, subsequent _notify_terminal calls are no-ops."""
    from app.sse_adapter import SseServerStream

    n = {"hits": 0}

    async def go():
        stream = SseServerStream(
            "http://x", on_terminal=lambda: n.__setitem__("hits", n["hits"] + 1)
        )
        stream._notify_terminal()
        stream._notify_terminal()
        stream._notify_terminal()
        assert n["hits"] == 1
        assert stream.disconnected is True

    asyncio.run(go())


@requires_agent
def test_sse_server_stream_callbacks_swallow_exceptions():
    """Buggy callbacks must not crash the notify path."""
    from app.sse_adapter import SseServerStream

    def boom() -> None:
        raise RuntimeError("operator wrote a bad callback")

    async def go():
        stream = SseServerStream("http://x", on_cache_invalidate=boom, on_terminal=boom)
        stream._notify_cache_invalidate()  # must not raise
        stream._notify_terminal()  # must not raise
        assert stream.disconnected is True

    asyncio.run(go())


class _FakeFailingPosts:
    """Stand-in for httpx.AsyncClient.post that always raises ConnectError."""

    async def post(self, url, *, content, headers):
        import httpx as _httpx

        raise _httpx.ConnectError("nope")


@requires_agent
def test_sse_server_stream_post_loop_signals_terminal_on_transport_error():
    """Codex P1 round 1: POST failure → terminal-signal + EOF, not silent task death."""
    from app.sse_adapter import SseServerStream

    cache_clears = {"n": 0}
    terminal_hits = {"n": 0}

    async def go():
        stream = SseServerStream(
            "http://x",
            on_cache_invalidate=lambda: cache_clears.__setitem__("n", cache_clears["n"] + 1),
            on_terminal=lambda: terminal_hits.__setitem__("n", terminal_hits["n"] + 1),
        )
        stream._client = _FakeFailingPosts()
        # _post_loop blocks on _post_url_ready.wait() before POSTing (Codex P1 round 2).
        stream._post_url = "http://x/messages"
        stream._post_url_ready.set()
        await stream._post_queue.put(b'{"jsonrpc":"2.0","id":1}')
        await stream._post_loop()
        assert cache_clears["n"] == 1
        assert terminal_hits["n"] == 1
        line = await stream.reader.readline()
        assert line == b""

    asyncio.run(go())


# ----- Codex round 2: spec, closed-client, bounded queues -------------------


@requires_agent
def test_sse_client_stream_push_inbound_returns_false_when_closed():
    """Codex P2 round 2: a late POST after on_terminal must be rejected cleanly,
    not crash with AssertionError from feed_data() after feed_eof()."""

    async def go():
        s = SseClientStream()
        assert s.push_inbound(b'{"a":1}') is True
        s.close_inbound()
        assert s.closed is True
        s.close_inbound()  # idempotent
        assert s.push_inbound(b'{"b":2}') is False

    asyncio.run(go())


@requires_agent
def test_sse_client_stream_outbound_queue_is_bounded_and_terminates_on_overflow():
    """Writes past the bounded queue size trigger on_full → close_inbound."""
    from app.sse_adapter import _MAX_QUEUE_FRAMES

    async def go():
        s = SseClientStream()
        for i in range(_MAX_QUEUE_FRAMES):
            s.writer.write(f'{{"i":{i}}}\n'.encode())
        assert s.closed is False
        # One more → overflow → on_full triggers close_inbound.
        s.writer.write(b'{"overflow":true}\n')
        assert s.closed is True

    asyncio.run(go())


class _FakePosts:
    """Stand-in for httpx.AsyncClient. Records POSTs, returns OK."""

    def __init__(self):
        self.calls: list[tuple[str, bytes]] = []

    async def post(self, url, *, content, headers):
        self.calls.append((url, content))

        class _R:
            status_code = 200

        return _R()


@requires_agent
def test_sse_server_stream_post_loop_uses_endpoint_event_url():
    """Codex P1 round 2: POSTs go to the URL the upstream advertised via the
    `endpoint` SSE event (MCP HTTP+SSE 2024-11-05 spec), not hardcoded
    /messages."""
    from app.sse_adapter import SseServerStream

    async def go():
        stream = SseServerStream("http://upstream.example/mcp")
        stream._client = _FakePosts()
        # Simulate the SSE side handing us a session-scoped endpoint URL.
        stream._post_url = "http://upstream.example/mcp/messages?sessionId=abc123"
        stream._post_url_ready.set()
        await stream._post_queue.put(b'{"jsonrpc":"2.0","id":1}')
        await stream._post_queue.put(None)  # sentinel — exit loop
        await stream._post_loop()
        assert stream._client.calls == [
            ("http://upstream.example/mcp/messages?sessionId=abc123", b'{"jsonrpc":"2.0","id":1}'),
        ]

    asyncio.run(go())


@requires_agent
def test_sse_server_stream_post_loop_blocks_until_endpoint_advertised():
    """A POST queued before the upstream sends an `endpoint` event must wait,
    not be sent to a hardcoded fallback URL."""
    from app.sse_adapter import SseServerStream

    async def go():
        stream = SseServerStream("http://upstream.example/mcp")
        stream._client = _FakePosts()
        await stream._post_queue.put(b'{"jsonrpc":"2.0","id":1}')

        post_task = asyncio.create_task(stream._post_loop())
        # Give the loop a chance to dequeue + start awaiting the URL event.
        for _ in range(20):
            await asyncio.sleep(0)
        # Endpoint URL not advertised yet — POST must not have fired.
        assert stream._client.calls == []
        # Advertise the URL + sentinel; loop drains.
        stream._post_url = "http://upstream.example/mcp/m?sid=42"
        stream._post_url_ready.set()
        await stream._post_queue.put(None)
        await asyncio.wait_for(post_task, timeout=1.0)
        assert len(stream._client.calls) == 1
        assert stream._client.calls[0][0] == "http://upstream.example/mcp/m?sid=42"

    asyncio.run(go())
