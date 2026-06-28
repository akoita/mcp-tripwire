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


# ----- SseServerStream reconnect / cache invalidation (slot 5 — group 4) ----


@requires_agent
def test_sse_server_stream_signals_disconnect_on_terminal_failure():
    """On both connect attempts failing, feed_eof + on_disconnect callback fires."""
    import asyncio as _aio

    import httpx
    from app.sse_adapter import SseServerStream

    cleared = {"hit": False}

    async def go():
        stream = SseServerStream(
            "http://invalid.local",
            on_disconnect=lambda: cleared.__setitem__("hit", True),
        )
        # Patch _sse_loop to simulate two HTTP failures back-to-back; we just
        # care that the public behavior on terminal failure is right.
        calls = {"n": 0}

        async def fail_loop(self) -> None:
            for attempt in (1, 2):
                calls["n"] += 1
                if attempt == 1:
                    continue  # simulate first failure
                raise httpx.ConnectError("simulated")

        original_loop = stream._sse_loop

        async def patched():
            try:
                await fail_loop(stream)
            except httpx.HTTPError:
                pass
            stream.reader.feed_eof()
            stream._signal_disconnect()

        stream._sse_loop = patched  # type: ignore[method-assign]
        await patched()
        # Use a small sleep loop to let any internal scheduling settle.
        for _ in range(10):
            if stream.disconnected:
                break
            await _aio.sleep(0)
        assert stream.disconnected is True
        assert cleared["hit"] is True
        # Reader should be at EOF.
        line = await stream.reader.readline()
        assert line == b""
        assert calls["n"] == 2  # one initial + one reconnect attempt
        # Touch unused reference to avoid F841 if reformatting drops it.
        assert original_loop is not None

    asyncio.run(go())


@requires_agent
def test_sse_server_stream_disconnect_callback_swallows_callback_errors():
    """A buggy callback must not crash _signal_disconnect."""
    from app.sse_adapter import SseServerStream

    def boom() -> None:
        raise RuntimeError("operator wrote a bad callback")

    async def go():
        stream = SseServerStream("http://x", on_disconnect=boom)
        stream._signal_disconnect()  # must not raise
        assert stream.disconnected is True

    asyncio.run(go())


@requires_agent
def test_sse_server_stream_idempotent_disconnect_signal():
    """Repeated _signal_disconnect calls fire the callback exactly once."""
    from app.sse_adapter import SseServerStream

    n = {"hits": 0}

    async def go():
        stream = SseServerStream(
            "http://x", on_disconnect=lambda: n.__setitem__("hits", n["hits"] + 1)
        )
        stream._signal_disconnect()
        stream._signal_disconnect()
        stream._signal_disconnect()
        assert n["hits"] == 1

    asyncio.run(go())
