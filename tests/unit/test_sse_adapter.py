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
