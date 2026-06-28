"""SSE adapter — wraps inbound (server-side) and upstream (client-side) SSE
connections as ``asyncio.StreamReader`` / writer-shaped objects that
``StdioTripwireProxy.bridge()`` consumes unchanged.

RFC-0004 Decision #5: third-party SSE deps live here (``sse-starlette`` for
the server side, ``httpx-sse`` + ``httpx`` for the upstream side), keeping
``src/tripwire/proxy.py`` stdlib-only. No Hard Rule #2 widening needed.

Both stream pairs follow the same shape:

- ``reader`` is an ``asyncio.StreamReader`` the bridge can ``readline()``.
- ``writer`` is a minimal shim exposing ``write(bytes)``, ``await drain()``,
  ``close()``, and ``is_closing()`` — the four methods the bridge calls.

Bytes flowing through the writer are line-delimited JSON-RPC frames (the same
on-wire shape ``StdioTripwireProxy`` produces). The SSE/HTTP transport-specific
work (framing into ``event: message\\ndata: <line>``, POSTing to
``/messages``, subscribing to ``/events``) happens inside this module.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator


class _QueueWriter:
    """Minimal writer shim that splits incoming bytes on ``\\n`` and pushes
    each non-empty line (stripped) onto a queue. Sentinel ``None`` on close.

    The bridge writes JSON-RPC frames with trailing newlines (the
    ``_send`` helper appends one). One push per frame is what consumers
    expect — the SSE side wraps each as ``event: message``, the upstream
    side POSTs each to ``/messages``.
    """

    def __init__(self, queue: asyncio.Queue) -> None:
        self._q = queue
        self._closed = False
        self._buf = b""

    def write(self, data: bytes) -> None:
        if self._closed:
            return
        self._buf += data
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            line = line.strip()
            if line:
                self._q.put_nowait(line)

    async def drain(self) -> None:
        # Backpressure is bounded by the queue's maxsize (unbounded by default).
        # The bridge expects an awaitable; yielding once is enough to honour it.
        await asyncio.sleep(0)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            # Sentinel so consumers (iter_outbound / upstream POST task) exit cleanly.
            try:
                self._q.put_nowait(None)
            except asyncio.QueueFull:  # pragma: no cover - unbounded queue
                pass

    def is_closing(self) -> bool:
        return self._closed


class SseClientStream:
    """Inbound side: one client connected over SSE/HTTP.

    The ``reader`` is fed by ``POST /messages`` (one JSON-RPC frame per request
    body — call ``push_inbound(body)`` from the handler). The ``writer``
    captures server→client frames; ``iter_outbound()`` yields each one for the
    SSE event stream to emit as ``event: message``.
    """

    def __init__(self) -> None:
        self.reader: asyncio.StreamReader = asyncio.StreamReader()
        self._outbound: asyncio.Queue = asyncio.Queue()
        self.writer = _QueueWriter(self._outbound)

    def push_inbound(self, frame_bytes: bytes) -> None:
        """Feed a single JSON-RPC frame (raw bytes, with or without trailing
        newline) into the reader."""
        if not frame_bytes.endswith(b"\n"):
            frame_bytes = frame_bytes + b"\n"
        self.reader.feed_data(frame_bytes)

    def close_inbound(self) -> None:
        self.reader.feed_eof()
        self.writer.close()

    async def iter_outbound(self) -> AsyncIterator[bytes]:
        """Async iterator over outbound JSON-RPC lines for the SSE event stream.
        Terminates when the writer is closed."""
        while True:
            item = await self._outbound.get()
            if item is None:
                return
            yield item


class SseServerStream:
    """Upstream side: Tripwire as a client of a remote SSE-transport MCP server.

    Lifecycle is async-context-managed. ``__aenter__`` opens an ``httpx``
    client and starts a background task subscribing to ``{url}/events`` via
    ``httpx-sse``; ``__aexit__`` tears both down.

    The ``writer`` POSTs each outbound JSON-RPC frame to ``{url}/messages``
    via a per-line fire-and-forget task. Headers passed to the constructor
    are forwarded byte-for-byte on both the POST and the GET (Decision #3).
    """

    def __init__(
        self,
        upstream_url: str,
        *,
        headers: dict[str, str] | None = None,
        on_disconnect: callable | None = None,
    ) -> None:
        self._url = upstream_url.rstrip("/")
        self._headers = dict(headers or {})
        # Operator may pass on_disconnect to clear engine state on upstream drop.
        # RFC-0004 §"Reconnect / resume": cache cleared so no stale-state survives.
        self._on_disconnect = on_disconnect
        self.reader: asyncio.StreamReader = asyncio.StreamReader()
        self._client = None
        self._sse_task: asyncio.Task | None = None
        self._post_queue: asyncio.Queue = asyncio.Queue()
        self._post_task: asyncio.Task | None = None
        self.writer = _QueueWriter(self._post_queue)
        self.disconnected: bool = False

    async def __aenter__(self) -> SseServerStream:
        import httpx  # lazy — keeps the module importable without httpx

        # Timeout(None) for connect would block forever on a missing upstream; an explicit
        # generous per-stage budget keeps a stuck upstream from wedging the gateway
        # (Decision #9: gateway readiness != upstream readiness).
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=30.0, read=None, write=30.0, pool=30.0),
            headers=self._headers,
        )  # noqa: S113
        self._sse_task = asyncio.create_task(self._sse_loop(), name="sse-upstream-events")
        self._post_task = asyncio.create_task(self._post_loop(), name="sse-upstream-post")
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.writer.close()
        for t in (self._sse_task, self._post_task):
            if t is None:
                continue
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: BLE001, S110 - shutdown cleanup; ok to swallow
                pass
        if self._client is not None:
            await self._client.aclose()

    async def _sse_loop(self) -> None:
        """RFC-0004 Decision #2: reconnect ONCE on drop, then give up. On
        terminal failure, EOF the reader so the bridge stops cleanly and fire
        the on_disconnect callback so the engine can clear its `_live_tools`
        cache (no stale state survives a cleanly-failed connection)."""
        import httpx
        from httpx_sse import aconnect_sse  # lazy

        for attempt in (1, 2):  # initial connect + one reconnect
            try:
                async with aconnect_sse(
                    self._client, "GET", f"{self._url}/events", headers=self._headers
                ) as es:
                    async for event in es.aiter_sse():
                        if event.event != "message":
                            continue
                        # Each SSE 'data:' becomes one line into the reader.
                        self.reader.feed_data((event.data + "\n").encode())
                # Clean end of stream — no reconnect needed.
                self.reader.feed_eof()
                self._signal_disconnect()
                return
            except asyncio.CancelledError:
                raise
            except (httpx.HTTPError, OSError):
                if attempt == 1:
                    # One reconnect attempt, then fall through to giving up.
                    continue
                break
        # Both attempts failed (or the clean stream ended via exception path).
        self.reader.feed_eof()
        self._signal_disconnect()

    def _signal_disconnect(self) -> None:
        if not self.disconnected:
            self.disconnected = True
            if self._on_disconnect is not None:
                try:
                    self._on_disconnect()
                except Exception:  # noqa: BLE001, S110 - callback hygiene
                    pass

    async def _post_loop(self) -> None:
        while True:
            line = await self._post_queue.get()
            if line is None:
                return
            await self._client.post(f"{self._url}/messages", content=line, headers=self._headers)
