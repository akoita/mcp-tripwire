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

    def __init__(self, queue: asyncio.Queue, *, on_full: callable | None = None) -> None:
        self._q = queue
        self._closed = False
        self._buf = b""
        # Codex P2 round 2: bounded queues need a real backpressure escape.
        # write() is sync (asyncio.StreamWriter shape), so we can't await;
        # we DROP+terminate when the queue is full to avoid OOM. The owner
        # passes `on_full` to convert a full queue into a session-terminal
        # signal (cache-invalidate + EOF).
        self._on_full = on_full

    def write(self, data: bytes) -> None:
        if self._closed:
            return
        self._buf += data
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue
            try:
                self._q.put_nowait(line)
            except asyncio.QueueFull:
                # Bounded queue full → stall in the consumer. Convert into a
                # terminal signal so the bridge stops feeding into a dead end.
                self._closed = True
                if self._on_full is not None:
                    try:
                        self._on_full()
                    except Exception:  # noqa: BLE001, S110
                        pass
                return

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


# Bounded-queue size (Codex P2 round 2). 1024 in-flight frames per direction
# is generous for MCP traffic; if a slow client or stalled upstream blows
# through it, _QueueWriter treats it as a session-terminal signal.
_MAX_QUEUE_FRAMES = 1024


class SseClientStream:
    """Inbound side: one client connected over SSE/HTTP.

    The ``reader`` is fed by ``POST /messages`` (one JSON-RPC frame per request
    body — call ``push_inbound(body)`` from the handler). The ``writer``
    captures server→client frames; ``iter_outbound()`` yields each one for the
    SSE event stream to emit as ``event: message``.
    """

    def __init__(self) -> None:
        self.reader: asyncio.StreamReader = asyncio.StreamReader()
        self._outbound: asyncio.Queue = asyncio.Queue(maxsize=_MAX_QUEUE_FRAMES)
        # If the outbound queue fills (slow SSE consumer), terminate cleanly.
        self.writer = _QueueWriter(self._outbound, on_full=self.close_inbound)
        # Codex P2 round 2: track "closed" so a late POST can be rejected
        # cleanly instead of hitting `feed_data after feed_eof` → AssertionError.
        self._closed = False

    def push_inbound(self, frame_bytes: bytes) -> bool:
        """Feed a single JSON-RPC frame into the reader. Returns False if the
        session is already closed (caller should respond 410)."""
        if self._closed:
            return False
        if not frame_bytes.endswith(b"\n"):
            frame_bytes = frame_bytes + b"\n"
        self.reader.feed_data(frame_bytes)
        return True

    def close_inbound(self) -> None:
        """Idempotent close — safe to call from POST-full path AND on_terminal."""
        if self._closed:
            return
        self._closed = True
        self.reader.feed_eof()
        self.writer.close()

    @property
    def closed(self) -> bool:
        return self._closed

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
        on_cache_invalidate: callable | None = None,
        on_terminal: callable | None = None,
    ) -> None:
        self._url = upstream_url.rstrip("/")
        self._headers = dict(headers or {})
        # Two separate callbacks (Codex review of slot 5):
        #   on_cache_invalidate fires on EVERY upstream drop, including before
        #     a reconnect attempt — so the proxy's _live_tools is cleared and
        #     the fresh-stream tools/list rebuilds it. RFC §"Reconnect" + #8.
        #   on_terminal fires exactly once when the connection is over for good
        #     (both reconnect attempts exhausted, or clean end of stream) —
        #     for stream-close cleanup at the gateway layer.
        self._on_cache_invalidate = on_cache_invalidate
        self._on_terminal = on_terminal
        self.reader: asyncio.StreamReader = asyncio.StreamReader()
        self._client = None
        self._sse_task: asyncio.Task | None = None
        self._post_queue: asyncio.Queue = asyncio.Queue(maxsize=_MAX_QUEUE_FRAMES)
        self._post_task: asyncio.Task | None = None
        # MCP HTTP+SSE 2024-11-05 spec (Codex P1 round 2): the upstream
        # advertises the POST URL via the first SSE `event: endpoint, data:
        # <url>` frame. Real upstreams use session-scoped URLs like
        # `/messages?sessionId=...`; hardcoding `/messages` made us
        # interoperable only with naive fixtures. We capture the URL on the
        # endpoint event and gate _post_loop on it being set.
        self._post_url: str | None = None
        self._post_url_ready: asyncio.Event = asyncio.Event()
        # Stalled upstream POST path → bounded queue fills → treat as terminal.
        self.writer = _QueueWriter(self._post_queue, on_full=self._on_post_queue_full)
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
        """RFC-0004 Decision #2: reconnect ONCE on drop, then give up. On every
        drop (including before reconnect), fire on_cache_invalidate so the
        proxy's _live_tools clears and a fresh tools/list rebuilds it (RFC
        §"Reconnect" + Decision #8 — no stale state survives a cleanly-failed
        connection). At terminal end (clean EOF or both attempts exhausted)
        feed_eof + fire on_terminal so the gateway can close the client stream.
        """
        import httpx
        from httpx_sse import aconnect_sse  # lazy

        for attempt in (1, 2):  # initial connect + one reconnect
            try:
                async with aconnect_sse(
                    self._client, "GET", f"{self._url}/events", headers=self._headers
                ) as es:
                    async for event in es.aiter_sse():
                        if event.event == "endpoint":
                            # MCP spec: this `data:` is the URL clients POST to
                            # for this session. May be absolute or relative to
                            # the SSE base. Resolve against the SSE URL.
                            self._post_url = str(httpx.URL(f"{self._url}/events").join(event.data))
                            self._post_url_ready.set()
                        elif event.event == "message":
                            # Each SSE `data:` becomes one line into the reader.
                            self.reader.feed_data((event.data + "\n").encode())
                        # Other event types (heartbeat, etc.) silently ignored.
                # Clean end of stream — terminal.
                break
            except asyncio.CancelledError:
                raise
            except (httpx.HTTPError, OSError):
                # The upstream just dropped. Cache must clear NOW — a tool
                # approved pre-drop must be re-vetted via the fresh stream's
                # tools/list. Also reset the POST URL — the next stream will
                # advertise its own (possibly different session-scoped) one.
                self._notify_cache_invalidate()
                self._post_url = None
                self._post_url_ready.clear()
                if attempt == 1:
                    continue
                break
        # Stream is over (clean or terminal failure).
        self.reader.feed_eof()
        self._notify_terminal()

    def _notify_cache_invalidate(self) -> None:
        """Fired on every upstream drop. Cleared cache → fresh tools/list."""
        if self._on_cache_invalidate is None:
            return
        try:
            self._on_cache_invalidate()
        except Exception:  # noqa: BLE001, S110 - callback hygiene
            pass

    def _on_post_queue_full(self) -> None:
        """Bounded outbound POST queue filled — treat as terminal upstream issue
        (same as a POST transport error). Avoids unbounded memory growth on a
        stalled upstream while keeping the session-end shape consistent."""
        self._notify_cache_invalidate()
        self.reader.feed_eof()
        self._notify_terminal()

    def _notify_terminal(self) -> None:
        """Fired once when the connection is over for good. Idempotent."""
        if self.disconnected:
            return
        self.disconnected = True
        if self._on_terminal is None:
            return
        try:
            self._on_terminal()
        except Exception:  # noqa: BLE001, S110 - callback hygiene
            pass

    async def _post_loop(self) -> None:
        """Drain the outbound queue, POSTing each line to the URL the upstream
        advertised via its SSE ``endpoint`` event. Waits for that event before
        the first POST — if the upstream never advertises one, _post_loop
        blocks here until ``__aexit__`` cancels the task.

        A transport error on POST is treated as terminal: cache-invalidate +
        EOF + signal terminal so the bridge stops accepting client frames
        into a dead session (instead of hanging).
        """
        import httpx

        while True:
            line = await self._post_queue.get()
            if line is None:
                return
            # Wait until the upstream tells us where to POST (MCP spec, Codex
            # P1 round 2). Cancellation from __aexit__ surfaces as
            # CancelledError, which the surrounding gather/__aexit__ handles.
            await self._post_url_ready.wait()
            try:
                await self._client.post(self._post_url, content=line, headers=self._headers)
            except (httpx.HTTPError, OSError):
                self._notify_cache_invalidate()
                self.reader.feed_eof()
                self._notify_terminal()
                return
