"""Transparent stdio MCP proxy (E2).

Sits between an MCP client and an upstream MCP server (spawned as a subprocess),
intercepting JSON-RPC traffic so every ``tools/list`` is vetted and every
``tools/call`` is checked against the approved fingerprint before it executes.

The deterministic guard methods (`guard_tools_list`, `guard_tool_call`) are unit-
testable in isolation. `serve()` is the asyncio stdio bridge that wires them into
a real subprocess pump — see RFC-0001 for the design.
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from typing import IO

from .engine import Action, Decision, TripwireEngine

# JSON-RPC server error range is -32000..-32099. Tripwire reserves -32001
# for any non-ALLOW decision; distinguish kinds via error.data.tripwire.action.
TRIPWIRE_ERROR_CODE = -32001


@dataclass
class GuardedListResult:
    approved: list[dict]  # tool descriptors that passed vetting (with badges attached)
    blocked: list[Decision]  # tools refused or quarantined


class StdioTripwireProxy:
    """Policy enforcement for a single upstream MCP server."""

    def __init__(self, engine: TripwireEngine) -> None:
        self.engine = engine
        # Live cache: name -> latest descriptor as advertised by the server.
        # Refreshed wholesale on every tools/list response. Used by guard_tool_call
        # so a tools/call request (which only carries name+args) has a schema to
        # re-fingerprint against.
        self._live_tools: dict[str, dict] = {}

    def invalidate_cache(self) -> None:
        """Clear the live-tools cache. Called by SseServerStream on every upstream
        drop so the post-reconnect tools/list rebuilds confidence in current
        advertisements (RFC-0004 §Reconnect / Decision #8). Safe to call any
        time; the next tools/list response will rebuild the cache wholesale."""
        self._live_tools = {}

    # ------------------------------------------------------------------
    # Guard methods (transport-agnostic; covered by unit + integration tests)

    def guard_tools_list(self, tools: list[dict]) -> GuardedListResult:
        """Vet every advertised tool. For tools we've already approved, re-check
        for drift (rug-pull on re-list). For new tools, run full approval.
        Approved tools get a ``_tripwire_badge``; the rest are stripped from
        what the client ever sees."""
        approved: list[dict] = []
        blocked: list[Decision] = []
        for tool in tools:
            # evaluate_call returns REQUIRE_APPROVAL for unknown tools, ALLOW for
            # matched fingerprints, QUARANTINE for drift. Use it to route.
            check = self.engine.evaluate_call(tool)
            if check.action is Action.REQUIRE_APPROVAL:
                decision = self.engine.approve(tool)
            else:
                decision = check
            if decision.allowed:
                badge = decision.badge or self.engine.badge_for(decision.tool)
                approved.append({**tool, "_tripwire_badge": badge})
            else:
                blocked.append(decision)
        return GuardedListResult(approved, blocked)

    def guard_tool_call(self, current_tool: dict) -> Decision:
        """Re-check a tool at call time against its approved fingerprint."""
        return self.engine.evaluate_call(current_tool)

    # ------------------------------------------------------------------
    # Stdio bridge

    async def serve(self, command: list[str], *, log: IO[str] | None = None) -> int:
        """Spawn ``command`` as the upstream MCP server and pump JSON-RPC
        through the guards over real stdio. Returns the subprocess's exit code.

        Thin wrapper around :meth:`bridge` that wires stdin/stdout.
        """
        loop = asyncio.get_running_loop()
        client_reader = asyncio.StreamReader()
        await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(client_reader), sys.stdin)
        transport, protocol = await loop.connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout
        )
        client_writer = asyncio.StreamWriter(transport, protocol, None, loop)
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
        )
        assert proc.stdin is not None and proc.stdout is not None
        try:
            await self.bridge(
                client_reader=client_reader,
                client_writer=client_writer,
                server_reader=proc.stdout,
                server_writer=proc.stdin,
                log=log if log is not None else sys.stderr,
            )
        finally:
            await proc.wait()
        return proc.returncode or 0

    async def bridge(
        self,
        *,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        server_reader: asyncio.StreamReader,
        server_writer: asyncio.StreamWriter,
        log: IO[str],
    ) -> None:
        """Transport-agnostic pump. Runs both directions until either side closes.

        Architecture (RFC-0001):
            client_reader -> [c->s: tools/call short-circuit on non-ALLOW] -> server_writer
            server_reader -> [s->c: tools/list response rewrite + cache  ] -> client_writer
        """
        # Pair request ids to methods so the s->c pump knows which response
        # to rewrite (only tools/list responses need result.tools mangling).
        # Keyed by NORMALIZED id (str|None). Codex P1 round 2: an untrusted
        # upstream could reply with `id: "1"` to a `id: 1` request and bypass
        # the tools/list rewrite branch if we matched by raw object equality.
        pending_methods: dict[object, str] = {}

        async def pump_client_to_server() -> None:
            try:
                async for raw in _iter_lines(client_reader):
                    msg = _try_parse(raw)
                    if msg is None:
                        server_writer.write(raw)
                        await server_writer.drain()
                        continue
                    method = msg.get("method")
                    req_id = msg.get("id")
                    if method == "tools/call":
                        name = (msg.get("params") or {}).get("name")
                        live = self._live_tools.get(name) if isinstance(name, str) else None
                        if live is None:
                            _send(
                                client_writer,
                                _error_response(
                                    req_id,
                                    "tool not present in last tools/list",
                                    {"tripwire": {"action": "require_approval", "tool": name}},
                                ),
                            )
                            await client_writer.drain()
                            _log(log, "require_approval", name, "uncached tool/call")
                            continue
                        decision = self.guard_tool_call(live)
                        if not decision.allowed:
                            _send(
                                client_writer,
                                _error_response(
                                    req_id,
                                    decision.reason,
                                    {
                                        "tripwire": {
                                            "action": decision.action.value,
                                            "tool": decision.tool,
                                            "findings": [f.as_dict() for f in decision.findings],
                                        }
                                    },
                                ),
                            )
                            await client_writer.drain()
                            _log(log, decision.action.value, decision.tool, decision.reason)
                            continue
                    if req_id is not None and method:
                        pending_methods[_normalize_id(req_id)] = method
                    server_writer.write((json.dumps(msg) + "\n").encode())
                    await server_writer.drain()
            except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
                pass
            finally:
                if not server_writer.is_closing():
                    server_writer.close()

        async def pump_server_to_client() -> None:
            try:
                async for raw in _iter_lines(server_reader):
                    msg = _try_parse(raw)
                    if msg is None:
                        client_writer.write(raw)
                        await client_writer.drain()
                        continue
                    req_id = msg.get("id")
                    method = (
                        pending_methods.pop(_normalize_id(req_id), None)
                        if req_id is not None
                        else None
                    )
                    if method == "tools/list" and isinstance(msg.get("result"), dict):
                        tools = msg["result"].get("tools") or []
                        # Refresh the cache with what the server actually sent
                        # BEFORE filtering, so guard_tool_call sees current state.
                        self._live_tools = {
                            t["name"]: t for t in tools if isinstance(t.get("name"), str)
                        }
                        guarded = self.guard_tools_list(tools)
                        msg["result"]["tools"] = guarded.approved
                        for d in guarded.blocked:
                            _log(log, d.action.value, d.tool, d.reason)
                    _send(client_writer, msg)
                    await client_writer.drain()
            except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
                pass

        c2s = asyncio.create_task(pump_client_to_server())
        s2c = asyncio.create_task(pump_server_to_client())
        done, pending = await asyncio.wait({c2s, s2c}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


# ---------------------------------------------------------------------
# Helpers


async def _iter_lines(reader: asyncio.StreamReader):
    while True:
        line = await reader.readline()
        if not line:
            return
        yield line


def _try_parse(raw: bytes) -> dict | None:
    text = raw.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _normalize_id(req_id: object) -> str | None:
    """Canonicalize a JSON-RPC id for routing. Per spec ids are
    string|number|null; an untrusted upstream replying with a different-typed
    id (``"1"`` vs ``1``) MUST NOT route around the tools/list rewrite branch
    or any other id-keyed dispatch. None remains None."""
    if req_id is None:
        return None
    return str(req_id)


def _send(writer: asyncio.StreamWriter, msg: dict) -> None:
    writer.write((json.dumps(msg) + "\n").encode())


def _error_response(req_id: object, message: str, data: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": TRIPWIRE_ERROR_CODE, "message": message, "data": data},
    }


def _log(stream: IO[str], action: str, tool: object, reason: str) -> None:
    stream.write(
        json.dumps({"tripwire": {"action": action, "tool": tool, "reason": reason}}) + "\n"
    )
    stream.flush()


# ---------------------------------------------------------------- SSE variant
# RFC-0004 / #33. SseTripwireProxy is a thin subclass of StdioTripwireProxy
# that drives the same `bridge()` pump with adapter streams instead of stdio
# pipes. All guard logic + state lives in the parent — only the entry point
# (and the implicit contract on stream-shaped objects) is new. The actual
# SSE/HTTP transport work lives in `app/sse_adapter.py` (Decision #5).


class SseTripwireProxy(StdioTripwireProxy):
    """Policy enforcement over SSE/HTTP transport. Same guards as the stdio
    variant; the only difference is the shape of the streams handed to
    ``bridge()``.

    Callers construct adapter streams (``SseClientStream`` for the inbound
    client connection, ``SseServerStream`` for the upstream MCP server) in
    ``app/sse_adapter.py`` and pass them in. Both must expose a ``reader``
    that's an ``asyncio.StreamReader`` and a ``writer`` with the minimal
    ``write / drain / close / is_closing`` shape the bridge uses.
    """

    async def bridge_sse(
        self,
        *,
        client_stream,
        server_stream,
        log: IO[str] | None = None,
    ) -> None:
        """Drive the inherited ``bridge()`` over the adapter streams.

        Both ``client_stream`` and ``server_stream`` are duck-typed to
        ``app.sse_adapter.SseClientStream`` / ``SseServerStream``; the import
        is NOT done here so this module stays free of any ``app`` /
        ``httpx`` reference (Hard Rule #2).
        """
        await self.bridge(
            client_reader=client_stream.reader,
            client_writer=client_stream.writer,
            server_reader=server_stream.reader,
            server_writer=server_stream.writer,
            log=log if log is not None else sys.stderr,
        )
