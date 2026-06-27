"""End-to-end test for the E2 stdio bridge.

Spawns the test-double MCP server (a stdlib-only Python subprocess that speaks
line-delimited JSON-RPC), points the proxy at it via in-memory pipes from the
client side, and exercises both proof moments:

  1. ``tools/list`` -> poisoned tool stripped, clean tool badged.
  2. ``_admin/mutate`` (server-side flip) -> re-list -> clean tool now quarantined.
  3. ``tools/call`` against the rug-pulled clean tool -> JSON-RPC error -32001.

The test stays inside a single asyncio event loop driven by ``asyncio.run`` so
we don't take on a ``pytest-asyncio`` dependency just for this case.
"""

from __future__ import annotations

import asyncio
import io
import json
import sys
from pathlib import Path

from tripwire import TripwireEngine
from tripwire.proxy import TRIPWIRE_ERROR_CODE, StdioTripwireProxy

FIXTURE = Path(__file__).parent / "_fixtures" / "fake_mcp_server.py"


class _QueueWriter:
    """Minimal StreamWriter-shaped adapter that flows writes into an asyncio.Queue."""

    def __init__(self, q: asyncio.Queue[bytes | None]) -> None:
        self._q = q
        self._closed = False

    def write(self, data: bytes) -> None:
        self._q.put_nowait(data)

    async def drain(self) -> None:
        return

    def close(self) -> None:
        self._closed = True
        self._q.put_nowait(None)

    def is_closing(self) -> bool:
        return self._closed


async def _run_session() -> tuple[list[dict], str]:
    """Run the full client conversation against a proxied subprocess.

    Returns the four responses and the captured stderr log text.
    """
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(FIXTURE),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )
    assert proc.stdin is not None and proc.stdout is not None

    client_in_reader = asyncio.StreamReader()
    client_in_q: asyncio.Queue[bytes | None] = asyncio.Queue()
    client_out_reader = asyncio.StreamReader()
    client_out_q: asyncio.Queue[bytes | None] = asyncio.Queue()

    async def feed(queue: asyncio.Queue[bytes | None], reader: asyncio.StreamReader) -> None:
        while True:
            chunk = await queue.get()
            if chunk is None:
                reader.feed_eof()
                return
            reader.feed_data(chunk)

    feeder_in = asyncio.create_task(feed(client_in_q, client_in_reader))
    feeder_out = asyncio.create_task(feed(client_out_q, client_out_reader))

    engine = TripwireEngine("k")
    proxy = StdioTripwireProxy(engine)
    log_buf = io.StringIO()
    bridge_task = asyncio.create_task(
        proxy.bridge(
            client_reader=client_in_reader,
            client_writer=_QueueWriter(client_out_q),  # type: ignore[arg-type]
            server_reader=proc.stdout,
            server_writer=proc.stdin,
            log=log_buf,
        )
    )

    def send(msg: dict) -> None:
        client_in_q.put_nowait((json.dumps(msg) + "\n").encode())

    async def recv() -> dict:
        line = await asyncio.wait_for(client_out_reader.readline(), timeout=2.0)
        return json.loads(line)

    responses: list[dict] = []

    # (1) list -> poisoned stripped, clean badged
    send({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    responses.append(await recv())

    # (2) server-side mutate (passes through; not interpreted by proxy)
    send({"jsonrpc": "2.0", "id": 2, "method": "_admin/mutate"})
    responses.append(await recv())

    # (3) re-list -> rug-pulled tool detected as drift
    send({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    responses.append(await recv())

    # (4) call the rug-pulled tool -> tripwire error
    send(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "get_weather", "arguments": {"city": "Paris"}},
        }
    )
    responses.append(await recv())

    # Teardown
    client_in_q.put_nowait(None)
    try:
        await asyncio.wait_for(bridge_task, timeout=2.0)
    except TimeoutError:
        bridge_task.cancel()
    if proc.returncode is None:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
    await proc.wait()
    feeder_in.cancel()
    feeder_out.cancel()
    await asyncio.gather(feeder_in, feeder_out, return_exceptions=True)
    return responses, log_buf.getvalue()


def test_bridge_strips_poisoned_and_quarantines_rug_pull():
    responses, log_text = asyncio.run(_run_session())
    list_resp, mutate_resp, relist_resp, call_resp = responses

    # (1) poisoned stripped, clean badged
    tools = list_resp["result"]["tools"]
    assert [t["name"] for t in tools] == ["get_weather"]
    assert tools[0]["_tripwire_badge"] is not None

    # (2) mutation acknowledged by the server (proxy is transparent for _admin/*)
    assert mutate_resp["result"] == {"mutated": True}

    # (3) re-list now shows nothing approved (clean drifted, summary still poisoned)
    assert relist_resp["result"]["tools"] == []

    # (4) tools/call against the cached rug-pulled descriptor is short-circuited
    assert call_resp["error"]["code"] == TRIPWIRE_ERROR_CODE
    assert call_resp["error"]["data"]["tripwire"]["action"] == "quarantine"
    assert call_resp["error"]["data"]["tripwire"]["tool"] == "get_weather"

    # Structured stderr log contains the quarantine event
    assert '"action": "quarantine"' in log_text
