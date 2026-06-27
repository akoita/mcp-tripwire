"""MCP-Tripwire proxy demo — the bridge version of the proof moment.

Run:  make demo   (or)   PYTHONPATH=src python3 examples/demo_proxy.py

Where `demo.py` shows the engine-level A/B (poisoned tool refused at approval,
rug-pull caught by `evaluate_call`, badge tamper-evident), THIS script shows
the same story through the real `StdioTripwireProxy.serve()` bridge against
the vulnerable MCP server subprocess. Same code path as a production deploy.

Three sections:
  A) Without Tripwire — the vulnerable server's tools/list is observed raw;
     the poisoned tool is visible to the client.
  B) With Tripwire   — the same tools/list goes through the proxy: poisoned
     stripped, clean badged.
  C) Rug pull        — trigger _admin/mutate on the upstream, re-list (drift
     detected, clean tool now stripped too), then tools/call the rug-pulled
     tool → proxy short-circuits with JSON-RPC error -32001.

SAFETY (Hard Rule #4): canary-labelled secret + local sink; no real
credentials are read or transmitted at any point.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tripwire import TripwireEngine  # noqa: E402
from tripwire.proxy import TRIPWIRE_ERROR_CODE, StdioTripwireProxy  # noqa: E402

VULN_SERVER = REPO / "examples" / "vulnerable_mcp_server.py"


def rule(title: str) -> None:
    print(f"\n{'─' * 64}\n{title}\n{'─' * 64}")


class _QueueWriter:
    """Minimal StreamWriter-shaped adapter that flows writes into an asyncio.Queue.

    Same shape as the integration test's adapter — letting the demo drive the
    bridge with in-memory pipes instead of attaching to real stdio (which would
    require a parent process holding the other end).
    """

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


async def _direct_tools_list() -> list[dict]:
    """Section A: talk to the vulnerable server WITHOUT the proxy, so we see
    what a naive client would see."""
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(VULN_SERVER),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
    await proc.stdin.drain()
    line = await asyncio.wait_for(proc.stdout.readline(), timeout=5.0)
    proc.stdin.close()
    await proc.wait()
    return json.loads(line)["result"]["tools"]


async def _proxied_session():
    """Spin up vulnerable_mcp_server through the bridge with in-memory pipes
    on the client side. Returns (send, recv, shutdown)."""
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(VULN_SERVER),
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

    feeders = [
        asyncio.create_task(feed(client_in_q, client_in_reader)),
        asyncio.create_task(feed(client_out_q, client_out_reader)),
    ]

    engine = TripwireEngine(os.environ.get("TRIPWIRE_SIGNING_KEY", "demo-only"))
    proxy = StdioTripwireProxy(engine)
    # Quiet the structured stderr log for the demo narrative; production users
    # can pass `log=sys.stderr` to see one JSON line per block/quarantine event.
    bridge = asyncio.create_task(
        proxy.bridge(
            client_reader=client_in_reader,
            client_writer=_QueueWriter(client_out_q),  # type: ignore[arg-type]
            server_reader=proc.stdout,
            server_writer=proc.stdin,
            log=io.StringIO(),
        )
    )

    def send(msg: dict) -> None:
        client_in_q.put_nowait((json.dumps(msg) + "\n").encode())

    async def recv() -> dict:
        line = await asyncio.wait_for(client_out_reader.readline(), timeout=5.0)
        return json.loads(line)

    async def shutdown() -> None:
        client_in_q.put_nowait(None)
        try:
            await asyncio.wait_for(bridge, timeout=2.0)
        except TimeoutError:
            bridge.cancel()
        if proc.returncode is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
        await proc.wait()
        for t in feeders:
            t.cancel()
        await asyncio.gather(*feeders, return_exceptions=True)

    return send, recv, shutdown


async def run() -> int:
    print("MCP-Tripwire — proxy bridge demo (the production code path)")
    print(f"upstream: {VULN_SERVER.relative_to(REPO)}  (vulnerable model; canary-only)")

    # --- A: without the proxy ------------------------------------------------
    rule("A) WITHOUT Tripwire: the naive client sees the poisoned tool")
    raw = await _direct_tools_list()
    for t in raw:
        marker = " (POISONED)" if "ignore previous instructions" in t["description"].lower() else ""
        print(f"  - {t['name']}{marker}")
    print(f"  total tools advertised: {len(raw)}  (a naive agent might call any of them)")

    # --- B: through the proxy ------------------------------------------------
    rule("B) WITH Tripwire: same upstream, vetted at tools/list")
    send, recv, shutdown = await _proxied_session()
    send({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    listed = await recv()
    approved = listed["result"]["tools"]
    for t in approved:
        badge_ok = t.get("_tripwire_badge") is not None
        print(f"  ✓ {t['name']}  badge={'attached' if badge_ok else 'MISSING'}")
    print(
        f"  approved tools: {[t['name'] for t in approved]}  "
        f"(was {len(raw)}; proxy stripped {len(raw) - len(approved)})"
    )

    # --- C: rug pull ---------------------------------------------------------
    rule("C) Rug pull: upstream mutates after approval; proxy quarantines")
    send({"jsonrpc": "2.0", "id": 2, "method": "_admin/mutate"})
    await recv()  # server ack
    send({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    relisted = await recv()
    survivors = [t["name"] for t in relisted["result"]["tools"]]
    print(f"  re-list after mutation → approved: {survivors}  (clean tool now drifted)")
    send(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "get_weather", "arguments": {"city": "Paris"}},
        }
    )
    call_resp = await recv()
    err = call_resp.get("error") or {}
    if err.get("code") == TRIPWIRE_ERROR_CODE:
        meta = err.get("data", {}).get("tripwire", {})
        print(
            f"  tools/call → JSON-RPC error {err['code']}: "
            f"action={meta.get('action')!r} tool={meta.get('tool')!r}  ✅"
        )
    else:
        print(f"  UNEXPECTED: call was NOT short-circuited; response was {call_resp}")
        await shutdown()
        return 1
    await shutdown()

    print(
        "\nSummary: poisoned stripped at tools/list · rug-pull caught at tools/call · "
        "engine + bridge same code path."
    )
    return 0


def main() -> int:
    return asyncio.run(run())


if __name__ == "__main__":
    raise SystemExit(main())
