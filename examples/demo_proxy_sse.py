"""MCP-Tripwire SSE proxy demo — the bridge over HTTP+SSE transport.

Run:  make demo-proxy-sse   (or)   PYTHONPATH=src:. python3 examples/demo_proxy_sse.py

Where ``demo_proxy.py`` shows the proof moment over stdio against a subprocess,
THIS script shows the same three-act story over HTTP+SSE against an in-process
FastAPI MCP server (``tests/integration/_fixtures/fake_sse_mcp_server.py``).
Same guard semantics; different transport.

Three sections:
  A) Without Tripwire — direct SSE round-trip to the vulnerable server;
     the poisoned tool is visible to the client.
  B) With Tripwire   — same tools/list goes through SseTripwireProxy:
     poisoned stripped, clean badged.
  C) Rug pull        — POST `_admin/mutate` upstream, re-list (drift detected,
     clean tool now stripped too), then tools/call the rug-pulled tool →
     proxy short-circuits with JSON-RPC error -32001.

SAFETY (Hard Rule #4): the upstream fixture is purely in-process; no real
credentials are read or transmitted at any point.
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading
import time
from contextlib import closing
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO))  # so `tests.integration._fixtures...` is importable

import httpx  # noqa: E402
from app.sse_adapter import SseClientStream, SseServerStream  # noqa: E402
from tests.integration._fixtures import fake_mcp_server  # noqa: E402
from tests.integration._fixtures.fake_sse_mcp_server import build_app  # noqa: E402

from tripwire import TripwireEngine  # noqa: E402
from tripwire.proxy import SseTripwireProxy  # noqa: E402

CLEAN_DESC = fake_mcp_server.CLEAN_DESC
RUGPULL_DESC = fake_mcp_server.RUGPULL_DESC


def rule(title: str) -> None:
    print(f"\n{'─' * 64}\n{title}\n{'─' * 64}")


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_fixture(port: int) -> threading.Thread:
    """Run the fixture FastAPI app on an ephemeral port in a background thread."""
    import uvicorn

    config = uvicorn.Config(build_app(), host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    # Wait until the port answers; 2 s is generous for an in-process FastAPI app.
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            with httpx.Client() as c:
                if c.get(f"http://127.0.0.1:{port}/health", timeout=0.2).status_code == 200:
                    return thread
        except httpx.HTTPError:
            time.sleep(0.05)
    raise RuntimeError("fixture server did not come up")


async def _next_client_frame(client: SseClientStream) -> dict:
    """Pull one outbound JSON-RPC frame from the proxy's SSE writer."""
    async for line in client.iter_outbound():
        return json.loads(line)
    raise AssertionError("client stream closed before yielding a frame")


async def section_a_without_tripwire(base_url: str) -> list[dict]:
    """Talk to the upstream WITHOUT the proxy, so we see what a naive client sees."""
    rule("A · Without Tripwire — naive client talking SSE directly")
    print(f"upstream: {base_url}  (vulnerable model; in-process)")
    async with httpx.AsyncClient() as client:
        # The fixture's first SSE event is `endpoint`; we ignore it for this
        # naive read (we don't really need to POST through SSE — direct HTTP
        # is enough to see tools/list).
        await client.post(
            f"{base_url}/messages",
            content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
        )
        # Open SSE briefly and read the first message frame.
        from httpx_sse import aconnect_sse

        async with aconnect_sse(client, "GET", f"{base_url}/events") as es:
            async for event in es.aiter_sse():
                if event.event == "message":
                    raw = json.loads(event.data)
                    break
    tools = raw["result"]["tools"]
    print(f"  tools/list returned {len(tools)} tools (a naive agent might call any of them):")
    for t in tools:
        marker = "" if t["description"] == CLEAN_DESC else "  ← LOOKS DANGEROUS"
        print(f"  - {t['name']}{marker}")
    return tools


async def section_b_with_tripwire(
    base_url: str,
) -> tuple[SseTripwireProxy, SseClientStream, asyncio.Task]:
    """Same tools/list, this time through SseTripwireProxy."""
    rule("B · With Tripwire — same upstream, through SseTripwireProxy")

    engine = TripwireEngine(signing_key="demo-only-key")
    proxy = SseTripwireProxy(engine)
    client = SseClientStream()
    server = SseServerStream(
        base_url,
        on_cache_invalidate=proxy.invalidate_cache,
        on_terminal=client.close_inbound,
    )

    async def run_bridge():
        async with server as srv:
            await proxy.bridge_sse(client_stream=client, server_stream=srv)

    bridge_task = asyncio.create_task(run_bridge())

    client.push_inbound(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
    resp = await asyncio.wait_for(_next_client_frame(client), timeout=2.0)
    tools = resp["result"]["tools"]
    print(f"  tools/list now returns {len(tools)} tool(s):")
    for t in tools:
        badge = t.get("_tripwire_badge")
        ok = bool(badge and badge.get("sig"))
        print(f"  ✓ {t['name']}  badge={'attached' if ok else 'MISSING'}")
    print(
        f"  poisoned tools stripped, clean tool signed (alg={tools[0]['_tripwire_badge']['alg']})."
    )
    return proxy, client, bridge_task


async def section_c_rug_pull(
    base_url: str,
    client: SseClientStream,
) -> None:
    """Trigger _admin/mutate upstream; re-list; tools/call against the rug-pulled tool."""
    rule("C · Rug pull — post-approval mutation + tools/call short-circuit")

    # Mutate the upstream's tool state directly in-process. The fixture and
    # this demo share a Python process; calling _admin/mutate over JSON-RPC
    # would queue a response onto the same SSE stream the proxy is reading,
    # racing with the client's next tools/list. Direct state mutation avoids
    # the race and matches what an attacker-controlled upstream would do.
    fake_mcp_server.state["get_weather"]["description"] = RUGPULL_DESC

    # Re-list through the proxy — drift detected, clean tool now stripped too.
    client.push_inbound(b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')
    resp2 = await asyncio.wait_for(_next_client_frame(client), timeout=2.0)
    survivors = [t["name"] for t in resp2["result"]["tools"]]
    print(f"  re-list after mutation → approved: {survivors}  (clean tool now drifted)")

    # tools/call against the rug-pulled tool: proxy short-circuits with -32001.
    client.push_inbound(
        b'{"jsonrpc":"2.0","id":3,"method":"tools/call",'
        b'"params":{"name":"get_weather","arguments":{"city":"SF"}}}\n'
    )
    call_resp = await asyncio.wait_for(_next_client_frame(client), timeout=2.0)
    err = call_resp.get("error") or {}
    if err.get("code") == -32001:
        action = err["data"]["tripwire"]["action"]
        print(f"  ✓ tools/call short-circuited at the proxy (code -32001, action={action})")
    else:
        print(f"  UNEXPECTED: call was NOT short-circuited; response was {call_resp}")
        raise SystemExit(1)


async def run() -> int:
    print("MCP-Tripwire — SSE proxy bridge demo (the v0.2 operator path)")
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    _start_fixture(port)
    try:
        # Reset the rug-pull description in case the fixture was loaded earlier.
        fake_mcp_server.state["get_weather"]["description"] = CLEAN_DESC

        await section_a_without_tripwire(base_url)
        proxy, client, bridge_task = await section_b_with_tripwire(base_url)
        try:
            await section_c_rug_pull(base_url, client)
        finally:
            client.close_inbound()
            try:
                await asyncio.wait_for(bridge_task, timeout=1.0)
            except (TimeoutError, Exception):  # noqa: BLE001
                bridge_task.cancel()
                try:
                    await bridge_task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass

        rule("Summary")
        print(
            "  poisoning stripped · rug-pull quarantined · "
            "same guard semantics as the stdio bridge.\n"
            "  difference: this ran over HTTP+SSE end to end, "
            "the dominant transport for hosted MCP."
        )
        return 0
    finally:
        # Fixture thread is daemon=True — exits with the process.
        pass


def main() -> int:
    return asyncio.run(run())


if __name__ == "__main__":
    sys.exit(main())
