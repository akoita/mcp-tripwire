"""Real MCP demo: Tripwire in front of Microsoft Playwright MCP.

Run:
    make demo-real-mcp

This demo intentionally uses a real, published MCP server instead of the local
vulnerable fixture. It proves the happy path that matters for adoption:

1. Start Playwright MCP via `npx @playwright/mcp@latest`.
2. Route JSON-RPC through StdioTripwireProxy.
3. Vet the server's real browser-automation tool descriptors.
4. Call `browser_navigate` through the proxy against https://example.com.

If the browser binary is missing, run:
    npx -y @playwright/mcp@latest install-browser chrome-for-testing
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tripwire import TripwireEngine  # noqa: E402
from tripwire.proxy import StdioTripwireProxy  # noqa: E402

MCP_PROTOCOL_VERSION = "2025-06-18"
PLAYWRIGHT_COMMAND = ["npx", "-y", "@playwright/mcp@latest"]
TARGET_URL = "https://example.com"


def rule(title: str) -> None:
    print(f"\n{'-' * 72}\n{title}\n{'-' * 72}")


class _QueueWriter:
    """Small StreamWriter-shaped adapter for in-memory client pipes."""

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


async def _feed(queue: asyncio.Queue[bytes | None], reader: asyncio.StreamReader) -> None:
    while True:
        chunk = await queue.get()
        if chunk is None:
            reader.feed_eof()
            return
        reader.feed_data(chunk)


async def _proxied_playwright_session(output_dir: str):
    """Start Playwright MCP behind Tripwire and return send/recv/shutdown helpers."""
    command = [
        *PLAYWRIGHT_COMMAND,
        "--headless",
        "--isolated",
        "--browser",
        "chromium",
        "--output-dir",
        output_dir,
    ]
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(REPO),
    )
    assert proc.stdin is not None and proc.stdout is not None

    client_in_reader = asyncio.StreamReader()
    client_in_q: asyncio.Queue[bytes | None] = asyncio.Queue()
    client_out_reader = asyncio.StreamReader()
    client_out_q: asyncio.Queue[bytes | None] = asyncio.Queue()

    feeders = [
        asyncio.create_task(_feed(client_in_q, client_in_reader)),
        asyncio.create_task(_feed(client_out_q, client_out_reader)),
    ]

    engine = TripwireEngine(signing_key=os.environ.get("TRIPWIRE_SIGNING_KEY", "demo-only"))
    proxy = StdioTripwireProxy(engine)
    log = io.StringIO()
    bridge = asyncio.create_task(
        proxy.bridge(
            client_reader=client_in_reader,
            client_writer=_QueueWriter(client_out_q),  # type: ignore[arg-type]
            server_reader=proc.stdout,
            server_writer=proc.stdin,
            log=log,
        )
    )

    def send(msg: dict[str, Any]) -> None:
        client_in_q.put_nowait((json.dumps(msg, separators=(",", ":")) + "\n").encode())

    async def recv(timeout: float = 30.0) -> dict[str, Any]:
        line = await asyncio.wait_for(client_out_reader.readline(), timeout=timeout)
        if not line:
            stderr = await proc.stderr.read()
            raise RuntimeError(
                "Playwright MCP closed before responding"
                + (f": {stderr.decode(errors='replace')[:800]}" if stderr else "")
            )
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
        for task in feeders:
            task.cancel()
        await asyncio.gather(*feeders, return_exceptions=True)

    return send, recv, shutdown


def _extract_text(resp: dict[str, Any]) -> str:
    content = resp.get("result", {}).get("content", [])
    parts = [item.get("text", "") for item in content if isinstance(item, dict)]
    return "\n".join(parts)


def _print_browser_missing_hint(text: str) -> None:
    if "is not installed" not in text:
        return
    print("\nPlaywright MCP is installed, but its browser binary is missing.")
    print("Run this once, then retry the demo:")
    print("  npx -y @playwright/mcp@latest install-browser chrome-for-testing")


async def run() -> int:
    print("MCP-Tripwire — real MCP demo with Microsoft Playwright MCP")
    print("upstream: npx @playwright/mcp@latest --headless --isolated")
    print(f"target page: {TARGET_URL}")

    with tempfile.TemporaryDirectory(prefix="tripwire-playwright-mcp-") as output_dir:
        send, recv, shutdown = await _proxied_playwright_session(output_dir)
        try:
            rule("A) Initialize the real MCP server through Tripwire")
            send(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {
                            "name": "mcp-tripwire-real-mcp-demo",
                            "version": "0.1.0",
                        },
                    },
                }
            )
            init = await recv()
            server = init.get("result", {}).get("serverInfo", {})
            print(
                f"  connected to {server.get('name', 'unknown')} {server.get('version', 'unknown')}"
            )
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})

            rule("B) Vet the real Playwright tool catalog")
            send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            listed = await recv()
            tools = listed.get("result", {}).get("tools", [])
            badged = [t for t in tools if isinstance(t, dict) and t.get("_tripwire_badge")]
            names = [t.get("name") for t in tools if isinstance(t, dict)]
            print(f"  tools approved by Tripwire: {len(tools)}")
            print(f"  tools carrying trust badges: {len(badged)}")
            print("  sample approved tools:")
            for name in names[:8]:
                print(f"    - {name}")

            if "browser_navigate" not in names:
                print("  browser_navigate was not advertised; cannot prove live navigation.")
                return 1

            rule("C) Execute a real browser navigation through the proxy")
            send(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "browser_navigate",
                        "arguments": {"url": TARGET_URL},
                    },
                }
            )
            nav = await recv(timeout=45.0)
            text = _extract_text(nav)
            if nav.get("result", {}).get("isError"):
                print(text)
                _print_browser_missing_hint(text)
                return 2
            print("  upstream tool call reached Playwright MCP and returned:")
            for line in text.splitlines():
                if "Page URL:" in line or "Page Title:" in line:
                    print(f"  {line}")
            if "Example Domain" not in text:
                print("  expected live page title was not present in the tool response.")
                return 1

            rule("Summary")
            print("  real MCP server: Playwright MCP")
            print("  real tool catalog: approved and badged by Tripwire")
            print("  real web action: browser_navigate reached https://example.com")
            print("  why it matters: Tripwire can sit in front of useful MCPs, not just fixtures.")
            return 0
        finally:
            await shutdown()


def main() -> int:
    return asyncio.run(run())


if __name__ == "__main__":
    raise SystemExit(main())
