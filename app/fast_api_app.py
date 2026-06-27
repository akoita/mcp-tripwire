"""Cloud Run entrypoint: `uvicorn app.fast_api_app:app` (course Day-5 convention).

Currently exposes a health endpoint and reserves the HTTP/SSE gateway mount for P1.
Telemetry is configured first so Cloud Trace + GenAI logging can carry over.
"""

from __future__ import annotations

from app.app_utils.telemetry import setup_telemetry

setup_telemetry()

try:
    from fastapi import FastAPI
except ImportError as exc:  # pragma: no cover - only at deploy time
    raise RuntimeError("Install the served gateway deps: uv sync --extra agent") from exc

app = FastAPI(title="MCP-Tripwire Gateway", version="0.1.0")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "mcp-tripwire"}


# STUB(E2): mount the transparent MCP gateway (stdio→HTTP/SSE) ASGI app here,
# wiring tripwire.proxy.StdioTripwireProxy in front of the configured upstream server(s).
