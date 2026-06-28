"""HTTP gateway SSE mount tests — RFC-0004 test plan group 7.

End-to-end SSE traffic through the mount (talking to a real fake_sse_mcp_server
upstream) is more than this slot's scope — that needs a uvicorn-in-thread
fixture. This file covers the gateway's own behavior:

- Decision #9: with no TRIPWIRE_UPSTREAM_SSE_URL, both `/mcp/sse/events`
  and `/mcp/sse/messages` return 503 with a non-secret diagnostic;
  `/healthz` keeps reporting the gateway process is alive.
- Decision #7: env-gated mount surface (endpoint exists either way; the
  503 distinguishes "not configured" from "404 not found").
- Session error path: POST /mcp/sse/messages?session=unknown → 404.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sse_starlette")

from app.fast_api_app import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(app)


def test_healthz_is_independent_of_upstream_configuration(monkeypatch: pytest.MonkeyPatch):
    """Decision #9: /healthz reports the gateway process, NOT the upstream."""
    monkeypatch.delenv("TRIPWIRE_UPSTREAM_SSE_URL", raising=False)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_mcp_sse_events_returns_503_without_upstream(monkeypatch: pytest.MonkeyPatch):
    """Without TRIPWIRE_UPSTREAM_SSE_URL: 503 with a non-secret diagnostic.

    Httpx TestClient surfaces the HTTPException as a regular response.
    """
    monkeypatch.delenv("TRIPWIRE_UPSTREAM_SSE_URL", raising=False)
    resp = client.get("/mcp/sse/events")
    assert resp.status_code == 503
    body = resp.json()
    assert "TRIPWIRE_UPSTREAM_SSE_URL" in body["detail"]
    # Must NOT leak secrets/credentials in the diagnostic.
    assert "SIGNING_KEY" not in body["detail"]
    assert "PRIVATE_KEY" not in body["detail"]


def test_mcp_sse_messages_returns_503_without_upstream(monkeypatch: pytest.MonkeyPatch):
    """Same 503 contract on the POST endpoint."""
    monkeypatch.delenv("TRIPWIRE_UPSTREAM_SSE_URL", raising=False)
    resp = client.post(
        "/mcp/sse/messages?session=anything",
        content=b'{"jsonrpc":"2.0","id":1,"method":"initialize"}',
    )
    assert resp.status_code == 503
    assert "TRIPWIRE_UPSTREAM_SSE_URL" in resp.json()["detail"]


def test_mcp_sse_messages_404_on_unknown_session(monkeypatch: pytest.MonkeyPatch):
    """Upstream configured but session id doesn't exist → 404 (not 503)."""
    monkeypatch.setenv("TRIPWIRE_UPSTREAM_SSE_URL", "http://configured-but-unreachable.local")
    resp = client.post(
        "/mcp/sse/messages?session=does-not-exist",
        content=b'{"jsonrpc":"2.0","id":1,"method":"initialize"}',
    )
    assert resp.status_code == 404
    assert "unknown session" in resp.json()["detail"]
