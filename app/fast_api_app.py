"""Cloud Run entrypoint: `uvicorn app.fast_api_app:app` (course Day-5 convention).

Exposes the deterministic Tripwire core over HTTP so a centralised policy
engine can be reached by CI jobs, batch scanners, or downstream audit
pipelines without each caller installing the SDK locally.

Endpoints:
    GET  /healthz   liveness probe (Cloud Run convention)
    POST /scan      {"tool": {...}} -> scan_tool_descriptor() shape
                    Accept: application/sarif+json -> SARIF 2.1.0 (RFC-0003)
    POST /verify    {"badge": {...}} -> {"valid", "status", "reason", "tool"}
    GET  /eval      runs the default attack corpus -> CorpusResult dict
                    Accept: application/sarif+json -> SARIF 2.1.0 (RFC-0003)

The stdio MCP gateway (transparent bridge for an MCP client to talk through
a deployed Tripwire instance) is a separate, larger surface — tracked in
[STATUS.md](../docs/STATUS.md) and not in scope for this PR.
"""

from __future__ import annotations

import os

from app.app_utils.telemetry import setup_telemetry

setup_telemetry()

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover - only at deploy time
    raise RuntimeError("Install the served gateway deps: uv sync --extra agent") from exc

# The tripwire imports come *after* the fastapi guard so a missing [agent]
# extra fails fast with a clear hint, before pulling stdlib-only modules
# into a process that can't serve them anyway.
from tripwire import attestation  # noqa: E402
from tripwire.agents.scanner_agent import scan_tool_descriptor  # noqa: E402
from tripwire.corpus import load_corpus, run_corpus  # noqa: E402
from tripwire.detection import scan_tool  # noqa: E402
from tripwire.sarif import SarifInput, from_corpus_rows, to_sarif  # noqa: E402

app = FastAPI(
    title="MCP-Tripwire Gateway",
    version="0.1.0",
    description=(
        "Trust gateway for MCP tools: deterministic scan, drift quarantine, "
        "signed attestations. See https://github.com/akoita/mcp-tripwire."
    ),
)


_REQUIRED_BADGE_FIELDS = ("tool", "fingerprint", "sig")
SARIF_MIME = "application/sarif+json"
_EVAL_SIGNING_KEY = "ci-only"


def _wants_sarif(request: Request) -> bool:
    """Return True iff the caller asked for `application/sarif+json` via Accept.

    Conservative: only flips on an exact substring match — `*/*` does NOT
    trigger SARIF (browsers default to that and would otherwise get a
    confusing SARIF blob). Operators opt in explicitly.
    """
    accept = request.headers.get("accept", "")
    return SARIF_MIME in accept


def _signing_key() -> str:
    return os.environ.get("TRIPWIRE_SIGNING_KEY", "")


def _verifier():
    """Resolve a verify-side dispatcher. RFC-0002 #31.

    If any of ``TRIPWIRE_PUBLIC_KEY_PATH`` (Ed25519) or
    ``TRIPWIRE_SIGNING_KEY`` (HMAC) is set, returns a populated
    ``VerifyRegistry`` so a single process accepts a mixed-alg stream.
    Otherwise returns None so ``/verify`` fails closed instead of checking
    badges against a placeholder key.
    """
    from tripwire.signing import resolve_verify_registry

    registry = resolve_verify_registry()
    if registry:
        return registry
    key = _signing_key()
    return key or None


class ScanRequest(BaseModel):
    tool: dict


class VerifyRequest(BaseModel):
    badge: dict


@app.get("/healthz")
def healthz() -> dict:
    """Liveness probe. Used by Cloud Run health-check and local docker run smoke."""
    return {"status": "ok", "service": "mcp-tripwire"}


@app.post("/scan")
def scan(req: ScanRequest, request: Request):
    """Scan an MCP tool descriptor; return findings grouped by OWASP category.

    Default response shape is the dict returned by `scan_tool_descriptor`.
    With `Accept: application/sarif+json` the response is a SARIF 2.1.0
    document (RFC-0003) with `Content-Type: application/sarif+json`.
    """
    if _wants_sarif(request):
        findings = list(scan_tool(req.tool))
        sarif_doc = to_sarif(
            [SarifInput(findings=tuple(findings), input_uri="urn:tripwire:input:http-body")]
        )
        return JSONResponse(content=sarif_doc, media_type=SARIF_MIME)
    return scan_tool_descriptor(req.tool)


@app.post("/verify")
def verify(req: VerifyRequest) -> dict:
    """Verify a signed trust badge. Three outcomes mirror the CLI exit codes.

    Returns:
        valid: bool — true only for a structurally-correct, signature-valid badge.
        status: "valid" | "tampered" | "invalid" — same taxonomy as
            `tripwire verify` (exit codes 0 / 2 / 3).
        reason: human-readable explanation from `attestation.verify_badge`,
            or a description of the structural problem.
        tool: the tool name embedded in the badge, or null when malformed.
    """
    badge = req.badge
    if not isinstance(badge, dict) or any(k not in badge for k in _REQUIRED_BADGE_FIELDS):
        missing = [
            k for k in _REQUIRED_BADGE_FIELDS if not isinstance(badge, dict) or k not in badge
        ]
        return {
            "valid": False,
            "status": "invalid",
            "reason": f"malformed badge (missing {missing})",
            "tool": None,
        }
    verifier = _verifier()
    if verifier is None:
        return {
            "valid": False,
            "status": "invalid",
            "reason": (
                "TRIPWIRE_PUBLIC_KEY_PATH or TRIPWIRE_SIGNING_KEY is required to verify badges"
            ),
            "tool": badge.get("tool"),
        }
    ok, reason = attestation.verify_badge(badge, verifier)
    return {
        "valid": ok,
        "status": "valid" if ok else "tampered",
        "reason": reason,
        "tool": badge.get("tool"),
    }


@app.get("/eval")
def eval_corpus(request: Request):
    """Run the default attack corpus; return real counts (Hard Rule #6).

    Default shape is identical to `tripwire ci --json` (one downstream
    parser across CLI + HTTP). With `Accept: application/sarif+json` the
    response is a SARIF 2.1.0 document covering every corpus case
    (one combined `runs[]`, per-case `properties.tripwire_case` on
    every result).
    """
    cases = load_corpus()
    result = run_corpus(
        cases,
        signing_key=os.environ.get("TRIPWIRE_SIGNING_KEY", _EVAL_SIGNING_KEY),
    )
    passed = result.all_attacks_blocked and not result.false_positives

    if _wants_sarif(request):
        sarif_doc = to_sarif(from_corpus_rows(result.rows))
        return JSONResponse(content=sarif_doc, media_type=SARIF_MIME)

    return {
        "attacks_total": result.attacks_total,
        "attacks_blocked": result.attacks_blocked,
        "clean_total": result.clean_total,
        "false_positives": result.false_positives,
        "passed": passed,
        "rows": result.rows,
    }


# ----------------------------------------------------------------- /mcp/sse
# RFC-0004 / #33 slot 6 — HTTP gateway mount for SSE-transport MCP servers.
#
# Two endpoints:
#   GET  /mcp/sse/events          subscribe to server→client SSE stream
#   POST /mcp/sse/messages?...    client→server JSON-RPC frames
#
# Gated by TRIPWIRE_UPSTREAM_SSE_URL (Decision #7). With it unset, both
# endpoints return 503 with a non-secret diagnostic (Decision #9 — gateway
# liveness vs upstream readiness, codified in the RFC's reviewer round).
#
# Per-client session lifecycle: GET /events spins up a fresh
# SseClientStream + SseServerStream + SseTripwireProxy + bridge task, all
# tracked under a UUID. The first SSE frame is an `endpoint` event pointing
# at /messages?session=<uuid>; subsequent POSTs route into that session's
# inbound queue. The session closes on client disconnect.


import uuid as _uuid  # noqa: E402

from fastapi import HTTPException  # noqa: E402


def _upstream_sse_url() -> str | None:
    """Read at request time so tests can monkeypatch."""
    return os.environ.get("TRIPWIRE_UPSTREAM_SSE_URL")


# In-process session table: session_id → SseClientStream.
# Lifetime is tied to the active GET /events handler.
_sse_sessions: dict[str, object] = {}

# Codex P2 #3: shared engine per RFC-0004 Decision #1 ("one SseTripwireProxy
# instance per client connection, shared engine"). The engine carries
# deployment policy (approvals, badges) that MUST be consistent across
# clients of the same upstream. Per-client engines would split approvals.
# Lazy so env vars can still be set by the importer / tests.
_proxy_engine = None


def _get_proxy_engine():
    """Module-level shared engine for the SSE proxy. First call wins; tests
    can reset via _reset_proxy_engine_for_tests()."""
    global _proxy_engine
    if _proxy_engine is None:
        from tripwire import TripwireEngine
        from tripwire.signing import SigningConfigError, resolve_signing_backend

        try:
            backend = resolve_signing_backend()
        except SigningConfigError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        _proxy_engine = TripwireEngine(signing_backend=backend)
    return _proxy_engine


def _reset_proxy_engine_for_tests() -> None:
    """Test helper: clear the cached engine so the next request rebuilds it
    from current env. Not exposed via the HTTP surface."""
    global _proxy_engine
    _proxy_engine = None


def _ensure_upstream_or_503() -> str:
    """RFC-0004 Decision #9: gateway readiness != upstream readiness.
    With no upstream configured, surface a clear 503 on the SSE endpoints
    while /healthz keeps reporting the process is alive."""
    url = _upstream_sse_url()
    if not url:
        raise HTTPException(
            status_code=503,
            detail=(
                "SSE proxy not configured: set TRIPWIRE_UPSTREAM_SSE_URL to a "
                "reachable MCP-over-SSE server. /healthz continues to report "
                "gateway-process liveness only."
            ),
        )
    return url


@app.get("/mcp/sse/events")
async def mcp_sse_events(request: Request):
    """Open the SSE subscription. First frame is `event: endpoint, data:
    /mcp/sse/messages?session=<uuid>` so the client knows where to POST.
    Subsequent frames carry server→client JSON-RPC responses."""
    import asyncio

    from sse_starlette.sse import EventSourceResponse

    from app.sse_adapter import SseClientStream, SseServerStream
    from tripwire.proxy import SseTripwireProxy

    upstream_url = _ensure_upstream_or_503()

    session_id = _uuid.uuid4().hex
    client_stream = SseClientStream()
    _sse_sessions[session_id] = client_stream

    # Forward request headers byte-for-byte (Decision #3) but strip Host so the
    # upstream HTTP client picks the correct one.
    forwarded_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in {"host", "content-length"}
    }
    # Shared engine (Decision #1). One proxy per client connection (state
    # isolation for `_live_tools`); the engine carries approval/badge state
    # that must be consistent across clients.
    proxy = SseTripwireProxy(_get_proxy_engine())
    server_stream = SseServerStream(
        upstream_url,
        headers=forwarded_headers,
        # On every upstream drop (incl. mid-reconnect): clear this client's
        # live-tools cache so the fresh stream's tools/list rebuilds it.
        on_cache_invalidate=proxy.invalidate_cache,
        # On terminal end (both reconnect attempts exhausted, or clean EOF):
        # close the inbound client stream so the SSE response handler exits.
        on_terminal=client_stream.close_inbound,
    )

    async def session_lifecycle():
        """Run the bridge for the lifetime of this connection."""
        try:
            async with server_stream as srv:
                await proxy.bridge_sse(client_stream=client_stream, server_stream=srv)
        except (asyncio.CancelledError, ConnectionResetError):
            pass

    bridge_task = asyncio.create_task(session_lifecycle(), name=f"sse-session-{session_id}")

    async def event_stream():
        try:
            # First frame: tell the client where to POST.
            yield {"event": "endpoint", "data": f"/mcp/sse/messages?session={session_id}"}
            async for line in client_stream.iter_outbound():
                if await request.is_disconnected():
                    break
                yield {"event": "message", "data": line.decode()}
        finally:
            client_stream.close_inbound()
            _sse_sessions.pop(session_id, None)
            bridge_task.cancel()
            try:
                await bridge_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001, S110
                pass

    return EventSourceResponse(event_stream())


@app.post("/mcp/sse/messages")
async def mcp_sse_messages(session: str, request: Request):
    """Inbound JSON-RPC frame. Routes to the open SSE session by id."""
    _ensure_upstream_or_503()
    stream = _sse_sessions.get(session)
    if stream is None:
        raise HTTPException(status_code=404, detail=f"unknown session: {session}")
    body = await request.body()
    stream.push_inbound(body)  # type: ignore[attr-defined]
    return {"queued": True}
