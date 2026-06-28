"""Cloud Run entrypoint: `uvicorn app.fast_api_app:app` (course Day-5 convention).

Exposes the deterministic Tripwire core over HTTP so a centralised policy
engine can be reached by CI jobs, batch scanners, or downstream audit
pipelines without each caller installing the SDK locally.

Endpoints:
    GET  /healthz   liveness probe (Cloud Run convention)
    POST /scan      {"tool": {...}} -> scan_tool_descriptor() shape
    POST /verify    {"badge": {...}} -> {"valid", "status", "reason", "tool"}
    GET  /eval      runs the default attack corpus -> CorpusResult dict

The stdio MCP gateway (transparent bridge for an MCP client to talk through
a deployed Tripwire instance) is a separate, larger surface — tracked in
[STATUS.md](../STATUS.md) and not in scope for this PR.
"""

from __future__ import annotations

import os

from app.app_utils.telemetry import setup_telemetry

setup_telemetry()

try:
    from fastapi import FastAPI
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover - only at deploy time
    raise RuntimeError("Install the served gateway deps: uv sync --extra agent") from exc

# The tripwire imports come *after* the fastapi guard so a missing [agent]
# extra fails fast with a clear hint, before pulling stdlib-only modules
# into a process that can't serve them anyway.
from tripwire import attestation  # noqa: E402
from tripwire.agents.scanner_agent import scan_tool_descriptor  # noqa: E402
from tripwire.corpus import load_corpus, run_corpus  # noqa: E402

app = FastAPI(
    title="MCP-Tripwire Gateway",
    version="0.1.0",
    description=(
        "Trust gateway for MCP tools: deterministic scan, drift quarantine, "
        "signed attestations. See https://github.com/akoita/mcp-tripwire."
    ),
)


_REQUIRED_BADGE_FIELDS = ("tool", "fingerprint", "sig")


def _signing_key() -> str:
    return os.environ.get("TRIPWIRE_SIGNING_KEY", "dev-only-change-me")


class ScanRequest(BaseModel):
    tool: dict


class VerifyRequest(BaseModel):
    badge: dict


@app.get("/healthz")
def healthz() -> dict:
    """Liveness probe. Used by Cloud Run health-check and local docker run smoke."""
    return {"status": "ok", "service": "mcp-tripwire"}


@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    """Scan an MCP tool descriptor; return findings grouped by OWASP category.

    Same return shape as the agent-layer `scan_tool_descriptor` function and
    the `tripwire scan` CLI — one source of truth for the verdict format.
    """
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
    ok, reason = attestation.verify_badge(badge, _signing_key())
    return {
        "valid": ok,
        "status": "valid" if ok else "tampered",
        "reason": reason,
        "tool": badge.get("tool"),
    }


@app.get("/eval")
def eval_corpus() -> dict:
    """Run the default attack corpus; return real counts (Hard Rule #6).

    Identical schema to `tripwire ci --json` so CLI and HTTP callers share
    one downstream parser. Never reads from a cache; every call re-runs
    the corpus.
    """
    cases = load_corpus()
    result = run_corpus(cases, signing_key=_signing_key())
    passed = result.all_attacks_blocked and not result.false_positives
    return {
        "attacks_total": result.attacks_total,
        "attacks_blocked": result.attacks_blocked,
        "clean_total": result.clean_total,
        "false_positives": result.false_positives,
        "passed": passed,
        "rows": result.rows,
    }
