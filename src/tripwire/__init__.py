"""MCP-Tripwire — a lightweight OSS trust gateway for MCP tools.

Public API (deterministic core, stdlib-only):
    from tripwire import TripwireEngine, Action, Decision, scan_tool, fingerprint
"""

from __future__ import annotations

from .attestation import issue_badge, sign, verify_badge
from .detection import Finding, Severity, detect_drift, fingerprint, scan_tool
from .engine import Action, Decision, TripwireEngine
from .owasp import OWASP_MCP_TOP_10

__version__ = "0.1.0"

__all__ = [
    "TripwireEngine",
    "Action",
    "Decision",
    "Finding",
    "Severity",
    "scan_tool",
    "fingerprint",
    "detect_drift",
    "issue_badge",
    "sign",
    "verify_badge",
    "OWASP_MCP_TOP_10",
    "__version__",
]
