"""Optional ADK multi-agent layer — Scanner · Red-team · Attestor.

Three cooperating agents that drive the same deterministic engine the rest of
the project uses. ADK imports are isolated to this subpackage and to `app/`,
so the stdlib core (`src/tripwire/*.py` outside this directory) stays
dependency-free per Hard Rule #2 — enforced by `scripts/harness_guardrails.py`.

Exports the public factories. Each `create_*_agent()` is the boundary that
imports `google.adk`; the underlying tool callables (`scan_tool_descriptor`,
`seed_probes`, `propose_probe`, `issue_if_clean`) are pure stdlib + tripwire
core, so they can be unit-tested without the `[agent]` extra installed.
"""

from __future__ import annotations

from .attestor_agent import create_attestor_agent, issue_if_clean
from .redteam_agent import create_redteam_agent, propose_probe, seed_probes
from .scanner_agent import create_scanner_agent, scan_tool_descriptor

__all__ = [
    "adk_available",
    "create_scanner_agent",
    "create_redteam_agent",
    "create_attestor_agent",
    "scan_tool_descriptor",
    "seed_probes",
    "propose_probe",
    "issue_if_clean",
]


def adk_available() -> bool:
    """True if `google-adk` is importable (i.e. `[agent]` extra installed)."""
    try:
        import google.adk  # noqa: F401, PLC0415

        return True
    except ImportError:
        return False
