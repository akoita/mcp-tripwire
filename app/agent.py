"""ADK application entry (P1). Composes the Scanner/Red-team/Attestor agents.

Kept import-light so the stdlib core never depends on ADK. The real wiring is E3.
"""

from __future__ import annotations

from tripwire.agents import adk_available


def build_app():
    """Return the ADK `App` wiring the Tripwire multi-agent system.

    # STUB(E3): compose root agent + Scanner/Red-team/Attestor sub-agents and plugins.
    """
    if not adk_available():
        raise RuntimeError("google-adk not installed — run: uv sync --extra agent")
    raise NotImplementedError("STUB(E3): assemble ADK App from tripwire.agents.*")
