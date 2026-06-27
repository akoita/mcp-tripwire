"""Attestor agent (P1) — issues or withholds the signed trust badge.

Human-in-the-loop: high-stakes attestation requires confirmation
(`tool_context.request_confirmation`) before a badge is signed (Day-4 guidance).
# STUB(E3): wire ADK FunctionTool(require_confirmation=True).
"""

from __future__ import annotations

import os

from ..engine import TripwireEngine

SYSTEM_PROMPT = (
    "You are the Tripwire Attestor. Issue a signed trust badge ONLY for tools the Scanner "
    "cleared and a human approved. Withhold on any unresolved finding. Never sign blindly."
)


def issue_if_clean(tool: dict) -> dict:
    """ADK tool: approve+attest a tool via the deterministic engine. Returns the decision."""
    engine = TripwireEngine(os.environ.get("TRIPWIRE_SIGNING_KEY", "dev-only-change-me"))
    return engine.approve(tool).as_dict()


def build_attestor_agent():  # pragma: no cover
    from google.adk.agents import LlmAgent
    from google.adk.tools import FunctionTool

    return LlmAgent(
        name="tripwire_attestor",
        model="gemini-3-pro",
        instruction=SYSTEM_PROMPT,
        tools=[FunctionTool(issue_if_clean, require_confirmation=True)],
    )
