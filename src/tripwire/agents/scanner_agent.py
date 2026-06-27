"""Scanner agent (P1) — classifies a target MCP server's tools.

Wraps the deterministic `tripwire.detection` scan as an ADK tool so an LlmAgent can
reason over findings, cluster them, and explain drift in natural language.
# STUB(E3): wire real ADK Agent + before_tool_callback guardrail.
"""

from __future__ import annotations

from ..detection import scan_tool

SYSTEM_PROMPT = (
    "You are the Tripwire Scanner. For each MCP tool, call `scan_tool_descriptor` and "
    "summarise findings by OWASP MCP category and severity. Never invent findings; only "
    "report what the deterministic scanner returns."
)


def scan_tool_descriptor(tool: dict) -> list[dict]:
    """ADK tool: deterministic scan of one tool descriptor (returns serialisable findings)."""
    return [f.as_dict() for f in scan_tool(tool)]


def build_scanner_agent():  # pragma: no cover
    """Return an ADK LlmAgent wired to `scan_tool_descriptor`."""
    from google.adk.agents import LlmAgent  # lazy import (Hard Rule #2)

    return LlmAgent(
        name="tripwire_scanner",
        model="gemini-3-pro",
        instruction=SYSTEM_PROMPT,
        tools=[scan_tool_descriptor],
    )
