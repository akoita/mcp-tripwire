"""Scanner agent — explains a target MCP server's tools in natural language.

The LLM provides routing and explanation; the *verdict* always comes from
`tripwire.detection.scan_tool`, the deterministic core. This split means
the agent can never fabricate a finding (Hard Rule #6) — only the rule
engine writes to `findings`, and the agent's job is to summarise.
"""

from __future__ import annotations

from collections import Counter

from ..detection import max_severity, scan_tool
from ..owasp import title as owasp_title

SYSTEM_PROMPT = (
    "You are the Tripwire Scanner. For every MCP tool the operator gives you, "
    "call `scan_tool_descriptor(tool=...)` exactly once and report what the "
    "deterministic scanner returns. Group findings by OWASP MCP category, name "
    "the rule that fired, and quote the evidence snippet verbatim. Never invent "
    "findings; if the tool returns no findings, say so plainly."
)

AGENT_DESCRIPTION = (
    "Scans MCP tool descriptors against the deterministic Tripwire ruleset and "
    "explains the findings in plain language, mapped to the OWASP MCP Top 10."
)


def scan_tool_descriptor(tool: dict) -> dict:
    """Run the deterministic Tripwire scanner against one MCP tool descriptor.

    Args:
        tool: An MCP `tools/list` entry — at minimum a dict with a `name` and a
            `description`, optionally `inputSchema`.

    Returns:
        A dict with the scan result. Always JSON-serialisable.
            findings: list of finding dicts (rule, title, severity, owasp,
                evidence, tool name).
            owasp_categories: deduplicated list of OWASP MCP category titles
                that fired, e.g. ["Prompt / Tool-Description Injection",
                "Sensitive Data & Secret Exfiltration"].
            counts_by_category: {owasp_id: count} for quick aggregation.
            worst_severity: the highest severity present, or "none" if clean.
            status: "clean" if no findings, otherwise "findings".
    """
    findings = scan_tool(tool)
    counts = Counter(f.owasp for f in findings)
    worst = max_severity(findings)
    return {
        "status": "clean" if not findings else "findings",
        "findings": [f.as_dict() for f in findings],
        "owasp_categories": sorted({owasp_title(owasp_id) for owasp_id in counts}),
        "counts_by_category": dict(counts),
        "worst_severity": str(worst) if worst is not None else "none",
    }


def create_scanner_agent():
    """Build the Scanner Agent. Lazy ADK import keeps Hard Rule #2 intact."""
    from google.adk.agents import Agent  # noqa: PLC0415 — Hard Rule #2

    return Agent(
        name="tripwire_scanner",
        model="gemini-3-pro",
        description=AGENT_DESCRIPTION,
        instruction=SYSTEM_PROMPT,
        tools=[scan_tool_descriptor],
    )
