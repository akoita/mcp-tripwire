"""OWASP MCP Top 10 taxonomy mapping.

Findings are tagged with an OWASP MCP category so risk is communicated in a recognised
taxonomy (Day-4 guidance) rather than a bespoke label. IDs/titles track the public
OWASP MCP Top 10 project; treat as representative and update as the list evolves.
"""

from __future__ import annotations

# Canonical id -> human title. Used by detection rules and the triage skill.
OWASP_MCP_TOP_10: dict[str, str] = {
    "MCP-01": "Prompt / Tool-Description Injection",
    "MCP-02": "Tool Poisoning",
    "MCP-03": "Excessive Permissions / Over-Privilege",
    "MCP-04": "Rug Pull (Post-Approval Tool Mutation)",
    "MCP-05": "Tool Shadowing / Name Collision",
    "MCP-06": "Sensitive Data & Secret Exfiltration",
    "MCP-07": "Confused Deputy",
    "MCP-08": "Supply-Chain / Slopsquatting",
    "MCP-09": "Insufficient Authentication & Identity",
    "MCP-10": "Inadequate Logging & Monitoring",
}


def title(owasp_id: str) -> str:
    """Return the human title for an OWASP MCP id, or the id if unknown."""
    return OWASP_MCP_TOP_10.get(owasp_id, owasp_id)


def is_valid(owasp_id: str) -> bool:
    return owasp_id in OWASP_MCP_TOP_10
