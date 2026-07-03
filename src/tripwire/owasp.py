"""OWASP MCP Top 10 taxonomy mapping.

Findings are tagged with an OWASP MCP category so risk is communicated in a recognised
taxonomy (Day-4 guidance) rather than a bespoke label. IDs/titles track the official
OWASP MCP Top 10 (2025) working draft — https://owasp.org/www-project-mcp-top-10/ —
using the project's canonical `MCPnn:2025` notation. Which categories Tripwire
actually addresses (vs out-of-scope) is documented in docs/OWASP_MCP_COVERAGE.md.
"""

from __future__ import annotations

# Canonical id -> human title. Used by detection rules and the triage skill.
OWASP_MCP_TOP_10: dict[str, str] = {
    "MCP01:2025": "Token Mismanagement & Secret Exposure",
    "MCP02:2025": "Privilege Escalation via Scope Creep",
    "MCP03:2025": "Tool Poisoning",
    "MCP04:2025": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05:2025": "Command Injection & Execution",
    "MCP06:2025": "Intent Flow Subversion",
    "MCP07:2025": "Insufficient Authentication & Authorization",
    "MCP08:2025": "Lack of Audit and Telemetry",
    "MCP09:2025": "Shadow MCP Servers",
    "MCP10:2025": "Context Injection & Over-Sharing",
}


def title(owasp_id: str) -> str:
    """Return the human title for an OWASP MCP id, or the id if unknown."""
    return OWASP_MCP_TOP_10.get(owasp_id, owasp_id)


def is_valid(owasp_id: str) -> bool:
    return owasp_id in OWASP_MCP_TOP_10
