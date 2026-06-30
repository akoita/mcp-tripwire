"""Attestor agent — issues or withholds the signed trust badge.

Issuance is human-gated by wrapping `issue_if_clean` in
`FunctionTool(require_confirmation=True)`, so the operator must explicitly
approve every badge-mint at runtime. The deterministic engine still has
the final say — a tool the engine refuses can never be signed, even if a
human ticks the confirmation box.
"""

from __future__ import annotations

from ..engine import TripwireEngine

SYSTEM_PROMPT = (
    "You are the Tripwire Attestor. The operator asks you to issue a signed "
    "trust badge for a specific MCP tool. Call `issue_if_clean(tool=...)`. The "
    "tool requires user confirmation before it runs (the operator will see a "
    "prompt). If the engine returns action='block' or action='quarantine', "
    "explain which findings blocked it and DO NOT retry. If action='allow' and "
    "a badge is returned, hand back the badge JSON verbatim — never edit it."
)

AGENT_DESCRIPTION = (
    "Mints a signed Tripwire trust badge for an MCP tool, gated by deterministic "
    "vetting and explicit human confirmation."
)


def issue_if_clean(tool: dict) -> dict:
    """Approve + attest a tool via the deterministic Tripwire engine.

    Args:
        tool: An MCP `tools/list` entry to vet and (if clean) attest.

    Returns:
        A dict with the engine decision. Always JSON-serialisable.
            action: "allow" | "block" | "quarantine" | "require_approval".
            reason: human-readable explanation.
            tool: the tool name.
            findings: list of finding dicts (empty when clean).
            fingerprint: canonical fingerprint hex, or None when blocked.
            badge: the signed trust badge dict, or None when not allowed.

    The signing key is read from the `TRIPWIRE_SIGNING_KEY` env var (Hard
    Rule #3 — never hardcoded). If unset, the function refuses to mint a
    badge so production trust flows fail closed.
    """
    from ..signing import SigningConfigError, resolve_signing_backend

    try:
        backend = resolve_signing_backend()
    except SigningConfigError as exc:
        return {
            "action": "block",
            "reason": str(exc),
            "tool": str(tool.get("name", "<unnamed>")),
            "findings": [],
            "fingerprint": None,
            "badge": None,
        }
    engine = TripwireEngine(signing_backend=backend)
    return engine.approve(tool).as_dict()


def create_attestor_agent():
    """Build the Attestor Agent. Lazy ADK import keeps Hard Rule #2 intact."""
    from google.adk.agents import Agent  # noqa: PLC0415
    from google.adk.tools import FunctionTool  # noqa: PLC0415

    return Agent(
        name="tripwire_attestor",
        model="gemini-3-pro",
        description=AGENT_DESCRIPTION,
        instruction=SYSTEM_PROMPT,
        tools=[FunctionTool(issue_if_clean, require_confirmation=True)],
    )
