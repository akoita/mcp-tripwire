"""The Tripwire policy engine — the trust loop.

scan → approve/reject → fingerprint → (later) detect drift → quarantine → attest.

The engine is the deterministic decision layer the proxy (E2) and the ADK agent
layer (P1) both drive. It owns the registry of approved fingerprints and badges.

Per RFC-0002 (#31), badge minting goes through a pluggable ``SigningBackend``
rather than a raw key. Existing call sites that pass ``signing_key=KEY`` keep
working — internally the engine wraps the key in ``HmacBackend``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from . import attestation
from .detection import Finding, Severity, detect_drift, fingerprint, max_severity, scan_tool
from .signing import HmacBackend, SigningBackend


class Action(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class Decision:
    action: Action
    reason: str
    tool: str
    findings: list[Finding] = field(default_factory=list)
    fingerprint: str | None = None
    badge: dict | None = None

    @property
    def allowed(self) -> bool:
        return self.action is Action.ALLOW

    def as_dict(self) -> dict:
        return {
            "action": self.action.value,
            "reason": self.reason,
            "tool": self.tool,
            "findings": [f.as_dict() for f in self.findings],
            "fingerprint": self.fingerprint,
            "badge": self.badge,
        }


class TripwireEngine:
    """Stateful trust gateway. One instance guards one MCP session/server set.

    Constructor accepts a configured ``signing_backend`` (preferred) or a legacy
    ``signing_key`` keyword (back-compat). Exactly one must be supplied.
    """

    def __init__(
        self,
        signing_backend: SigningBackend | None = None,
        *,
        signing_key: str | bytes | None = None,
        block_at: Severity = Severity.HIGH,
    ) -> None:
        if signing_backend is not None and signing_key is not None:
            raise TypeError("TripwireEngine: pass either signing_backend OR signing_key, not both")
        if signing_backend is not None:
            self._backend: SigningBackend = signing_backend
        elif signing_key is not None:
            self._backend = HmacBackend(signing_key)
        else:
            raise TypeError("TripwireEngine requires a signing_backend or signing_key")
        self._block_at = block_at
        self._approved: dict[str, str] = {}  # tool name -> approved fingerprint
        self._badges: dict[str, dict] = {}  # tool name -> trust badge

    # -- approval (vetting time) -------------------------------------------
    def approve(self, tool: dict, *, issued_at: str | None = None) -> Decision:
        """Vet a tool. Block if it carries findings at/above the block threshold;
        otherwise fingerprint it, mint a signed badge, and register it as trusted."""
        name = str(tool.get("name", "<unnamed>"))
        findings = scan_tool(tool)
        worst = max_severity(findings)
        if worst is not None and worst >= self._block_at:
            return Decision(
                Action.BLOCK, f"refused approval: {worst} finding(s) detected", name, findings
            )
        fp = fingerprint(tool)
        badge = attestation.issue_badge(name, fp, self._backend, issued_at=issued_at)
        self._approved[name] = fp
        self._badges[name] = badge
        return Decision(Action.ALLOW, "approved and attested", name, findings, fp, badge)

    # -- enforcement (call time) -------------------------------------------
    def evaluate_call(self, tool: dict) -> Decision:
        """Decide whether an in-flight tool call may proceed."""
        name = str(tool.get("name", "<unnamed>"))
        if name not in self._approved:
            return Decision(Action.REQUIRE_APPROVAL, "tool not yet approved", name, scan_tool(tool))
        if detect_drift(self._approved[name], tool):
            return Decision(
                Action.QUARANTINE,
                "schema drift since approval — rug pull suspected",
                name,
                scan_tool(tool),
                fingerprint(tool),
            )
        return Decision(
            Action.ALLOW,
            "matches approved fingerprint",
            name,
            fingerprint=self._approved[name],
            badge=self._badges.get(name),
        )

    # -- introspection ------------------------------------------------------
    def badge_for(self, tool_name: str) -> dict | None:
        return self._badges.get(tool_name)

    def verify_badge(self, badge: dict) -> tuple[bool, str]:
        return attestation.verify_badge(badge, self._backend)
