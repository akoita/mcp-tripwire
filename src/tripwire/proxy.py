"""Transparent stdio MCP proxy (E2).

Sits between an MCP client and an upstream MCP server (spawned as a subprocess),
intercepting JSON-RPC traffic so every `tools/list` is vetted and every `tools/call`
is checked against the approved fingerprint before it executes.

The *guard logic* (`guard_tools_list`, `guard_tool_call`) is fully implemented and
unit-testable here. The byte-level stdio pump is a documented skeleton:
# STUB(E2): wire the asyncio read/write loop to a real subprocess.
"""

from __future__ import annotations

from dataclasses import dataclass

from .engine import Decision, TripwireEngine


@dataclass
class GuardedListResult:
    approved: list[dict]  # tool descriptors that passed vetting (with badges attached)
    blocked: list[Decision]  # tools refused at approval


class StdioTripwireProxy:
    """Policy enforcement for a single upstream MCP server."""

    def __init__(self, engine: TripwireEngine) -> None:
        self.engine = engine

    def guard_tools_list(self, tools: list[dict]) -> GuardedListResult:
        """Vet every advertised tool. Approved tools get a `_tripwire_badge`; the rest
        are stripped from what the client ever sees."""
        approved, blocked = [], []
        for tool in tools:
            decision = self.engine.approve(tool)
            if decision.allowed:
                approved.append({**tool, "_tripwire_badge": decision.badge})
            else:
                blocked.append(decision)
        return GuardedListResult(approved, blocked)

    def guard_tool_call(self, current_tool: dict) -> Decision:
        """Re-check a tool at call time against its approved fingerprint (rug-pull guard)."""
        return self.engine.evaluate_call(current_tool)

    # ------------------------------------------------------------------
    def serve(self, command: list[str]) -> None:  # pragma: no cover
        """Spawn `command` as the upstream MCP server and pump JSON-RPC through the guards.

        # STUB(E2): implement the asyncio stdio bridge:
        #   client.stdin -> [intercept] -> server.stdin
        #   server.stdout -> [intercept tools/list + responses] -> client.stdout
        # On tools/list: replace result.tools with guard_tools_list(...).approved.
        # On tools/call: look up the live tool schema, run guard_tool_call(...);
        #   if action != ALLOW, short-circuit with a JSON-RPC error instead of forwarding.
        """
        raise NotImplementedError("STUB(E2): stdio subprocess bridge not yet wired")
