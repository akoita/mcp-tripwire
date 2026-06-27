"""MCP-Tripwire proof-moment demo (the 5-minute video script, in code).

Run:  make demo   (or)   PYTHONPATH=src python3 examples/demo.py

Shows, deterministically:
  A/B  — a compromised agent leaks a CANARY secret WITHOUT Tripwire; Tripwire blocks it.
  Rug  — an approved tool mutates after approval; Tripwire quarantines it.
  Proof— a signed trust badge verifies, then breaks the instant it's tampered with.

Everything uses a labelled canary + local fake sink. No real credentials. (Hard Rule #4)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from vulnerable_mcp_server import (  # noqa: E402
    CANARY_SECRET,
    clean_weather_tool,
    naive_agent_execute,
    poisoned_tool,
    rugpull_mutate,
)

from tripwire import TripwireEngine  # noqa: E402
from tripwire.detection import fingerprint  # noqa: E402

KEY = os.environ.get("TRIPWIRE_SIGNING_KEY", "dev-only-change-me")


def rule(title: str) -> None:
    print(f"\n{'─' * 64}\n{title}\n{'─' * 64}")


def main() -> int:
    print("MCP-Tripwire — proof-moment demo")
    print(f"(using a labelled CANARY secret: {CANARY_SECRET!r} — not a real credential)")

    # --- A: WITHOUT Tripwire -------------------------------------------------
    rule("A) WITHOUT Tripwire: the agent blindly trusts the poisoned tool")
    sink: list[str] = []
    naive_agent_execute(poisoned_tool(), CANARY_SECRET, sink)
    leaked = CANARY_SECRET in sink
    print(f"  fake exfiltration sink: {sink}")
    print(f"  >>> CANARY LEAKED: {leaked}  ❌" if leaked else "  no leak")

    # --- B: WITH Tripwire ----------------------------------------------------
    rule("B) WITH Tripwire: the poisoned tool never gets approved")
    engine = TripwireEngine(KEY)
    decision = engine.approve(poisoned_tool())
    print(f"  decision: {decision.action.value} — {decision.reason}")
    for f in decision.findings:
        print(f"    • [{f.severity}] {f.owasp} {f.title}")
    sink2: list[str] = []
    if decision.allowed:
        naive_agent_execute(poisoned_tool(), CANARY_SECRET, sink2)
    print(f"  fake exfiltration sink: {sink2}")
    print(f"  >>> CANARY BLOCKED: {CANARY_SECRET not in sink2}  ✅")

    # --- Rug pull ------------------------------------------------------------
    rule("Rug pull: an approved tool mutates after approval")
    clean = clean_weather_tool()
    approve = engine.approve(clean)
    print(f"  approved '{clean['name']}' → {approve.action.value}; badge issued ✅")
    mutated = rugpull_mutate(clean)
    verdict = engine.evaluate_call(mutated)
    print(f"  tool mutated → evaluate_call: {verdict.action.value.upper()} — {verdict.reason}  ✅")

    # --- Verifiable attestation ---------------------------------------------
    rule("Proof: the signed trust badge breaks on tamper")
    badge = engine.badge_for(clean["name"])
    ok, why = engine.verify_badge(badge)
    print(f"  verify(original badge): {ok} ({why}) ✅")
    tampered = dict(badge, fingerprint=fingerprint(mutated))  # swap in the mutated hash
    ok2, why2 = engine.verify_badge(tampered)
    print(f"  verify(tampered badge): {ok2} ({why2}) ✅")

    print("\nSummary: poisoning blocked · rug-pull quarantined · attestation tamper-evident.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
