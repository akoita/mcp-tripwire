#!/usr/bin/env python3
"""Issue a signed trust badge for each tool in a vetted manifest.

Refuses to sign any tool the engine would block. Key from $TRIPWIRE_SIGNING_KEY.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from tripwire.engine import Action, TripwireEngine


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: sign_badge.py <manifest.json>", file=sys.stderr)
        return 2
    manifest = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    tools = manifest.get("tools", [manifest]) if isinstance(manifest, dict) else [manifest]
    engine = TripwireEngine(os.environ.get("TRIPWIRE_SIGNING_KEY", "dev-only-change-me"))
    badges = []
    for tool in tools:
        decision = engine.approve(tool)
        if decision.action is not Action.ALLOW:
            print(f"refusing to sign '{decision.tool}': {decision.reason}", file=sys.stderr)
            return 1
        badges.append(decision.badge)
    print(json.dumps(badges, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
