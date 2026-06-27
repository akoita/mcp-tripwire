"""Smoke test for `examples/demo_proxy.py` (issue #5 acceptance).

The proxy demo is the user-facing script that exercises the full bridge
end-to-end. The unit + integration tests cover the engine and the bridge
in isolation; this test makes sure the demo SCRIPT (which is what `make
demo` runs and what the video records) doesn't silently rot.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEMO = REPO / "examples" / "demo_proxy.py"


def test_proxy_demo_script_exits_zero_and_shows_proof_moments():
    result = subprocess.run(
        [sys.executable, str(DEMO)],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, (
        f"demo_proxy exited {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    out = result.stdout
    # Three proof-moment beats must land in plain text for a judge to follow.
    assert "without tripwire" in out.lower(), out
    assert "with tripwire" in out.lower(), out
    assert "quarantine" in out.lower(), out
