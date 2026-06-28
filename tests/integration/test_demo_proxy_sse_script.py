"""Subprocess-runs the SSE demo and asserts the three-act narrative renders.

Slot 7 of RFC-0004 day-N. Mirrors `test_proxy_demo_script.py` for the
SSE transport: confirms `python examples/demo_proxy_sse.py` exits 0 and
prints the expected proof-moment text.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("httpx")
pytest.importorskip("sse_starlette")

REPO = Path(__file__).resolve().parents[2]
DEMO = REPO / "examples" / "demo_proxy_sse.py"


def test_demo_proxy_sse_script_exits_zero_and_shows_proof_moments():
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{REPO / 'src'}{os.pathsep}{REPO}"
    result = subprocess.run(
        [sys.executable, str(DEMO)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, (
        f"demo exited {result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    out = result.stdout
    # Act A — naive view sees both tools.
    assert "Without Tripwire" in out
    assert "summarize_notes" in out
    # Act B — Tripwire strips the poisoned tool and badges the clean one.
    assert "With Tripwire" in out
    assert "tools/list now returns 1 tool(s)" in out
    assert "badge=attached" in out
    # Act C — rug pull caught + -32001 short-circuit.
    assert "Rug pull" in out
    assert "tools/call short-circuited" in out
    assert "code -32001" in out
    assert "action=quarantine" in out
    # Closing line.
    assert "Summary" in out
    assert "rug-pull quarantined" in out
