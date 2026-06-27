"""Smoke test for `examples/demo_adk.py` (issue #8 acceptance).

The demo script imports `tripwire.agents` (which exercises the factories
without actually invoking the LLM) and prints the deterministic-tool
output for all three sub-agents. This test makes sure the user-facing
demo doesn't silently rot the way `examples/demo_proxy.py` is covered
by `test_proxy_demo_script.py`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DEMO = REPO / "examples" / "demo_adk.py"


def _adk_available() -> bool:
    try:
        import google.adk  # noqa: F401

        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _adk_available(), reason="google-adk not installed")
def test_adk_demo_script_exits_zero_and_shows_three_sections():
    result = subprocess.run(
        [sys.executable, str(DEMO)],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, (
        f"demo_adk exited {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    out = result.stdout
    # Each of the three agents gets its own section.
    assert "scanner" in out.lower(), out
    assert "red-team" in out.lower() or "redteam" in out.lower(), out
    assert "attestor" in out.lower(), out
    # The deterministic verdicts are visible.
    assert "owasp" in out.lower() or "mcp-0" in out.lower(), out
    assert "block" in out.lower(), out
    assert "allow" in out.lower(), out
