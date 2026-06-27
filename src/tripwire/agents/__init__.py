"""Optional ADK multi-agent layer (P1 — the 'multi-agent ADK' course concept).

Three cooperating agents drive the same deterministic engine:
  - Scanner  : classifies a target server's tools (uses tripwire.detection)
  - Red-team : generates adversarial probes against the target (corpus + LLM variation)
  - Attestor : issues/withholds the signed badge based on the verdict

These are import-guarded so the stdlib core never depends on google-adk (Hard Rule #2).
# STUB(E3): flesh out the ADK Agent/LlmAgent wiring and tool definitions.
"""

from __future__ import annotations


def adk_available() -> bool:
    try:
        import google.adk  # noqa: F401

        return True
    except ImportError:
        return False
