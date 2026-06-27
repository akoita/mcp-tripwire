"""Red-team agent (P1) — generates adversarial probes against a target MCP server.

Seeds from the static corpus, then (via the LLM) mutates descriptions to find novel
poisoning that the deterministic rules miss — feeding new cases back into the corpus
(the Quality Flywheel).
# STUB(E3): wire ADK LlmAgent; add adversarial mutation + pass^k evaluation.
"""

from __future__ import annotations

from ..corpus import DEFAULT_CORPUS, load_corpus

SYSTEM_PROMPT = (
    "You are the Tripwire Red-Team. Propose adversarial MCP tool descriptors that attempt "
    "tool poisoning, secret exfiltration, rug pulls, and tool shadowing. Output structured "
    "candidates ONLY; never execute anything. Stay within the canary/fake-sink sandbox."
)


def seed_probes() -> list[dict]:
    """Deterministic seed set drawn from the shipped corpus."""
    return [c["tool"] for c in load_corpus(DEFAULT_CORPUS) if c.get("expect") == "block"]


def build_redteam_agent():  # pragma: no cover
    from google.adk.agents import LlmAgent

    return LlmAgent(name="tripwire_redteam", model="gemini-3-pro", instruction=SYSTEM_PROMPT)
