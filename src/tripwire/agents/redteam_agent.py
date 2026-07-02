"""Red-team agent — proposes adversarial probes against a target MCP gateway.

The agent's job is to *select* and *explain* probes; the probe set itself
is deterministic and ships with the repo (`corpus/attacks.jsonl`). This
keeps Hard Rule #4 (no real credentials in any demo) intact: every probe
is canary-labelled and intentionally inert.

LLM-driven mutation of probes — the "Quality Flywheel" pattern from the
course — lives behind a future eval entrypoint; this PR ships the seed
loop only.
"""

from __future__ import annotations

from ..corpus import DEFAULT_CORPUS, load_corpus
from ..owasp import title as owasp_title

SYSTEM_PROMPT = (
    "You are the Tripwire Red-Team. The operator asks for adversarial MCP tool "
    "descriptors that exercise the gateway. Always call `seed_probes()` first to "
    "see the canonical probe set, then call `propose_probe(category=...)` when the "
    "operator wants a specific OWASP category. Never execute a probe; only describe "
    "what it would do. Stay within the canary/fake-sink sandbox (Hard Rule #4)."
)

AGENT_DESCRIPTION = (
    "Surfaces adversarial MCP tool probes (poisoning, exfiltration, rug-pull, "
    "tool-shadowing) for the operator to test the gateway against."
)


def seed_probes() -> dict:
    """Return the deterministic probe set from the shipped corpus.

    Returns:
        A dict with the probe list. Always JSON-serialisable.
            probes: list of {id, category, owasp_hint, tool} drawn from
                `corpus/attacks.jsonl` (entries where `expect == "block"`).
            count: number of probes returned.
            source: relative path to the corpus file.
    """
    cases = [c for c in load_corpus(DEFAULT_CORPUS) if c.get("expect") == "block"]
    return {
        "probes": [
            {
                "id": c.get("id"),
                "category": c.get("category"),
                "owasp_hint": _category_to_owasp(c.get("category", "")),
                "tool": c.get("tool"),
            }
            for c in cases
        ],
        "count": len(cases),
        "source": "corpus/attacks.jsonl",
    }


def propose_probe(category: str) -> dict:
    """Return one probe whose `category` matches the operator's request.

    Args:
        category: Free-text category hint, e.g. "exfiltration", "rug-pull",
            "instruction-override". Substring-matched, case-insensitive,
            against the corpus's per-case `category` field.

    Returns:
        A dict with the selected probe. Always JSON-serialisable.
            matched: bool — whether a corpus entry matched.
            category_query: echo of the input for debugging.
            probe: {id, category, owasp_hint, tool} or None if no match.
    """
    needle = category.lower().strip()
    for case in load_corpus(DEFAULT_CORPUS):
        if case.get("expect") != "block":
            continue
        if needle and needle in case.get("category", "").lower():
            return {
                "matched": True,
                "category_query": category,
                "probe": {
                    "id": case.get("id"),
                    "category": case.get("category"),
                    "owasp_hint": _category_to_owasp(case.get("category", "")),
                    "tool": case.get("tool"),
                },
            }
    return {"matched": False, "category_query": category, "probe": None}


def _category_to_owasp(category: str) -> str:
    """Heuristic mapping from corpus category labels to OWASP MCP titles.

    The corpus uses short kebab-case labels (e.g. `secret-exfiltration`);
    this helper translates them into human OWASP titles for the agent's
    output. Falls back to the input string when nothing fits.
    """
    cat = category.lower()
    if "exfil" in cat or "credential" in cat or "env" in cat:
        return owasp_title("MCP01:2025")
    if "instruction" in cat or "system-prompt" in cat or "hidden" in cat:
        return owasp_title("MCP06:2025")
    if "invisible" in cat or "rug" in cat or "drift" in cat or "shadow" in cat:
        return owasp_title("MCP03:2025")
    return category


def create_redteam_agent():
    """Build the Red-team Agent. Lazy ADK import keeps Hard Rule #2 intact."""
    from google.adk.agents import Agent  # noqa: PLC0415

    return Agent(
        name="tripwire_redteam",
        model="gemini-3-pro",
        description=AGENT_DESCRIPTION,
        instruction=SYSTEM_PROMPT,
        tools=[seed_probes, propose_probe],
    )
