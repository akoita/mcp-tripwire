"""Real-world attack suite — characterization tests (Hard Rule #5 + #6).

Every case in `corpus/real_world/attacks.jsonl` is reproduced from PUBLISHED
security research and carries its citation. This suite pins what Tripwire
ACTUALLY does against each one — catches *and* misses.

The misses (`rw-02`, `rw-07`, `rw-08`) are deliberate recorded findings, not
bugs to fix here: this suite exists to report real-world efficacy honestly.
The pass/fail gate is `corpus/attacks.jsonl` via `make eval`, which must stay
100% blocked; that gate is unaffected by anything in this file.
"""

import json
from pathlib import Path

import pytest

from tripwire.detection import scan_tool
from tripwire.engine import Action, TripwireEngine

CORPUS = Path(__file__).resolve().parents[2] / "corpus/real_world/attacks.jsonl"


def load_cases() -> list[dict]:
    """Load the JSONL suite: one case object per non-empty, non-comment line."""
    lines = CORPUS.read_text(encoding="utf-8").splitlines()
    return [json.loads(ln) for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


CASES = load_cases()


def case_by_id(case_id: str) -> dict:
    return next(case for case in CASES if case["id"] == case_id)


def classify(case: dict) -> tuple[str, str]:
    """Run one case through a fresh engine; return the measured (outcome, layer).

    Mirrors `scripts/real_world_audit.py` exactly — the report and the contract
    must never disagree about what a case did.
    """
    engine = TripwireEngine(signing_key="audit")
    base = engine.approve(case["tool"])
    if "mutate_to" in case:
        if base.action is Action.BLOCK:
            return "blocked", "scanner"
        call = engine.evaluate_call(case["mutate_to"])
        if call.action is Action.QUARANTINE:
            return "blocked", "drift"
        return "out_of_scope", "none"
    if base.action is Action.BLOCK:
        return "blocked", "scanner"
    if base.findings:
        return "advisory", "scanner"
    return "missed", "none"


def test_suite_is_non_empty():
    """Guard against a silently empty parametrization (a green suite that tested nothing)."""
    assert len(CASES) >= 9


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_measured_outcome_matches_recorded_expectation(case):
    """Pin the measured verdict for every published-research case."""
    measured = classify(case)
    recorded = (case["expected_outcome"], case["expected_layer"])
    assert measured == recorded, (
        f"{case['id']} ({case['technique']}): detection behaviour CHANGED — "
        f"recorded {recorded}, now measuring {measured}. This is a "
        f"characterization test, not a correctness test: the code is not "
        f"necessarily broken. Re-run `make audit`, decide deliberately whether "
        f"the new behaviour is what you want, and only then update "
        f"`expected_outcome`/`expected_layer` for this case in "
        f"corpus/real_world/attacks.jsonl. Never edit the recorded expectation "
        f"just to make this test green. Source: {case['source']['url']}"
    )


def test_drift_catches_what_the_scanner_misses():
    """THE headline, non-circular result of this project.

    Case `rw-09` carries a payload the content scanner genuinely cannot see —
    `scan_tool` returns ZERO findings on the mutated descriptor, so this is not
    a scanner grading its own homework. The deterministic drift layer still
    quarantines it, because it compares fingerprints rather than reading intent.

    That is the whole argument for a stateful trust gateway over a one-shot
    descriptor linter, and it is measured here rather than asserted in prose.
    """
    case = case_by_id("rw-09")
    mutated = case["mutate_to"]

    assert scan_tool(mutated) == [], (
        "rw-09 is only meaningful evidence while the scanner is BLIND to the "
        "mutated descriptor. It now produces findings, which makes the drift "
        "result circular — pick a fresh scanner-invisible payload instead of "
        "weakening this assertion."
    )

    engine = TripwireEngine(signing_key="audit")
    approved = engine.approve(case["tool"])
    assert approved.action is Action.ALLOW
    assert engine.evaluate_call(mutated).action is Action.QUARANTINE


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_every_case_carries_a_verifiable_citation(case):
    """No case may claim 'real-world' without a checkable published source (Rule #6)."""
    source = case["source"]
    assert source["name"].strip(), f"{case['id']}: empty source.name"
    assert source["url"].startswith("https://"), f"{case['id']}: source.url is not https"
    assert source["date"].strip(), f"{case['id']}: empty source.date"


def test_postmark_supply_chain_change_is_out_of_scope():
    """Documents a real limit: Tripwire guards the MANIFEST surface, not the server.

    In the postmark-mcp incident (`rw-04`) the published tool descriptor never
    changed — the malicious behaviour was added inside the server implementation.
    Both `tool` and `mutate_to` are therefore identical, no fingerprint drift
    fires, and Tripwire is structurally blind to it. Recording this as
    `out_of_scope` (rather than `missed`) keeps the honest distinction between
    "we should have caught it" and "no manifest-integrity gate could".
    """
    case = case_by_id("rw-04")
    assert case["tool"] == case["mutate_to"], "rw-04 only demonstrates the limit while identical"
    assert classify(case) == ("out_of_scope", "none")
