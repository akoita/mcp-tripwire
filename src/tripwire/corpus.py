"""Attack-corpus runner — the measurable, non-fabricated proof (Hard Rule #6).

Loads an MCPTox-style corpus of tool descriptors (poisoned + clean), runs each through
the engine's approval step, and reports REAL counts: N/M attacks blocked, plus any
false-positives on clean tools. `tripwire ci` fails the build if any attack survives.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .detection import Severity
from .engine import Action, TripwireEngine

DEFAULT_CORPUS = Path(__file__).resolve().parents[2] / "corpus" / "attacks.jsonl"


@dataclass
class CorpusResult:
    attacks_total: int
    attacks_blocked: int
    clean_total: int
    false_positives: int
    rows: list[dict]

    @property
    def all_attacks_blocked(self) -> bool:
        return self.attacks_total > 0 and self.attacks_blocked == self.attacks_total

    def summary(self) -> str:
        return (
            f"{self.attacks_blocked}/{self.attacks_total} attacks blocked · "
            f"{self.false_positives} false-positive(s) on {self.clean_total} clean tool(s)"
        )


def load_corpus(path: str | Path = DEFAULT_CORPUS) -> list[dict]:
    """Load a JSONL corpus. Each line: {id, expect: 'block'|'allow', category, tool:{...}}."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [json.loads(ln) for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def run_corpus(cases: list[dict], *, signing_key: str = "ci-only") -> CorpusResult:
    """Run each case and report real counts (Hard Rule #6).

    Case shapes:
      - Approval case: `tool` is checked by `engine.approve`. Counted as a blocked
        attack when `expect == "block"` and action is BLOCK; counted as a false
        positive when `expect == "allow"` and action is BLOCK.
      - Drift case (presence of `mutate_to`): the base `tool` is approved first
        (must ALLOW or the case is invalid), then `mutate_to` is fed to
        `evaluate_call`. The case "blocks the attack" iff QUARANTINE fires; if
        the mutation is identical to the original, expected behaviour is ALLOW
        and the case counts toward the clean / false-positive tally instead.
    """
    attacks_total = attacks_blocked = clean_total = false_positives = 0
    rows: list[dict] = []
    for case in cases:
        engine = TripwireEngine(signing_key, block_at=Severity.HIGH)
        base_decision = engine.approve(case["tool"])
        if "mutate_to" in case:
            # Drift case: the recorded action is the second-stage call verdict.
            if base_decision.action is Action.BLOCK:
                # The "before" tool was itself caught — malformed case, surface it.
                decision_action = Action.BLOCK
            else:
                decision_action = engine.evaluate_call(case["mutate_to"]).action
            attack_caught = decision_action is Action.QUARANTINE
        else:
            decision_action = base_decision.action
            attack_caught = decision_action is Action.BLOCK

        expect_block = case.get("expect") == "block"
        if expect_block:
            attacks_total += 1
            if attack_caught:
                attacks_blocked += 1
        else:
            clean_total += 1
            if decision_action in (Action.BLOCK, Action.QUARANTINE):
                false_positives += 1
        rows.append(
            {
                "id": case.get("id"),
                "category": case.get("category"),
                "expected": case.get("expect"),
                "action": decision_action.value,
                "ok": attack_caught == expect_block,
            }
        )
    return CorpusResult(attacks_total, attacks_blocked, clean_total, false_positives, rows)
