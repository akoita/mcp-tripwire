"""Attack-corpus runner — the measurable, non-fabricated proof (Hard Rule #6).

Loads an MCPTox-style corpus of tool descriptors (poisoned + clean), runs each through
the engine's approval step, and reports REAL counts: N/M attacks blocked, plus any
false-positives on clean tools. `tripwire ci` fails the build if any attack survives.

Per RFC-0003 §"Prerequisite — corpus row enrichment", every row also carries the
findings that fired (or a synthetic `MCP04-DRIFT` Finding for drift cases where the
scanner produces nothing), the source URI for the case (so SARIF results can
attribute back to it), and the approved fingerprint for drift cases. The SARIF
layer ([`tripwire.sarif`](sarif.py)) consumes these fields; the human / `--json`
output ignores them silently.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .detection import Finding, Severity, fingerprint, scan_tool
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


def _synthetic_drift_finding(case: dict, approved_fp: str) -> Finding:
    """Build the synthetic MCP04-DRIFT Finding for a quarantined drift case.

    The scanner produces no Finding for the post-mutation tool (rug-pull defense
    runs in `engine.evaluate_call`, not in `scan_tool`). The SARIF layer still
    needs ≥1 Finding per caught attack so the result attributes correctly —
    this synthetic one fills that gap and carries the OWASP MCP-04 mapping
    plus the fingerprint diff as evidence.
    """
    mutated = case.get("mutate_to", {})
    observed_fp = fingerprint(mutated) if isinstance(mutated, dict) else "<n/a>"
    name = (mutated or case.get("tool", {})).get("name", "<unnamed>")
    return Finding(
        rule="MCP04-DRIFT",
        title="Rug pull — schema drift since approval",
        severity=Severity.HIGH,
        owasp="MCP-04",
        evidence=(
            f"fingerprint mismatch (approved={approved_fp[:16]}…, observed={observed_fp[:16]}…)"
        ),
        tool=name,
    )


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

    Per RFC-0003 every row gains:
      - `findings`: the scanner output for the *decision-driving* tool
        descriptor (post-mutation for drift cases). Empty list for clean
        ALLOW cases. For caught drift cases the scanner returns nothing,
        so a synthetic MCP04-DRIFT Finding is added.
      - `source_uri`: `urn:tripwire:corpus:<case_id>` — per-case URI so SARIF
        consumers can group/filter by the originating corpus case.
      - `drift_from`: the approved fingerprint for drift cases (None otherwise).
    """
    attacks_total = attacks_blocked = clean_total = false_positives = 0
    rows: list[dict] = []
    for case in cases:
        engine = TripwireEngine(signing_key=signing_key, block_at=Severity.HIGH)
        base_decision = engine.approve(case["tool"])
        case_findings: list[Finding] = list(base_decision.findings)
        drift_from: str | None = None

        if "mutate_to" in case:
            # Drift case: the recorded action is the second-stage call verdict.
            if base_decision.action is Action.BLOCK:
                # The "before" tool was itself caught — malformed case, surface it.
                decision_action = Action.BLOCK
            else:
                drift_from = base_decision.fingerprint  # store the approved fp
                call_decision = engine.evaluate_call(case["mutate_to"])
                decision_action = call_decision.action
                # Findings on the post-mutation descriptor (may be empty if
                # the mutation introduced no scanner-visible signal).
                case_findings = list(scan_tool(case["mutate_to"]))
                # If quarantined with no scanner findings, synthesise one so
                # the SARIF layer attributes the caught attack correctly.
                if decision_action is Action.QUARANTINE and not case_findings and drift_from:
                    case_findings = [_synthetic_drift_finding(case, drift_from)]
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

        case_id = case.get("id", "?")
        rows.append(
            {
                "id": case_id,
                "category": case.get("category"),
                "expected": case.get("expect"),
                "action": decision_action.value,
                "ok": attack_caught == expect_block,
                # RFC-0003 enrichment fields:
                "findings": [f.as_dict() for f in case_findings],
                "source_uri": f"urn:tripwire:corpus:{case_id}",
                "drift_from": drift_from,
            }
        )
    return CorpusResult(attacks_total, attacks_blocked, clean_total, false_positives, rows)
