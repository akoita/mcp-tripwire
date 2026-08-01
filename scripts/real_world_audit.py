#!/usr/bin/env python3
"""Real-world attack suite — measured audit report (Hard Rule #6).

Runs every case in `corpus/real_world/attacks.jsonl` — attacks reproduced from
PUBLISHED security research, each carrying its citation — through the real
engine and prints what ACTUALLY happened, including the misses.

This is a REPORT, not a gate. `corpus/attacks.jsonl` + `make eval` is the
pass/fail gate (and must stay 100% blocked); this suite measures real-world
efficacy honestly, so a `missed` case is expected data, not a failure. The
script therefore always exits 0. The pass/fail contract for this suite lives
in `tests/security/test_real_world_attacks.py`, which asserts that the
measured outcomes still match the recorded ones.

Stdlib-only, like the deterministic core it audits.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tripwire.engine import Action, TripwireEngine  # noqa: E402 — after sys.path bootstrap

CORPUS = ROOT / "corpus" / "real_world" / "attacks.jsonl"
OUTCOMES = ("blocked", "advisory", "missed", "out_of_scope")


def load_cases(path: Path = CORPUS) -> list[dict]:
    """Load the JSONL suite: one case object per non-empty, non-comment line."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(ln) for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def classify(case: dict) -> tuple[str, str]:
    """Run one case through a fresh engine and return the measured (outcome, layer).

    - Approval-time cases: BLOCK => blocked/scanner, findings-but-allowed =>
      advisory/scanner (the operator sees a signal but the call proceeds),
      nothing at all => missed/none.
    - Drift cases (`mutate_to` present): the scanner gets first refusal on the
      benign descriptor; otherwise the mutated descriptor is fed to
      `evaluate_call` and QUARANTINE => blocked/drift. Anything else means no
      Tripwire layer can see the attack => out_of_scope/none.
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


def _rows(cases: list[dict]) -> list[dict]:
    rows = []
    for case in cases:
        outcome, layer = classify(case)
        rows.append(
            {
                "id": case.get("id", "?"),
                "technique": case.get("technique", "?"),
                "layer": layer,
                "outcome": outcome,
                "source_name": case.get("source", {}).get("name", "?"),
                "source_url": case.get("source", {}).get("url", "?"),
            }
        )
    return rows


def render(rows: list[dict]) -> str:
    """Render the audit table + summary as text (measured values only)."""
    headers = {"id": "ID", "technique": "TECHNIQUE", "layer": "LAYER", "outcome": "OUTCOME"}
    widths = {
        key: max(len(label), *(len(row[key]) for row in rows)) for key, label in headers.items()
    }
    indent = " " * (sum(widths.values()) + 2 * len(widths))
    out: list[str] = [
        "Real-world attack suite — measured audit",
        f"corpus: {CORPUS.relative_to(ROOT)}",
        "",
        "  ".join(headers[key].ljust(widths[key]) for key in headers) + "  SOURCE",
        "  ".join("-" * widths[key] for key in headers) + "  " + "-" * 6,
    ]
    for row in rows:
        out.append(
            "  ".join(row[key].ljust(widths[key]) for key in headers) + f"  {row['source_name']}"
        )
        out.append(indent + row["source_url"])
    counts = {name: sum(1 for row in rows if row["outcome"] == name) for name in OUTCOMES}
    out += [
        "",
        f"{len(rows)} case(s) · "
        + " · ".join(f"{counts[name]} {name}" for name in OUTCOMES)
        + f" · caught by drift: {sum(1 for r in rows if r['layer'] == 'drift')}",
        "Misses are recorded deliberately: this suite reports real-world efficacy,",
        "it is not the pass/fail gate (that is `make eval` on corpus/attacks.jsonl).",
    ]
    return "\n".join(out)


def main() -> int:
    print(render(_rows(load_cases())))
    return 0  # a report, never a gate — `missed` cases are data, not failures


if __name__ == "__main__":
    sys.exit(main())
