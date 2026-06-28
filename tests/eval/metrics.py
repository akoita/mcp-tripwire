"""Deterministic custom metrics referenced by eval_config.yaml.

These compute REAL numbers from the engine over the shipped corpus (Hard Rule #6) — they
are the CodeExecutionMetrics the course's eval methodology pairs with LLM-judge metrics.
Also runnable directly:  PYTHONPATH=src python -m tests.eval.metrics
"""

from __future__ import annotations

from tripwire import TripwireEngine, verify_badge
from tripwire.corpus import load_corpus, run_corpus


def detection_precision() -> float:
    r = run_corpus(load_corpus())
    tp, fp = r.attacks_blocked, r.false_positives
    return tp / (tp + fp) if (tp + fp) else 1.0


def detection_recall() -> float:
    r = run_corpus(load_corpus())
    return r.attacks_blocked / r.attacks_total if r.attacks_total else 1.0


def attestation_validity() -> float:
    """1.0 iff a freshly-issued badge verifies AND a tampered badge fails."""
    eng = TripwireEngine(signing_key="eval-key")
    d = eng.approve(
        {"name": "ok", "description": "benign", "inputSchema": {}},
        issued_at="2026-01-01T00:00:00+00:00",
    )
    ok, _ = verify_badge(d.badge, "eval-key")
    tampered = dict(d.badge, fingerprint="deadbeef")
    bad, _ = verify_badge(tampered, "eval-key")
    return 1.0 if (ok and not bad) else 0.0


if __name__ == "__main__":
    print(f"detection_precision  = {detection_precision():.3f}")
    print(f"detection_recall     = {detection_recall():.3f}")
    print(f"attestation_validity = {attestation_validity():.3f}")
