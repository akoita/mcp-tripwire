# ADR-0005: Two-layer verification (tests + evals)

- **Status:** accepted
- **Date:** 2026-06-27

## Context
Day-1/Day-4 guidance: deterministic tests alone miss model-driven behaviour; evals alone are
fuzzy. "Without both, the practice is always vibe coding."

## Decision
Ship **both** layers and write them **before** the code:
- Deterministic `pytest` for signing, fingerprinting, drift, and decisions.
- Non-deterministic evals (`tests/eval/`): an attack corpus with real `N/M` counts +
  deterministic custom metrics (precision/recall/attestation-validity) + an LLM-judge for
  explanation quality.

## Consequences
- Hard Rules #5 and #6 (test-first; never fabricate metrics).
- `make check` gates the deterministic layer; `agents-cli eval` drives the non-deterministic one.
- New attacks must arrive as new corpus cases (the flywheel).
