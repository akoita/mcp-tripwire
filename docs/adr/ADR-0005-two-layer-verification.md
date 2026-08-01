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

## Evidence (2026-08) — the second layer earned its place

*Appended after the fact; the decision above is unchanged and is kept as the
historical record.*

The [real-world attack suite](../features/real-world-attack-suite.md) is the
first measurement of this ADR's premise against material this project did not
author: **9 attack cases reproduced from published security research** (Invariant
Labs, MCPTox, Snyk), replayed through the real engine by `make audit`.

Measured outcome:

> **4 blocked · 1 advisory · 3 missed · 1 out-of-scope** (of 9 cases)
> **2 of the 4 blocks come from drift, not scanning.**

Two things this confirms:

1. **The two layers are genuinely different instruments, not redundancy.** The
   deterministic gate (`make eval`) reports **40/40 attacks blocked ·
   0 false-positive(s) on 12 clean tool(s)** and stayed green throughout — while
   the measurement layer showed 3 misses and 1 out-of-scope case on published
   attacks. A single layer would have reported only the flattering number. This
   is exactly the failure mode the ADR was written to prevent.
2. **`rw-09` is the empirical proof, and it is not circular.**
   `test_drift_catches_what_the_scanner_misses` asserts both halves:
   `scan_tool()` returns **zero findings** on the mutated descriptor — the
   content layer is provably blind, so the scanner is not grading its own
   homework — and `evaluate_call()` returns **QUARANTINE** anyway. An attack no
   content rule in this repo can see, stopped by comparing a fingerprint.

Consequence for how the layers are described from here on: they are **not equal
in strength**. Fingerprint drift and signed attestation are a deterministic
guarantee (hash + signature, zero false positives by construction); descriptor
scanning is a best-effort first pass with real false negatives. See
[TRUST_MODEL.md §1](../TRUST_MODEL.md#1-two-tiers-of-strength--read-this-first).

Corollary added to the flywheel rule: **misses are published, not tuned away.**
`rw-02`, `rw-07` and `rw-08` stay recorded as `missed` (tracked in
[#101](https://github.com/akoita/mcp-tripwire/issues/101)) rather than being
fixed by pattern-matching those exact strings, which would turn measured
evidence into a memorised answer key. `rw-04` stays recorded as `out_of_scope`
because the real `postmark-mcp` compromise never changed the published manifest.
