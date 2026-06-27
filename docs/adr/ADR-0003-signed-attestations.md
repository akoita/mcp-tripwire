# ADR-0003: Signed, tamper-evident attestations (the wedge)

- **Status:** accepted
- **Date:** 2026-06-27

## Context
Competitors emit a *report you must trust*. We want trust evidence that is portable and
*independently verifiable*, and that fails loudly on tamper — the differentiator.

## Decision
Every approved tool gets a signed **trust badge** binding `tool → fingerprint → status`.
v1 uses **HMAC-SHA256** (zero-dep, deterministic, demo-sufficient); the wire format is fixed
so a P1 upgrade to **Ed25519 / sigstore-style** asymmetric signing is drop-in. We do **not**
anchor to a blockchain — offline signing is right-sized; ledger anchoring is "vision" only.

## Consequences
- Hard Rule #1 (never trust an unverified manifest) — all trust flows through `attestation.py`.
- The proof moment ("tamper → verification fails") is built in and demoable.
- HMAC requires a shared secret; Ed25519 (P1) removes that for third-party verification.
