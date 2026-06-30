# Signed trust badges (attestation)

> **Status:** ✅ implemented — HMAC-SHA256 default plus Ed25519 via the `[signing]` extra ([RFC-0002](../rfc/RFC-0002-ed25519-signing.md), [#31](https://github.com/akoita/mcp-tripwire/issues/31)).
> **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)

## Value (what this gives the agent / LLM)

When an agent approves a tool descriptor, Tripwire mints a **signed badge** that binds `tool name → fingerprint → status → timestamp` with a cryptographic signature. The agent can:

- **Carry the badge** alongside the tool, so a downstream consumer (another agent, a CI step, an audit pipeline) can confirm the agent's claim to have approved this exact descriptor.
- **Re-verify the badge later** to catch payload tampering — flip one byte of the descriptor and verification fails.
- **Detect substitution** — a badge for a different tool, or for the same tool with a different fingerprint, won't validate.

This is the project's **wedge** (see [ADR-0003](../adr/ADR-0003-signed-attestations.md)): static scanners emit *reports you must trust*; Tripwire emits *trust evidence anyone can audit*.

## Audience

- **LLM agent** that wants to prove it vetted a specific tool descriptor.
- **Downstream auditor** (CI step, compliance check, sibling team) that consumes badges.
- **Operator** running `tripwire verify` to confirm a stored badge still validates.

## How it works today

`engine.approve(tool: dict) -> Decision` runs the scanner; if no HIGH+ findings, it computes a canonical fingerprint of the descriptor and mints a badge:

```python
# src/tripwire/attestation.py
{
  "tool":        "get_weather",
  "fingerprint": "a8cbde7f6ea1380a295c4490c5a3bc2d…",  # SHA-256 of canonical descriptor
  "status":      "trusted",
  "issued_at":   "2026-07-15T11:30:00+00:00",
  "alg":         "HMAC-SHA256",
  "sig":         "8d714583daa51ac434ef1a00bb3fc266…"  # HMAC(key, canonical(payload))
}
```

For the zero-dependency path, `attestation.verify_badge(badge: dict, key: str) -> tuple[bool, str]` re-computes the HMAC over the canonical payload and uses `hmac.compare_digest` for constant-time comparison.

For the independently-verifiable path, `tripwire key gen` creates an Ed25519 private key, `tripwire key pub` derives the public key, and `tripwire verify --pub <public.pem> <badge.json>` verifies the badge without sharing the signing secret. The HTTP `/verify` endpoint can also dispatch by `alg` when `TRIPWIRE_PUBLIC_KEY_PATH` is configured.

The signing key comes from the `TRIPWIRE_SIGNING_KEY` env var (Hard Rule #3 — never hardcoded).
Badge minting and verification refuse to proceed when the env var is missing; the only
fallback key is the inert `ci-only` value used inside the attack-corpus measurement loop.

## Contract

```python
# src/tripwire/attestation.py
def issue_badge(tool_name: str, fingerprint: str, key: str | bytes,
                *, status: str = "trusted",
                issued_at: str | None = None) -> dict: ...
def verify_badge(badge: dict, key: str | bytes) -> tuple[bool, str]: ...
def sign(payload: dict, key: str | bytes) -> str: ...
```

Wire format is stable across algorithms: Ed25519 preserves the schema, with `alg: "Ed25519"` and a base64url signature. Verifiers dispatch per badge on the `alg` field.

## Surfaces

| Surface | How to reach it |
|---|---|
| CLI key management | `tripwire key gen` creates an Ed25519 keypair; `tripwire key pub` prints the public key. |
| CLI verify | `tripwire verify <badge.json>` for HMAC, or `tripwire verify --pub <public.pem> <badge.json>` for Ed25519 — exit 0 valid / 2 tampered / 3 malformed. |
| HTTP verify | `POST /verify` body `{"badge": {...}}` → `{"valid", "status", "reason", "tool"}` |
| ADK | The Attestor agent ([`src/tripwire/agents/attestor_agent.py`](../../src/tripwire/agents/attestor_agent.py)) wraps `engine.approve` in `FunctionTool(require_confirmation=True)` — runtime requires explicit user OK before a badge is minted. |
| Python | `from tripwire import issue_badge, verify_badge` |

## Verification

- Unit: [`tests/unit/test_attestation.py`](../../tests/unit/test_attestation.py) — round-trip, tamper-per-field, wrong-key.
- Unit (CLI): [`tests/unit/test_cli.py`](../../tests/unit/test_cli.py) — three exit codes per failure mode, Ed25519 `--pub`, and missing-key fail-closed handling.
- HTTP: [`tests/integration/test_http_endpoints.py`](../../tests/integration/test_http_endpoints.py) — valid / tampered / malformed paths.
- Demo: `make demo` ends with `verify(original badge): True` then `verify(tampered badge): False` as the proof moment.

## Guarantees and limitations

- **Tamper-evident** — any change to `tool / fingerprint / status / issued_at / alg` invalidates the signature; constant-time compare prevents timing oracles.
- **Fail-closed key handling** — user-facing trust flows require `TRIPWIRE_SIGNING_KEY`; missing configuration returns an invalid/refused result instead of silently using a development key.
- **HMAC requires a shared secret** — fine for one team running both ends. Ed25519 closes the third-party-verification gap when operators install `[signing]` and distribute the public key.
- **No anchoring** to a public ledger (sigstore / Rekor stays P2; only interesting once we have v1.0 users asking).
- **One key per process** — multi-tenant key management is operator concern; Tripwire doesn't ship a key vault.

## Cross-references

- Companion: [descriptor-scanning.md](descriptor-scanning.md) — what determines whether a badge is mintable.
- Companion: [drift-quarantine.md](drift-quarantine.md) — why the fingerprint is the load-bearing field.
- Companion: [ed25519-signing.md](ed25519-signing.md) — the v0.2 public-key verification path.
- ADR: [docs/adr/ADR-0003-signed-attestations.md](../adr/ADR-0003-signed-attestations.md).
- RFC: [RFC-0002](../rfc/RFC-0002-ed25519-signing.md) — accepted design for the alg upgrade.
