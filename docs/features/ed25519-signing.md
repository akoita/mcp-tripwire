# Ed25519 third-party verifiable badges

> **Status:** ✅ implemented · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)
> **Design:** [RFC-0002 (accepted)](../rfc/RFC-0002-ed25519-signing.md) · **Implementation:** [#31](https://github.com/akoita/mcp-tripwire/issues/31)

## Value (what this gives the agent / auditor)

Today's badges are HMAC-SHA256 — verification requires the **shared secret** the signer used. That's fine for one team running both ends of a CI loop. It doesn't scale to *"any operator can audit any Tripwire badge they're handed,"* which is what the README's [**"portable, independently-verifiable attestations"**](../../README.md) claim actually requires.

Ed25519 closes that gap. A downstream consumer needs only the **public key** to verify; the signing private key never leaves the issuer's process. The badge ecosystem becomes genuinely portable — three Tripwire users verify the same badge in three different processes (CI, runtime gateway, downstream audit pipeline) and all reach the same verdict without speaking to each other or sharing a secret.

This is the **second piece** of v0.2 by ordering — lands after [SARIF](sarif-output.md) so the badge metadata SARIF is already carrying becomes a real-world artefact a third party can audit.

## Audience

- **Downstream auditor** verifying badges from a different team.
- **LLM agent** that wants to hand a badge to a *different* agent without sharing keys.
- **Compliance pipeline** consuming Tripwire badges as evidence in a regulated workflow.

## Implemented surfaces

| Surface | What changes |
|---|---|
| `tripwire key gen --out <path>` | CLI subcommand — Ed25519 keypair as PEM, private mode 0o600, refuses overwrite without `--force`, prints the public key PEM on stdout. |
| `tripwire key pub --in <path>` | Print the matching public key without re-generating. |
| `tripwire verify <badge.json> [--pub <path>]` | Dispatches on the badge's `alg` field — HMAC keeps working; Ed25519 needs `--pub` (or `TRIPWIRE_PUBLIC_KEY_PATH`). |
| `engine.approve()` | When `signing_backend` is Ed25519, emits badges with `alg: "Ed25519"` and base64-encoded sig. |
| HTTP `/verify` | Same per-alg dispatch through `VerifyRegistry`. |

The wire format is **identical** to today — only the `alg` value and the `sig` encoding change. HMAC badges in flight keep verifying during the migration window.

## Design highlights (full spec in the RFC)

- **`src/tripwire/signing/`** is a new subpackage that joins `src/tripwire/agents/` as an explicit Rule #2 exception. The boundary is `attestation.py`, which stays stdlib-only and dispatches per alg. The `cryptography` library (already transitive via `google-adk`) lives behind a new `[signing]` extra — installable without `[agent]` for HTTP-only / verifier-only operators.
- **Rule #2 widening is atomic with the implementation** — the implementation PR updates AGENTS.md Hard Rule #2 + ADR-0001/ADR-0003 + `harness_guardrails.py` exclude list in the same commit set. Documented in [RFC-0002 §Rule update](../rfc/RFC-0002-ed25519-signing.md#rule-update-hard-rule-2-widening).
- **One config resolver**, asymmetric by role: `resolve_signing_backend()` returns the one chosen backend (per process); `resolve_verify_registry()` returns a per-alg dispatch table so mixed HMAC + Ed25519 traffic during migration works in one process (Codex round-2 note).
- **Dev placeholder refused by default** — `TRIPWIRE_ALLOW_DEV_KEY=1` opts in; production fails fast on a forgotten key. Demo targets set the env explicitly.

The full architecture, key formats, configuration table, test plan, and Day-N (~8h) implementation plan are in [RFC-0002](../rfc/RFC-0002-ed25519-signing.md).

## Status

**Implemented** in [#31](https://github.com/akoita/mcp-tripwire/issues/31) — [PR #44](https://github.com/akoita/mcp-tripwire/pull/44) (slots 1-4: SSOT widening, `signing/` subpackage, `Ed25519Backend`, env-driven resolvers, alg-dispatcher) plus follow-up work landing the CLI (`tripwire key gen --out` / `tripwire key pub --in` / `tripwire verify --pub`) and the Ed25519 case on the FastAPI `/verify` endpoint.

Wire format unchanged on the badge side; only the new `alg="Ed25519"` value and base64-encoded `sig` are added. HMAC stays the default — operators opt into Ed25519 by configuring `TRIPWIRE_PRIVATE_KEY_PATH` (sign) / `TRIPWIRE_PUBLIC_KEY_PATH` (verify) or by installing the `[signing]` extra (`pip install 'mcp-tripwire[signing]'`).

## Cross-references

- Design: [RFC-0002](../rfc/RFC-0002-ed25519-signing.md).
- Tracking: [#31](https://github.com/akoita/mcp-tripwire/issues/31), [milestone v0.2.0](https://github.com/akoita/mcp-tripwire/milestone/1).
- Companion (current HMAC path): [signed-trust-badges.md](signed-trust-badges.md).
- Companion (transport that ferries the badge): [sarif-output.md](sarif-output.md).
- ADR: [docs/adr/ADR-0003-signed-attestations.md](../adr/ADR-0003-signed-attestations.md) — forward-references the Ed25519 upgrade as the natural follow-on.
