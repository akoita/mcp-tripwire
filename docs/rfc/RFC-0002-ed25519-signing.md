# RFC-0002 — Ed25519 over HMAC for trust badges

**Status:** **draft — REVIEW REQUESTED**
**Author:** Aboubakar Koita (with Claude)
**Issue:** [#31](https://github.com/akoita/mcp-tripwire/issues/31)
**Relates to:** [ADR-0003 signed attestations](../adr/ADR-0003-signed-attestations.md), [`src/tripwire/attestation.py`](../../src/tripwire/attestation.py)
**Targets:** v0.2 — first piece (blocking SARIF #32 and HTTP/SSE transport #33).

## Why this exists

Today every trust badge is HMAC-SHA256 over a canonical JSON payload. HMAC requires the verifier to know the same secret the signer used. That's fine for one team running both ends of a CI loop. It is **not** what the README promises:

> Tripwire's contribution is […] **portable, independently-verifiable attestations** […]
> verification needs only the public key.

That sentence is currently aspirational. Ed25519 is the move that makes it real.

## Goals (in scope for v0.2 #31)

1. Operators can generate an Ed25519 keypair, sign badges with the private key, and hand the public key (or its file) to any verifier — internal CI, a downstream auditor, a sister team — without sharing the private key.
2. Tripwire's own verifier (`attestation.verify_badge`, CLI `tripwire verify`, HTTP `/verify`) accepts Ed25519-signed badges; the alg is inspected on the badge itself.
3. Existing HMAC badges keep verifying for the operators currently issuing them — no flag-day migration.
4. The deterministic core stays stdlib-only at the `attestation.py` boundary. Ed25519 lives in a new `src/tripwire/signing/` subpackage, exempted from Hard Rule #2 in the same way `src/tripwire/agents/` already is.
5. `cryptography` is the chosen Ed25519 backend (rationale below); brought in via a new `[signing]` extra so the core stays installable without it.

## Non-goals (cuts for v0.2)

- Sigstore / Rekor anchoring. Stays P2 — interesting once we have v1.0 users asking for it.
- Hardware key support (YubiKey, Cloud HSM). Operator-managed keys on disk for now.
- Multi-key rotation policy. Operator runs `tripwire key gen` again and reconfigures; no automatic re-issuance.
- Replacing the badge JSON shape. Same shape, new `alg` value.

## Architecture

### The boundary stays where it is

`engine.py` will continue to call only the public functions in `attestation.py` — `issue_badge(...)` and `verify_badge(...)`. Those two functions become **alg-dispatching**: they inspect a configured backend (for signing) or the badge's `alg` field (for verifying) and route to either the existing HMAC code or the new Ed25519 backend.

```
                ┌────────────────────────┐
   engine.py ──▶│ attestation.py          │       stdlib-only (Rule #2 OK)
                │  issue_badge / verify   │
                └──────────┬──────────────┘
                           │ dispatches on alg
              ┌────────────┴────────────┐
              ▼                         ▼
  signing/hmac_backend.py     signing/ed25519_backend.py    new subpackage,
  (stdlib only)               (uses `cryptography`)         exempted from Rule #2
```

The new subpackage `src/tripwire/signing/` joins `src/tripwire/agents/` on the harness-guardrails exception list. That is a deliberate, machine-verifiable widening of the rule and is documented in this RFC's acceptance section so the guardrails change can't slip in silently.

### Library choice — `cryptography`

| Candidate | Pros | Cons |
|---|---|---|
| **`cryptography`** | well-audited, widely available, ships Ed25519 in `cryptography.hazmat.primitives.asymmetric.ed25519`; already a transitive of `google-adk` (so v0.2 doesn't add net-new dep weight for `[agent]` users) | compiled wheels (OpenSSL); slightly larger install |
| `PyNaCl` | libsodium binding, very clean API | extra native dep that adds no capability the cryptography package doesn't already give us |
| `pyca/ed25519` pure-python | zero native code | unmaintained since 2017, no constant-time guarantees |
| custom impl | nothing extra to ship | bad idea on principle |

Choosing `cryptography` because it's already transitively present for any operator who installs `[agent]`, and the standalone install cost for HTTP-only users is one well-known wheel.

### Key formats and storage

- Private key: PEM-encoded PKCS#8 (industry default; `openssl pkey -text` works). The file is written with mode `0o600`; the CLI refuses to overwrite an existing path without `--force`.
- Public key: PEM-encoded SubjectPublicKeyInfo. Cheap to share, safe to publish.
- Where keys live: operator's choice via `--priv` / `--pub` arguments and `TRIPWIRE_PRIVATE_KEY_PATH` / `TRIPWIRE_PUBLIC_KEY_PATH` env vars. No default home-dir caching — Tripwire never auto-discovers a key.

### Badge shape

Unchanged structurally; only the `alg` value and the `sig` encoding change:

```json
{
  "tool": "get_weather",
  "fingerprint": "a8cbde7f6ea1380a295c4490c5a3bc2d…",
  "status": "trusted",
  "issued_at": "2026-07-15T11:30:00+00:00",
  "alg": "Ed25519",
  "sig": "MEUCIQCx…base64…"
}
```

- For HMAC: `sig` is the existing lowercase hex digest.
- For Ed25519: `sig` is the **base64** encoding of the 64-byte raw signature (urlsafe-no-pad, RFC 4648 §5). Chosen over hex to keep payloads compact.
- `alg` strings: `"HMAC-SHA256"` (current) and `"Ed25519"` (new). Any other value verifies as `False, "unsupported alg: <value>"`.

### Verification dispatch

```python
def verify_badge(badge: dict, *, key: str | bytes | None = None,
                 public_key_pem: bytes | None = None) -> tuple[bool, str]:
    alg = badge.get("alg")
    if alg == "HMAC-SHA256":
        return _hmac_backend.verify(badge, key=key)          # backward-compat
    if alg == "Ed25519":
        return _ed25519_backend.verify(badge, public_key_pem=public_key_pem)
    return False, f"unsupported alg: {alg!r}"
```

The signature on the public API gains an optional `public_key_pem` kwarg. Callers that only ever verify HMAC badges keep working unchanged. Callers that pass either kwarg get the right backend.

### Signing dispatch (engine side)

`engine.TripwireEngine.__init__` today takes `signing_key: str | bytes` (the HMAC secret). It will gain an optional `signing_backend: Literal["hmac", "ed25519"]` argument plus an optional `private_key_pem: bytes | None`. Default behaviour (no kwargs change) stays HMAC for backward-compatibility. Programmatic Ed25519 use:

```python
engine = TripwireEngine(
    signing_key=b"",  # ignored for ed25519
    signing_backend="ed25519",
    private_key_pem=Path("/secrets/tripwire.pem").read_bytes(),
)
```

CLI / HTTP-server callers don't construct an engine directly with these args; they read env vars in their own thin layer (see "CLI surface" below) and pass them through.

## CLI surface

Two new subcommands on the `tripwire` CLI:

```
tripwire key gen --priv <path> --pub <path> [--force]
    Generate a fresh Ed25519 keypair. Writes private key as PEM (mode 0o600)
    and public key as PEM. Refuses to overwrite existing paths without --force.

tripwire key pub --priv <path>
    Read a private-key PEM file and print the matching public-key PEM on
    stdout (so an operator can extract the public key without re-generating).
```

`tripwire verify` gains:

```
tripwire verify <badge.json> [--pub <path>]
    If the badge alg is Ed25519, --pub (or env TRIPWIRE_PUBLIC_KEY_PATH /
    TRIPWIRE_PUBLIC_KEY_PEM) is required. If HMAC, falls back to
    TRIPWIRE_SIGNING_KEY as today.
```

Exit codes from `tripwire verify` are unchanged (0 valid, 2 tampered, 3 invalid/malformed). A missing public key when verifying an Ed25519 badge produces exit 3 with a clear message.

## Backward compatibility

| Scenario | Behaviour |
|---|---|
| Existing operator using HMAC, no env changes | Engine signs HMAC, `verify` accepts HMAC. Identical to today. |
| New operator wants Ed25519 | Generates a keypair, sets `TRIPWIRE_PRIVATE_KEY_PATH`. Engine sees the env, switches to Ed25519 backend. New badges have `alg: "Ed25519"`. |
| Mixed deployment (some HMAC badges in flight, new Ed25519 minted forward) | `verify` dispatches per-badge on `alg`. Works for both during the migration window. |
| Verifier-only environment | Only needs the public key; private key never present. The `[signing]` extra (which brings `cryptography`) is the only install requirement beyond the core. |

## Test plan

1. **Round-trip** — `key gen` → load private → `issue_badge` → load public → `verify_badge` → `(True, "valid")`.
2. **Tamper any field** — flip a byte in `fingerprint`, `issued_at`, `tool`, or `status` → `(False, "signature mismatch …")`. Same five fields exercised today for HMAC.
3. **Wrong key** — generate keypair A, sign with A, attempt verify with public key B → `(False, "signature mismatch …")`.
4. **Wrong alg in badge** — flip `alg` from `"Ed25519"` to `"HMAC-SHA256"` while leaving the Ed25519 signature → either `(False, "missing signature")` or the HMAC verifier rejects on shape; assert it's caught.
5. **Mixed corpus** — `tests/integration/test_attestation_mixed.py` issues N HMAC badges + N Ed25519 badges + N badges with `alg: "garbage"`, runs them all through `verify_badge`, asserts the right outcome class for each.
6. **CLI** — new `tests/unit/test_cli_key.py` covers `tripwire key gen` (file written with mode 0600), `tripwire key pub` (reads private, prints matching public), `tripwire verify --pub` happy + wrong-key + missing-pub paths.
7. **HTTP** — `tests/integration/test_http_endpoints.py` extended with one Ed25519-badge case on `/verify` to prove the dispatch works through the FastAPI layer.
8. **Harness guardrails** — extend `scripts/harness_guardrails.py` `_py_files(..., exclude=("agents", "signing"))` and add a self-test that `from tripwire.attestation import verify_badge` works in an env that has **only** stdlib + `tripwire` installed (i.e. `[signing]` not pulled in — Ed25519 backend lazy-loaded, HMAC backend works).

Acceptance criterion for the implementation PR: every existing test in the suite keeps passing AND the 7 new test groups above all pass.

## Open questions for the reviewer

1. **PEM vs raw?** I picked PEM for human-handleability (`cat` shows it, `openssl pkey` parses it). Alternative: raw 32-byte private + 32-byte public files. PEM is more verbose but matches every other tool an operator already uses. **Recommendation: PEM. Push back if you want raw.**

2. **Single CLI command `tripwire key` vs splitting into `tripwire keygen`?** Subcommand grouping (`tripwire key gen` / `tripwire key pub`) leaves room for `tripwire key rotate`, `tripwire key fingerprint`, etc. Top-level commands would be flatter but harder to extend.

3. **Should `[signing]` extra be folded into `[agent]`?** `cryptography` is already a transitive of `google-adk`. If we declare it directly under `[signing]`, an HTTP-only operator who skips `[agent]` still gets the option to install `[signing]` for Ed25519. Folding into `[agent]` would surprise an HTTP-only operator who'd need to install the whole ADK layer just to sign with Ed25519. **Recommendation: separate `[signing]` extra.**

4. **Default backend selection rule.** I'm proposing: if `TRIPWIRE_PRIVATE_KEY_PATH` is set, use Ed25519. Else if `TRIPWIRE_SIGNING_KEY` is set, use HMAC. Else use HMAC with the dev placeholder. Reviewer should sanity-check that this priority order matches what feels obvious for an operator who reads `env` for the first time.

5. **Drop the dev placeholder?** Today `_signing_key()` defaults to `"dev-only-change-me"`. Reasonable, easy to demo, but allows accidental production signing with a known key. Should the v0.2 implementation harden this — refuse to sign unless either env is explicitly set, even in dev mode? **Recommendation: yes, refuse-by-default with a one-flag escape hatch (`TRIPWIRE_ALLOW_DEV_KEY=1`). Pre-existing demos would set the flag once in `Makefile`.**

## Day-N implementation plan (post-RFC merge)

| Slot | Step | Exit signal |
|---|---|---|
| 1h | Add `[signing]` extra; widen `harness_guardrails.py` exclude list to `("agents", "signing")` + the importable-without-the-extra self-test | guardrails still pass |
| 2h | Implement `signing/ed25519_backend.py` (`sign(payload, private_key_pem) -> str`, `verify(badge, public_key_pem) -> (bool, str)`) | unit tests in 1, 2, 3 above pass against the backend in isolation |
| 1.5h | Refactor `attestation.py` to dispatch by alg; HMAC code moves to `signing/hmac_backend.py` | every existing test still passes; mixed-corpus test (5) passes |
| 1.5h | `tripwire key gen` / `tripwire key pub` CLI; `tripwire verify --pub` | CLI tests (6) pass |
| 1h | HTTP `/verify` extended; one Ed25519 case in `test_http_endpoints.py` | test (7) passes |
| 0.5h | README implementation-status row flip; STATUS.md update | `make eval` + `make demo*` still green from a fresh clone |
| 0.5h | Buffer | (use it or bank it) |

≈ 8h total — fits the deliberate-pace single-RFC, single-PR rhythm.
