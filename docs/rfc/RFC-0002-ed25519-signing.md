# RFC-0002 — Ed25519 over HMAC for trust badges

**Status:** **accepted (v3 — Codex review folded in, sign-off received 2026-06-28)**
**Author:** Aboubakar Koita (with Claude)
**Issue:** [#31](https://github.com/akoita/mcp-tripwire/issues/31)
**Relates to:** [ADR-0001 trust gateway](../adr/ADR-0001-mcp-trust-gateway.md), [ADR-0003 signed attestations](../adr/ADR-0003-signed-attestations.md), [`src/tripwire/attestation.py`](../../src/tripwire/attestation.py)
**Targets:** v0.2 — **second piece** (lands after SARIF #32, which is the fastest usefulness jump). Ed25519 closes the credibility gap on the badge metadata SARIF will already be carrying.

## Why this exists

Today every trust badge is HMAC-SHA256 over a canonical JSON payload. HMAC requires the verifier to know the same secret the signer used. That's fine for one team running both ends of a CI loop. It is **not** what the README promises:

> Tripwire's contribution is […] **portable, independently-verifiable attestations** […]
> verification needs only the public key.

That sentence is currently aspirational. Ed25519 is the move that makes it real. Ordering note: SARIF (#32) goes first because it's the bigger usefulness jump; this RFC's implementation lands after #32 so SARIF immediately speaks the new alg in its `partialFingerprints` / signature metadata.

## Goals (in scope for v0.2 #31)

1. Operators can generate an Ed25519 keypair, sign badges with the private key, and hand the public key (or its file) to any verifier — internal CI, a downstream auditor, a sister team — without sharing the private key.
2. Tripwire's own verifier (`attestation.verify_badge`, CLI `tripwire verify`, HTTP `/verify`) accepts Ed25519-signed badges; the alg is inspected on the badge itself.
3. Existing HMAC badges keep verifying for the operators currently issuing them — no flag-day migration.
4. `cryptography` is the chosen Ed25519 backend (rationale below); brought in via a new `[signing]` extra so the core stays installable without it.
5. The deterministic core stays well-defined. Ed25519 lives in a new `src/tripwire/signing/` subpackage. **This widens Hard Rule #2's exception list and so requires atomic updates to AGENTS.md, ADR-0001, and `scripts/harness_guardrails.py` — see §Rule update below.**

## Non-goals (cuts for v0.2)

- Sigstore / Rekor anchoring. Stays P2 — interesting once we have v1.0 users asking for it.
- Hardware key support (YubiKey, Cloud HSM). Operator-managed keys on disk for now.
- Multi-key rotation policy. Operator runs `tripwire key gen` again and reconfigures; no automatic re-issuance.
- Replacing the badge JSON shape. Same shape, new `alg` value.

## Rule update (Hard Rule #2 widening)

> **This was the main pushback in the Codex review of v1 of this RFC.** Per AGENTS.md today, the only allowed third-party-importing subpackage of `src/tripwire/` is `agents/`. This RFC proposes adding `signing/` to that exception list, but **the rule change does not become real when this RFC merges** — the rule change is part of the implementation PR's acceptance criteria, landing atomically with the new code.

The implementation PR for #31 MUST update, in the same commit set:

- **`AGENTS.md` line 23** (Hard Rule #2 statement) — change `"except agents/"` → `"except agents/ and signing/"`, with a one-line justification ("pluggable crypto backends follow the same ports-and-adapters pattern as the ADK layer; the `attestation.py` engine boundary stays stdlib-only").
- **`AGENTS.md` line 15** (Stack §Deterministic core) — mirror the same exception.
- **`AGENTS.md` line 49** (Conventions §Core modules) — mention `optional crypto backends in src/tripwire/signing/`.
- **`docs/adr/ADR-0001-mcp-trust-gateway.md` §Consequences** — add a bullet: "Pluggable backends (agents/, signing/) are explicit exceptions to the stdlib-only rule; each is gated behind an optional extra (`[agent]` / `[signing]`) and is import-guarded so a base install never pulls them."
- **`docs/adr/ADR-0003-signed-attestations.md` §Consequences** — the existing "Ed25519 (P1) removes that for third-party verification" line gains a forward-ref to RFC-0002.
- **`scripts/harness_guardrails.py`** — the `_py_files(CORE, exclude=("agents",))` call gains `"signing"`. Plus a new check `check_signing_backend_is_lazy_imported()` that fails the build if `attestation.py` does an unconditional `from .signing import ...` at module level — the engine must NEVER eagerly import a backend that may not be installed.

If reviewer prefers **not** to widen Rule #2 and instead keep crypto outside `src/tripwire/` entirely, the alternative is to ship a sibling distribution `tripwire-signing` (separate `pyproject.toml`, separate wheel). That's a noticeably heavier change to project packaging; the recommendation is to widen the rule and document the pattern, because the existing `agents/` exception already establishes the precedent and the next pluggable backend (whatever it turns out to be) will follow the same shape. **Reviewer should pick one path explicitly before this RFC merges.**

## Architecture

### The boundary stays where it is

`engine.py` continues to call only the public functions in `attestation.py` — `issue_badge(...)` and `verify_badge(...)`. Those two functions become **alg-dispatching**: they consult a backend registry (for signing, based on the engine's configured backend) or inspect the badge's `alg` field (for verifying) and route to either the existing HMAC code or the new Ed25519 backend.

```
                ┌────────────────────────┐
   engine.py ──▶│ attestation.py          │       stdlib-only (Rule #2 boundary)
                │  issue_badge / verify   │       dispatches on backend / alg
                └──────────┬──────────────┘
                           │ lazy import (only when used)
              ┌────────────┴────────────┐
              ▼                         ▼
  signing/hmac_backend.py     signing/ed25519_backend.py    new subpackage,
  (stdlib only)               (uses `cryptography`)         ★ widens Rule #2
```

The HMAC code today living in `attestation.py` moves into `signing/hmac_backend.py` for symmetry with the Ed25519 path. `attestation.py` becomes the thin dispatcher.

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
- Where keys live: operator's choice via `--priv` / `--pub` arguments and the resolver env vars (see §Configuration below). No default home-dir caching — Tripwire never auto-discovers a key.

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

### Backend protocol

```python
# src/tripwire/signing/__init__.py
from typing import Protocol

class SigningBackend(Protocol):
    alg: str  # canonical alg string written into badges, e.g. "Ed25519"
    def sign(self, payload: dict) -> str: ...
    def verify(self, badge: dict) -> tuple[bool, str]: ...
```

`HmacBackend(key: bytes)` and `Ed25519Backend(private_key_pem: bytes | None, public_key_pem: bytes | None)` both satisfy it. The Ed25519 backend can be constructed verify-only (private key absent).

### Configuration — ONE resolver, asymmetric by role

> **v1 contradiction (engine reading env vs CLI/HTTP reading env): resolved.** Engine stays env-free. v2 clarification (Codex 2026-06-28): the `verify` role returns a **registry** so a single process can verify a mixed stream of HMAC + Ed25519 badges in flight during the migration window. The `sign` role still returns one backend — signing has one configured choice per process.

```python
# src/tripwire/signing/__init__.py
def resolve_signing_backend() -> SigningBackend:
    """Pick the ONE backend this process will sign with. Read env at startup.

    Priority:
      1. TRIPWIRE_PRIVATE_KEY_PATH set → Ed25519Backend(private_key_pem=...).
      2. TRIPWIRE_SIGNING_KEY set      → HmacBackend(key=...).
      3. TRIPWIRE_ALLOW_DEV_KEY=1      → HmacBackend(dev placeholder, named
                                          "DEV-KEY-DO-NOT-USE-IN-PROD").
      4. else                           → raise SigningConfigError with a
                                          one-paragraph fix-this message.
    """

def resolve_verify_registry() -> VerifyRegistry:
    """Return a registry that knows how to verify EVERY alg the process can
    encounter — both HMAC and Ed25519 if the relevant env is set. The registry
    dispatches per badge by inspecting `badge["alg"]`.

    A process verifying only Ed25519 badges sets TRIPWIRE_PUBLIC_KEY_PATH;
    one still verifying legacy HMAC badges also sets TRIPWIRE_SIGNING_KEY; the
    registry uses whichever the badge needs. If a badge asks for an alg whose
    key the registry doesn't have, verify returns
    (False, "no verifier registered for alg=<alg>; configure
    TRIPWIRE_PUBLIC_KEY_PATH or TRIPWIRE_SIGNING_KEY").
    """
```

`VerifyRegistry` is a thin map `alg → SigningBackend` populated from whichever env vars are set. `attestation.verify_badge(badge, registry)` looks up `registry[badge["alg"]]` and delegates. This is the dispatch shape RFC v1 implied but didn't quite spell out; v2 makes it explicit.

The `TripwireEngine` constructor changes:

```python
class TripwireEngine:
    def __init__(self,
                 signing_backend: SigningBackend | None = None,
                 *,
                 signing_key: str | bytes | None = None,  # deprecated, kept for back-compat
                 block_at: Severity = Severity.HIGH):
        if signing_backend is not None:
            self._backend = signing_backend
        elif signing_key is not None:
            self._backend = HmacBackend(signing_key)            # old call site keeps working
        else:
            raise TypeError("TripwireEngine requires a signing_backend or signing_key")
```

**No env reads in the engine.** The CLI, the HTTP shell, the ADK app, and the test/demo fixtures each call `resolve_backend()` once at startup and pass the result in.

### What about the dev placeholder?

> **Another contradiction in v1** — the RFC both preserved and proposed dropping the placeholder. Resolved here in favour of dropping the implicit fallback.

After this PR:
- The engine refuses to construct without an explicit backend.
- `resolve_backend()` refuses to return a dev backend unless `TRIPWIRE_ALLOW_DEV_KEY=1` is set.
- The Makefile demo targets explicitly set `TRIPWIRE_ALLOW_DEV_KEY=1` so `make demo*` continues to Just Work.
- Tests use `monkeypatch.setenv("TRIPWIRE_ALLOW_DEV_KEY", "1")` per test that needs it.
- A production deploy that forgets to set a real key fails fast on first request, not silently with a known-public key.

This is a small behaviour change for any external user (none today) but a big safety win — no production deploy can ever sign with the well-known string `"dev-only-change-me"`.

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

Exit codes from `tripwire verify` are unchanged (0 valid, 2 tampered, 3 invalid/malformed). A missing public key when verifying an Ed25519 badge produces exit 3 with a clear message ("the badge says Ed25519; pass --pub or set TRIPWIRE_PUBLIC_KEY_PATH").

## Backward compatibility

| Scenario | Behaviour |
|---|---|
| Existing operator using HMAC, only `TRIPWIRE_SIGNING_KEY` set | `resolve_backend()` returns `HmacBackend`; engine signs HMAC, `verify` accepts HMAC. Identical to today. |
| New operator wants Ed25519 | Generates a keypair, sets `TRIPWIRE_PRIVATE_KEY_PATH`. Resolver returns Ed25519Backend; new badges have `alg: "Ed25519"`. |
| Mixed deployment (HMAC badges already in flight, new Ed25519 minted forward) | Verifier dispatches per-badge on `alg`. Both work during the migration window. |
| Verifier-only environment | Only needs the public key; private key never present. The `[signing]` extra (which brings `cryptography`) is the only install requirement beyond the core. |
| Existing call `TripwireEngine(signing_key=b"...")` | Still works, constructs an `HmacBackend` internally. Deprecation warning ships in v0.3. |

## Test plan

1. **Round-trip** — `key gen` → load private → `issue_badge` → load public → `verify_badge` → `(True, "valid")`.
2. **Tamper any field** — flip a byte in `fingerprint`, `issued_at`, `tool`, or `status` → `(False, "signature mismatch …")`.
3. **Wrong key** — generate keypair A, sign with A, attempt verify with public key B → `(False, "signature mismatch …")`.
4. **Wrong alg in badge** — flip `alg` from `"Ed25519"` to `"HMAC-SHA256"` while leaving the Ed25519 signature → caught with a clear message.
5. **Mixed corpus** — `tests/integration/test_attestation_mixed.py` issues N HMAC badges + N Ed25519 badges + N badges with `alg: "garbage"`, runs them all through `verify_badge`, asserts the right outcome class for each.
6. **CLI** — new `tests/unit/test_cli_key.py` covers `tripwire key gen` (file written with mode 0600), `tripwire key pub` (reads private, prints matching public), `tripwire verify --pub` happy + wrong-key + missing-pub paths.
7. **HTTP** — `tests/integration/test_http_endpoints.py` extended with one Ed25519-badge case on `/verify` to prove the dispatch works through the FastAPI layer.
8. **No-dev-key safety** — engine construction without an explicit backend AND without `TRIPWIRE_ALLOW_DEV_KEY=1` raises `SigningConfigError`. Demo targets that DO set the env work as before.
9. **Lazy import** — `from tripwire.attestation import verify_badge` works in an environment with **only** stdlib + `tripwire` installed (i.e. `[signing]` not pulled in). HMAC backend works; attempting to verify an Ed25519 badge in such an env returns `(False, "Ed25519 backend not available; pip install tripwire[signing]")` rather than ImportError.
10. **Harness guardrails update** — `scripts/harness_guardrails.py` updated with `"signing"` in the exclude list AND with a new check that `attestation.py` never eagerly imports `signing.ed25519_backend`. Self-test in the suite.

Acceptance criterion for the implementation PR: every existing test in the suite keeps passing AND the 10 new test groups above all pass AND the SSOT updates from §Rule update land in the same commit set.

## Decisions (Codex sign-off, 2026-06-28)

| # | Decision | Rationale |
|---|---|---|
| 1 | **PEM keys** (not raw) | Operator ergonomics; `openssl pkey -text` reads it. |
| 2 | `tripwire key gen` / `tripwire key pub` (grouped) | Room for future `key rotate`, `key fingerprint`. |
| 3 | Separate `[signing]` extra (not folded into `[agent]`) | HTTP-only / security-pipeline users shouldn't have to install ADK just to verify a signature. |
| 4 | **Widen Hard Rule #2** with atomic SSOT updates (not a sibling wheel) | A separate `tripwire-signing` wheel is packaging ceremony before the project has enough users to justify it. The atomic-update list in §Rule update keeps the rule and the code honest at every step. |
| 5 | ~~Default backend selection~~ → resolved | See §Configuration. `resolve_signing_backend()` priority is HMAC- / Ed25519-aware; `resolve_verify_registry()` returns a per-alg dispatch table. |
| 6 | ~~Dev placeholder~~ → resolved | See §"What about the dev placeholder?" — refused by default; `TRIPWIRE_ALLOW_DEV_KEY=1` opts in; production fails fast on a forgotten key. |

## Day-N implementation plan (post-RFC merge)

| Slot | Step | Exit signal |
|---|---|---|
| 1h | Atomic SSOT update — AGENTS.md (Rule #2 + Stack + Conventions), ADR-0001 §Consequences, ADR-0003 forward-ref, `harness_guardrails.py` exclude list + the new no-eager-import check | guardrails still pass; `grep -n 'signing' AGENTS.md docs/adr/*` shows the new exception consistently |
| 1.5h | New `src/tripwire/signing/` subpackage; `SigningBackend` Protocol + `HmacBackend` (the HMAC code moved out of `attestation.py`) | every existing test still passes against the moved-but-unchanged HMAC path |
| 2h | `signing/ed25519_backend.py`; `resolve_backend()`; engine refactor (constructor takes a backend, deprecation-paths the `signing_key` kwarg) | unit tests in groups 1–4 and 8–9 pass against the backend in isolation |
| 1h | `attestation.py` becomes the dispatcher; lazy import of Ed25519 backend; mixed-corpus test (5) passes | |
| 1.5h | `tripwire key gen` / `tripwire key pub` CLI; `tripwire verify --pub`; one Ed25519 case in HTTP test (7); CLI tests (6) pass | |
| 0.5h | README implementation-status row flip; STATUS.md update | `make eval` + `make demo*` still green from a fresh clone |
| 0.5h | Buffer | (use it or bank it) |

≈ 8h total — fits the deliberate-pace single-RFC, single-PR rhythm.
