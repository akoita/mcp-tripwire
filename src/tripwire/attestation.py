"""Portable, verifiable trust attestations — the project's wedge.

Per RFC-0002 (#31), this module is the alg-dispatching surface. ``issue_badge``
and ``verify_badge`` accept any of three input shapes for backwards compatibility
and forward-flexibility:

- A ``SigningBackend`` (HmacBackend, Ed25519Backend, …) — used directly.
- A ``VerifyRegistry`` (for verify only) — dispatches per ``badge["alg"]``.
- A raw ``str | bytes`` key — wrapped in ``HmacBackend`` for legacy callers.

The deterministic core stays stdlib-only. The HMAC backend is bundled
(stdlib-only); Ed25519 lives behind the ``[signing]`` extra and is **lazy**.
Importing ``tripwire.attestation`` does NOT import ``cryptography`` — the
guardrail ``check_pluggable_backends_lazy_imported`` enforces this.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .signing import HmacBackend, SigningBackend, VerifyRegistry
from .signing.hmac_backend import ALG  # legacy export for `from tripwire.attestation import ALG`

__all__ = ["ALG", "sign", "issue_badge", "verify_badge"]


def _as_signing_backend(thing) -> SigningBackend:
    """Normalize a sign-side input to a SigningBackend instance."""
    if hasattr(thing, "alg") and hasattr(thing, "sign"):
        return thing  # already a backend
    return HmacBackend(thing)


def sign(payload: dict, key_or_backend) -> str:
    """Sign a canonical payload. Returns the backend-specific encoding (hex for
    HMAC, urlsafe-b64-no-pad for Ed25519). Kept for back-compat with the v1
    public surface; new code should construct a backend and call ``.sign``."""
    return _as_signing_backend(key_or_backend).sign(payload)


def issue_badge(
    tool_name: str,
    fingerprint: str,
    key_or_backend,
    *,
    status: str = "trusted",
    issued_at: str | None = None,
) -> dict:
    """Mint a signed trust badge.

    Accepts a configured ``SigningBackend`` (preferred) or a raw HMAC key
    (back-compat). ``issued_at`` is injectable for deterministic tests.
    """
    backend = _as_signing_backend(key_or_backend)
    payload = {
        "tool": tool_name,
        "fingerprint": fingerprint,
        "status": status,
        "issued_at": issued_at or datetime.now(UTC).isoformat(),
        "alg": backend.alg,
    }
    return {**payload, "sig": backend.sign(payload)}


def verify_badge(badge: dict, key_or_backend_or_registry) -> tuple[bool, str]:
    """Verify a badge. Alg-dispatching per RFC-0002.

    Three input shapes:

    - ``VerifyRegistry`` — dispatches per ``badge["alg"]``. Use this when a
      process must accept a mixed stream of HMAC + Ed25519 badges (e.g. during
      a rotation window).
    - ``SigningBackend`` — single-backend verify. Returns a clear alg-mismatch
      message if the badge was signed by a different alg.
    - ``str | bytes`` — legacy raw HMAC key. Wrapped in ``HmacBackend``;
      Ed25519 badges get refused with a hint to pass a backend or registry.
    """
    alg = badge.get("alg")

    if isinstance(key_or_backend_or_registry, VerifyRegistry):
        return key_or_backend_or_registry.verify(badge)

    if hasattr(key_or_backend_or_registry, "alg") and hasattr(key_or_backend_or_registry, "verify"):
        backend = key_or_backend_or_registry
        if alg and alg != backend.alg:
            return False, (f"alg mismatch: badge says {alg!r}, verifier is {backend.alg!r}")
        return backend.verify(badge)

    # Legacy: raw key. Assume HMAC.
    if alg and alg != ALG:
        if alg == "Ed25519":
            return False, (
                "Ed25519 badge requires an Ed25519Backend or VerifyRegistry; "
                "pass one or set TRIPWIRE_PUBLIC_KEY_PATH and use resolve_verify_registry()"
            )
        return False, f"unsupported alg: {alg!r}"
    return HmacBackend(key_or_backend_or_registry).verify(badge)
