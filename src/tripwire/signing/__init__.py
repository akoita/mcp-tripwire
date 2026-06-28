"""Pluggable signing backends for trust attestations.

Per [RFC-0002](../../../docs/rfc/RFC-0002-ed25519-signing.md), the badge wire
format is alg-tagged so multiple backends can coexist. The default
``HmacBackend`` is stdlib-only and bundled with the base install; the
``Ed25519Backend`` ships behind the ``[signing]`` extra and is **lazy-imported**
inside the resolver functions — a base install can ``import tripwire`` cleanly
even without ``cryptography``.

Hard Rule #2 widens to allow third-party imports under this subpackage —
each backend is gated by an extra. See
``scripts/harness_guardrails.py::check_pluggable_backends_lazy_imported``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from .hmac_backend import HmacBackend

__all__ = [
    "SigningBackend",
    "HmacBackend",
    "VerifyRegistry",
    "SigningConfigError",
    "resolve_signing_backend",
    "resolve_verify_registry",
]


class SigningBackend(Protocol):
    """The contract every signing backend implements.

    ``alg`` is the canonical string written into the badge's ``alg`` field,
    e.g. ``"HMAC-SHA256"`` or ``"Ed25519"``. ``sign`` returns the signature
    in whatever encoding the backend documents (hex for HMAC, base64 for
    Ed25519). ``verify`` takes a complete badge dict (``sig`` field present),
    re-derives the canonical payload, and returns ``(is_valid, reason)``.
    """

    alg: str

    def sign(self, payload: dict) -> str: ...
    def verify(self, badge: dict) -> tuple[bool, str]: ...


class SigningConfigError(RuntimeError):
    """Raised when no signing backend can be resolved from env. The message
    tells the operator exactly which env vars to set."""


class VerifyRegistry(dict):
    """``alg → SigningBackend`` map for verifying a mixed stream of badges.

    A process verifying only Ed25519 badges populates ``"Ed25519"``; one still
    accepting legacy HMAC badges also populates ``"HMAC-SHA256"``. ``verify``
    inspects ``badge["alg"]`` and dispatches; an unknown alg returns a clear
    configuration hint instead of a crash.
    """

    def verify(self, badge: dict) -> tuple[bool, str]:
        alg = badge.get("alg")
        if not alg:
            return False, "badge has no `alg` field"
        backend = self.get(alg)
        if backend is None:
            return False, (
                f"no verifier registered for alg={alg}; configure "
                "TRIPWIRE_PUBLIC_KEY_PATH (for Ed25519) or TRIPWIRE_SIGNING_KEY (for HMAC)"
            )
        return backend.verify(badge)


def resolve_signing_backend() -> SigningBackend:
    """Pick the ONE backend this process will sign with. Read env at startup.

    Priority (RFC-0002 §Configuration):

    1. ``TRIPWIRE_PRIVATE_KEY_PATH`` set → ``Ed25519Backend`` from that PEM file.
    2. ``TRIPWIRE_SIGNING_KEY`` set      → ``HmacBackend`` with that key.
    3. ``TRIPWIRE_ALLOW_DEV_KEY=1``      → ``HmacBackend`` with a labelled dev
       placeholder (``DEV-KEY-DO-NOT-USE-IN-PROD``). Convenience only; never
       used unless explicitly opted in.
    4. else                              → raise ``SigningConfigError`` with
       a one-paragraph fix.
    """
    if pk_path := os.environ.get("TRIPWIRE_PRIVATE_KEY_PATH"):
        from .ed25519_backend import Ed25519Backend  # lazy — needs `cryptography`

        return Ed25519Backend(private_key_pem=Path(pk_path).read_bytes())
    if key := os.environ.get("TRIPWIRE_SIGNING_KEY"):
        return HmacBackend(key)
    if os.environ.get("TRIPWIRE_ALLOW_DEV_KEY") == "1":
        return HmacBackend(b"DEV-KEY-DO-NOT-USE-IN-PROD")
    raise SigningConfigError(
        "No signing backend configured. Set ONE of:\n"
        "  - TRIPWIRE_PRIVATE_KEY_PATH=/path/to/ed25519_private.pem  (preferred)\n"
        "  - TRIPWIRE_SIGNING_KEY=<shared-secret>                    (HMAC fallback)\n"
        "  - TRIPWIRE_ALLOW_DEV_KEY=1                                (dev only)\n"
        "See docs/runbooks/ for the operator workflow."
    )


def resolve_verify_registry() -> VerifyRegistry:
    """Return a registry that knows how to verify EVERY alg the process can
    encounter. Populated from whichever env vars are set — a process can
    verify a mixed HMAC + Ed25519 stream during a rotation window."""
    registry = VerifyRegistry()
    if pub_path := os.environ.get("TRIPWIRE_PUBLIC_KEY_PATH"):
        from .ed25519_backend import Ed25519Backend  # lazy — needs `cryptography`

        registry["Ed25519"] = Ed25519Backend(public_key_pem=Path(pub_path).read_bytes())
    if key := os.environ.get("TRIPWIRE_SIGNING_KEY"):
        registry["HMAC-SHA256"] = HmacBackend(key)
    return registry
