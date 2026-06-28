"""Pluggable signing backends for trust attestations.

Per [RFC-0002](../../../docs/rfc/RFC-0002-ed25519-signing.md), the badge wire
format is alg-tagged, so multiple backends can coexist. The default
``HmacBackend`` is stdlib-only and bundled with the base install; the
Ed25519Backend (slot 3 of #31) ships behind the ``[signing]`` extra.

Hard Rule #2 widens to allow third-party imports under this subpackage —
each backend is gated by an extra and import-guarded so a base install
without that extra still imports ``tripwire`` cleanly. See
``scripts/harness_guardrails.py::check_pluggable_backends_lazy_imported``.
"""

from __future__ import annotations

from typing import Protocol

from .hmac_backend import HmacBackend

__all__ = ["SigningBackend", "HmacBackend"]


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
