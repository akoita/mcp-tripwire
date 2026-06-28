"""Portable, verifiable trust attestations — the project's wedge.

Competitors emit a *report you must trust*. Tripwire emits a *signed attestation that
travels with the tool and breaks on tamper*. v1 inlined HMAC-SHA256 here; as of
RFC-0002 (#31) the algorithm lives in pluggable backends under
``src/tripwire/signing/``. This module keeps its public surface — ``sign /
issue_badge / verify_badge`` — so every existing caller works unchanged. Under
the hood the work is delegated to the appropriate backend.

The HMAC backend is stdlib-only and safe to eager-import. The Ed25519 backend
(landing in slot 3 of #31) pulls ``cryptography`` and must be lazy-imported —
enforced by ``scripts/harness_guardrails.py::check_pluggable_backends_lazy_imported``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .signing import HmacBackend
from .signing.hmac_backend import ALG

__all__ = ["ALG", "sign", "issue_badge", "verify_badge"]


def _hmac_backend(key: str | bytes) -> HmacBackend:
    return HmacBackend(key)


def sign(payload: dict, key: str | bytes) -> str:
    """Hex HMAC-SHA256 of the canonical payload. Kept for back-compat."""
    return _hmac_backend(key).sign(payload)


def issue_badge(
    tool_name: str,
    fingerprint: str,
    key: str | bytes,
    *,
    status: str = "trusted",
    issued_at: str | None = None,
) -> dict:
    """Mint a signed trust badge binding a tool name to its approved fingerprint.

    ``issued_at`` is injectable for deterministic tests; defaults to UTC now.
    """
    backend = _hmac_backend(key)
    payload = {
        "tool": tool_name,
        "fingerprint": fingerprint,
        "status": status,
        "issued_at": issued_at or datetime.now(UTC).isoformat(),
        "alg": backend.alg,
    }
    return {**payload, "sig": backend.sign(payload)}


def verify_badge(badge: dict, key: str | bytes) -> tuple[bool, str]:
    """Verify a badge. Returns (is_valid, reason). Any tamper -> (False, why)."""
    return _hmac_backend(key).verify(badge)
