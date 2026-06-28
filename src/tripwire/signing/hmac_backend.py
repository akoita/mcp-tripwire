"""HMAC-SHA256 signing backend — the default, stdlib-only.

Lifted out of ``attestation.py`` in slot 2 of #31 (RFC-0002). Wire format
is unchanged: ``sig`` is the lowercase hex digest of HMAC-SHA256 over the
canonical payload (sorted keys, ASCII-safe, no spaces). Existing badges
verify identically.
"""

from __future__ import annotations

import hashlib
import hmac
import json

ALG = "HMAC-SHA256"


def _canonical(payload: dict) -> bytes:
    """Deterministic byte encoding of the payload, sig excluded."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _key_bytes(key: str | bytes) -> bytes:
    return key.encode() if isinstance(key, str) else key


class HmacBackend:
    """HMAC-SHA256 backend. Constructs from a shared secret (str or bytes)."""

    alg: str = ALG

    def __init__(self, key: str | bytes) -> None:
        self._key = _key_bytes(key)

    def sign(self, payload: dict) -> str:
        return hmac.new(self._key, _canonical(payload), hashlib.sha256).hexdigest()

    def verify(self, badge: dict) -> tuple[bool, str]:
        if "sig" not in badge:
            return False, "missing signature"
        payload = {k: v for k, v in badge.items() if k != "sig"}
        expected = self.sign(payload)
        if not hmac.compare_digest(expected, str(badge["sig"])):
            return False, "signature mismatch — badge or payload was tampered with"
        return True, "valid"
