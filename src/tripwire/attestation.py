"""Portable, verifiable trust attestations — the project's wedge.

Competitors emit a *report you must trust*. Tripwire emits a *signed attestation that
travels with the tool and breaks on tamper*. v1 uses HMAC-SHA256 (deterministic, zero
deps); P1 upgrades to Ed25519/sigstore-style asymmetric signing — see
ADR-0003. The wire format is identical, so the upgrade is drop-in.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime

ALG = "HMAC-SHA256"


def _canonical(payload: dict) -> bytes:
    """Deterministic byte encoding of the badge payload (signature excluded)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _key_bytes(key: str | bytes) -> bytes:
    return key.encode() if isinstance(key, str) else key


def sign(payload: dict, key: str | bytes) -> str:
    """Return the hex HMAC-SHA256 of the canonical payload."""
    return hmac.new(_key_bytes(key), _canonical(payload), hashlib.sha256).hexdigest()


def issue_badge(
    tool_name: str,
    fingerprint: str,
    key: str | bytes,
    *,
    status: str = "trusted",
    issued_at: str | None = None,
) -> dict:
    """Mint a signed trust badge binding a tool name to its approved fingerprint.

    `issued_at` is injectable for deterministic tests; defaults to UTC now.
    """
    payload = {
        "tool": tool_name,
        "fingerprint": fingerprint,
        "status": status,
        "issued_at": issued_at or datetime.now(UTC).isoformat(),
        "alg": ALG,
    }
    return {**payload, "sig": sign(payload, key)}


def verify_badge(badge: dict, key: str | bytes) -> tuple[bool, str]:
    """Verify a badge. Returns (is_valid, reason). Any tamper -> (False, why)."""
    if "sig" not in badge:
        return False, "missing signature"
    payload = {k: v for k, v in badge.items() if k != "sig"}
    expected = sign(payload, key)
    if not hmac.compare_digest(expected, str(badge["sig"])):  # constant-time
        return False, "signature mismatch — badge or payload was tampered with"
    return True, "valid"
