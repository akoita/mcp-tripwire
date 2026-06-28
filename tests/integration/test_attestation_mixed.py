"""Mixed-alg corpus tests — RFC-0002 test plan group 5.

Verifies ``attestation.verify_badge`` correctly dispatches a stream of HMAC
badges, Ed25519 badges, and garbage-alg badges through both the single-backend
and the ``VerifyRegistry`` paths.
"""

from __future__ import annotations

import pytest

from tripwire import attestation
from tripwire.signing import HmacBackend, VerifyRegistry
from tripwire.signing.ed25519_backend import Ed25519Backend


def _ed25519_available() -> bool:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


requires_ed25519 = pytest.mark.skipif(
    not _ed25519_available(),
    reason="`cryptography` not installed — install [signing] extra",
)


KEY = b"mixed-corpus-key"


# -- HMAC alone (no [signing] needed) ---------------------------------------


def test_hmac_only_round_trip_via_legacy_key():
    """Legacy callers passing a raw key still work."""
    badge = attestation.issue_badge("t1", "fp1", KEY)
    assert attestation.verify_badge(badge, KEY) == (True, "valid")


def test_hmac_badge_with_legacy_key_tampered():
    badge = attestation.issue_badge("t1", "fp1", KEY)
    tampered = {**badge, "fingerprint": "X"}
    ok, reason = attestation.verify_badge(tampered, KEY)
    assert not ok and "tamper" in reason


def test_legacy_key_refuses_ed25519_badge_with_clear_message():
    """A raw HMAC key cannot verify an Ed25519 badge — we say so clearly."""
    fake_ed_badge = {
        "tool": "t",
        "fingerprint": "f",
        "status": "trusted",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "alg": "Ed25519",
        "sig": "anything",
    }
    ok, reason = attestation.verify_badge(fake_ed_badge, KEY)
    assert not ok
    assert "Ed25519Backend" in reason and "VerifyRegistry" in reason


def test_legacy_key_refuses_unknown_alg():
    fake_badge = {
        "tool": "t",
        "fingerprint": "f",
        "status": "trusted",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "alg": "BLAKE3-XOF",
        "sig": "anything",
    }
    ok, reason = attestation.verify_badge(fake_badge, KEY)
    assert not ok and "unsupported alg" in reason


# -- Mixed corpus through a VerifyRegistry ----------------------------------


@requires_ed25519
def test_group5_mixed_corpus_via_registry():
    """N HMAC + N Ed25519 + N garbage-alg badges → correct outcome class each."""
    hmac = HmacBackend(KEY)
    pair = Ed25519Backend.generate()
    registry = VerifyRegistry()
    registry["HMAC-SHA256"] = hmac
    registry["Ed25519"] = Ed25519Backend(public_key_pem=pair.public_key_pem())

    N = 5
    badges = []
    for i in range(N):
        badges.append((attestation.issue_badge(f"h{i}", "fp", hmac), True, "HMAC"))
    for i in range(N):
        badges.append((attestation.issue_badge(f"e{i}", "fp", pair), True, "Ed25519"))
    for i in range(N):
        badges.append(
            (
                {
                    "tool": f"g{i}",
                    "fingerprint": "fp",
                    "status": "trusted",
                    "issued_at": "2026-01-01T00:00:00+00:00",
                    "alg": "GARBAGE-1",
                    "sig": "x",
                },
                False,
                "GARBAGE",
            )
        )

    for badge, expected_ok, label in badges:
        ok, reason = attestation.verify_badge(badge, registry)
        assert ok is expected_ok, f"{label} {badge['tool']}: {reason!r}"


@requires_ed25519
def test_alg_mismatch_single_backend():
    """Single backend + wrong-alg badge → clear (False, 'alg mismatch ...')."""
    pair = Ed25519Backend.generate()
    hmac_badge = attestation.issue_badge("h", "fp", HmacBackend(KEY))
    ok, reason = attestation.verify_badge(hmac_badge, pair)
    assert not ok and "alg mismatch" in reason


@requires_ed25519
def test_ed25519_via_backend_directly():
    pair = Ed25519Backend.generate()
    badge = attestation.issue_badge("e", "fp", pair)
    verify_only = Ed25519Backend(public_key_pem=pair.public_key_pem())
    assert attestation.verify_badge(badge, verify_only) == (True, "valid")
