"""Backend-in-isolation tests for ``tripwire.signing`` (RFC-0002 / #31).

Covers slot 3 exit signal: groups 1–4 + 8–9 of the RFC test plan pass against
the backend in isolation. Groups 5 (mixed corpus), 6 (CLI), 7 (HTTP) and 10
(harness self-test) are wired in later slots.
"""

from __future__ import annotations

import pytest

from tripwire.signing import (
    HmacBackend,
    SigningConfigError,
    VerifyRegistry,
    resolve_signing_backend,
    resolve_verify_registry,
)
from tripwire.signing.ed25519_backend import Ed25519Backend


def _ed25519_available() -> bool:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


requires_ed25519 = pytest.mark.skipif(
    not _ed25519_available(),
    reason="`cryptography` not installed — run `uv sync --extra signing` (RFC-0002)",
)

# ---------------------------------------------------------------- HmacBackend
# Quick sanity that the moved-out HmacBackend (slot 2) still round-trips.

KEY = b"unit-test-key"


def test_hmac_round_trip():
    backend = HmacBackend(KEY)
    payload = {"tool": "t", "fingerprint": "f", "status": "trusted", "alg": backend.alg}
    badge = {**payload, "sig": backend.sign(payload)}
    assert backend.verify(badge) == (True, "valid")


def test_hmac_tamper():
    backend = HmacBackend(KEY)
    payload = {"tool": "t", "fingerprint": "f", "status": "trusted", "alg": backend.alg}
    badge = {**payload, "sig": backend.sign(payload)}
    tampered = {**badge, "fingerprint": "X"}
    ok, reason = backend.verify(tampered)
    assert not ok and "tamper" in reason


# ------------------------------------------------------------- Ed25519Backend
# Groups 1-4 of the RFC test plan, against the backend in isolation.


@pytest.fixture
def ed25519_keypair():
    """A freshly generated keypair — full backend (sign + verify)."""
    return Ed25519Backend.generate()


def _payload():
    return {
        "tool": "t",
        "fingerprint": "f",
        "status": "trusted",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "alg": Ed25519Backend.alg,
    }


@requires_ed25519
def test_ed25519_group1_round_trip(ed25519_keypair):
    """Group 1 — gen → sign → verify → (True, 'valid')."""
    backend = ed25519_keypair
    payload = _payload()
    sig = backend.sign(payload)
    badge = {**payload, "sig": sig}
    assert backend.verify(badge) == (True, "valid")


@pytest.mark.parametrize("field", ["fingerprint", "issued_at", "tool", "status"])
@requires_ed25519
def test_ed25519_group2_tamper(ed25519_keypair, field):
    """Group 2 — flip any field → (False, 'signature mismatch ...')."""
    backend = ed25519_keypair
    payload = _payload()
    badge = {**payload, "sig": backend.sign(payload)}
    tampered = {**badge, field: badge[field] + "_TAMPER"}
    ok, reason = backend.verify(tampered)
    assert not ok and "tamper" in reason


@requires_ed25519
def test_ed25519_group3_wrong_key():
    """Group 3 — sign with A, verify with B's public key → False."""
    a = Ed25519Backend.generate()
    b = Ed25519Backend.generate()
    payload = _payload()
    badge = {**payload, "sig": a.sign(payload)}
    # Verifier with B's public key only.
    verify_only = Ed25519Backend(public_key_pem=b.public_key_pem())
    ok, reason = verify_only.verify(badge)
    assert not ok and "tamper" in reason


@requires_ed25519
def test_ed25519_group4_alg_swap(ed25519_keypair):
    """Group 4 — keep the Ed25519 signature but swap alg → caught.

    Slot 3 scope is the backend in isolation: the backend doesn't itself
    police alg (the canonical payload encoding incorporates alg, so a swap
    breaks the signature). A subsequent slot wires the dispatcher to also
    refuse explicitly via the badge['alg'] check; that's group 5.
    """
    backend = ed25519_keypair
    payload = _payload()
    badge = {**payload, "sig": backend.sign(payload)}
    swapped = {**badge, "alg": "HMAC-SHA256"}
    ok, _reason = backend.verify(swapped)
    assert not ok


@requires_ed25519
def test_ed25519_verify_only_cannot_sign():
    """Sign-side guard: verify-only backend rejects ``.sign(...)``."""
    pair = Ed25519Backend.generate()
    verify_only = Ed25519Backend(public_key_pem=pair.public_key_pem())
    with pytest.raises(ValueError, match="verify-only"):
        verify_only.sign(_payload())


@requires_ed25519
def test_ed25519_requires_one_of_the_keys():
    """Constructor refuses the empty case."""
    with pytest.raises(ValueError, match="private_key_pem and/or public_key_pem"):
        Ed25519Backend()


@requires_ed25519
def test_ed25519_keypair_mismatch_raises():
    """If both PEMs are passed and they don't agree, instantiation fails."""
    a = Ed25519Backend.generate()
    b = Ed25519Backend.generate()
    with pytest.raises(ValueError, match="does not match"):
        Ed25519Backend(
            private_key_pem=a.private_key_pem(),
            public_key_pem=b.public_key_pem(),
        )


# ----------------------------------------------------- resolve_signing_backend
# Group 8 — no-dev-key safety: missing config raises a clear error.


@pytest.fixture
def clean_signing_env(monkeypatch):
    """Strip every TRIPWIRE_* signing-related env var for this test."""
    for var in (
        "TRIPWIRE_PRIVATE_KEY_PATH",
        "TRIPWIRE_PUBLIC_KEY_PATH",
        "TRIPWIRE_SIGNING_KEY",
        "TRIPWIRE_ALLOW_DEV_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


def test_group8_no_config_raises_clear_error(clean_signing_env):
    with pytest.raises(SigningConfigError) as exc:
        resolve_signing_backend()
    assert "TRIPWIRE_PRIVATE_KEY_PATH" in str(exc.value)
    assert "TRIPWIRE_SIGNING_KEY" in str(exc.value)
    assert "TRIPWIRE_ALLOW_DEV_KEY" in str(exc.value)


def test_group8_dev_key_opt_in(clean_signing_env, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_ALLOW_DEV_KEY", "1")
    backend = resolve_signing_backend()
    assert isinstance(backend, HmacBackend)
    # Sanity: signs with the dev placeholder, not garbage.
    payload = {"tool": "t", "fingerprint": "f", "status": "trusted", "alg": backend.alg}
    badge = {**payload, "sig": backend.sign(payload)}
    assert backend.verify(badge) == (True, "valid")


def test_group8_hmac_resolves_when_signing_key_set(clean_signing_env, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_SIGNING_KEY", "explicit-shared-secret")
    backend = resolve_signing_backend()
    assert isinstance(backend, HmacBackend)


@requires_ed25519
def test_group8_ed25519_resolves_when_private_path_set(clean_signing_env, monkeypatch, tmp_path):
    """Private-key path wins over signing-key env (priority order)."""
    pair = Ed25519Backend.generate()
    pem_path = tmp_path / "priv.pem"
    pem_path.write_bytes(pair.private_key_pem())
    monkeypatch.setenv("TRIPWIRE_PRIVATE_KEY_PATH", str(pem_path))
    monkeypatch.setenv("TRIPWIRE_SIGNING_KEY", "should-be-ignored")
    backend = resolve_signing_backend()
    assert isinstance(backend, Ed25519Backend)


# ----------------------------------------------------- VerifyRegistry / group 9
# Group 9 — the registry dispatches per badge['alg']; missing alg has a clear
# message instead of crashing. (The full lazy-import-without-cryptography path
# is exercised in slot 4 once attestation.py becomes the dispatcher.)


@requires_ed25519
def test_verify_registry_dispatches_per_alg(tmp_path):
    pair = Ed25519Backend.generate()
    hmac = HmacBackend(b"r-key")
    registry = VerifyRegistry()
    registry["HMAC-SHA256"] = hmac
    pub_path = tmp_path / "pub.pem"
    pub_path.write_bytes(pair.public_key_pem())
    registry["Ed25519"] = Ed25519Backend(public_key_pem=pair.public_key_pem())

    hmac_payload = {"tool": "h", "fingerprint": "f", "status": "t", "alg": "HMAC-SHA256"}
    hmac_badge = {**hmac_payload, "sig": hmac.sign(hmac_payload)}
    assert registry.verify(hmac_badge) == (True, "valid")

    ed_payload = {"tool": "e", "fingerprint": "f", "status": "t", "alg": "Ed25519"}
    ed_badge = {**ed_payload, "sig": pair.sign(ed_payload)}
    assert registry.verify(ed_badge) == (True, "valid")


def test_verify_registry_unknown_alg_returns_clear_message():
    registry = VerifyRegistry()
    ok, reason = registry.verify({"alg": "BLAKE3-MAC", "sig": "x"})
    assert not ok and "no verifier registered for alg=BLAKE3-MAC" in reason


def test_verify_registry_missing_alg_returns_clear_message():
    registry = VerifyRegistry()
    ok, reason = registry.verify({"sig": "x"})
    assert not ok and "no `alg` field" in reason


@requires_ed25519
def test_resolve_verify_registry_picks_up_both_keys(clean_signing_env, monkeypatch, tmp_path):
    pair = Ed25519Backend.generate()
    pub_path = tmp_path / "pub.pem"
    pub_path.write_bytes(pair.public_key_pem())
    monkeypatch.setenv("TRIPWIRE_PUBLIC_KEY_PATH", str(pub_path))
    monkeypatch.setenv("TRIPWIRE_SIGNING_KEY", "shared-secret")
    registry = resolve_verify_registry()
    assert "Ed25519" in registry
    assert "HMAC-SHA256" in registry
