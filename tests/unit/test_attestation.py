"""Tests for signed trust attestations — the wedge must break on tamper."""

from tripwire import issue_badge, verify_badge

KEY = "test-key"


def test_issue_and_verify_roundtrip():
    badge = issue_badge("get_weather", "abc123", KEY, issued_at="2026-01-01T00:00:00+00:00")
    ok, reason = verify_badge(badge, KEY)
    assert ok is True and reason == "valid"


def test_tampered_fingerprint_fails_verification():
    badge = issue_badge("get_weather", "abc123", KEY, issued_at="2026-01-01T00:00:00+00:00")
    badge["fingerprint"] = "deadbeef"  # attacker swaps in a different schema hash
    ok, _ = verify_badge(badge, KEY)
    assert ok is False


def test_tampered_signature_fails_verification():
    badge = issue_badge("get_weather", "abc123", KEY, issued_at="2026-01-01T00:00:00+00:00")
    badge["sig"] = "0" * 64
    assert verify_badge(badge, KEY)[0] is False


def test_wrong_key_fails_verification():
    badge = issue_badge("get_weather", "abc123", KEY, issued_at="2026-01-01T00:00:00+00:00")
    assert verify_badge(badge, "other-key")[0] is False


def test_missing_signature_fails():
    assert verify_badge({"tool": "x"}, KEY)[0] is False
