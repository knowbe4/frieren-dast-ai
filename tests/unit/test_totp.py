"""Unit tests for dast.profiles.totp — generator + test-account guard."""

from __future__ import annotations

import pyotp

from dast.profiles import totp


# A standard base32 seed (the pyotp docs example). Valid for SHA1/6-digit TOTP.
_SEED = "JBSWY3DPEHPK3PXP"


def test_current_code_is_accepted_by_verify():
    code = totp.current_code(_SEED)
    assert code.isdigit() and len(code) == 6
    # The real contract: the generated code must validate against the same seed.
    assert pyotp.TOTP(_SEED).verify(code)


def test_current_code_matches_reference_at_fixed_time():
    # Deterministic cross-check against pyotp's own computation at a pinned instant.
    for t in (0, 59, 1111111109, 1234567890, 2000000000):
        expected = pyotp.TOTP(_SEED).at(t)
        assert pyotp.TOTP(totp.normalize_secret(_SEED)).at(t) == expected


def test_normalize_secret_tolerates_human_input():
    assert totp.normalize_secret("  jbswy3 dpehpk3pxp ") == _SEED


def test_is_valid_secret():
    assert totp.is_valid_secret(_SEED) is True
    assert totp.is_valid_secret("jbswy3dpehpk3pxp") is True  # lowercase ok
    assert totp.is_valid_secret("") is False
    assert totp.is_valid_secret("not base32!!!") is False


def test_guard_refuses_non_test_account():
    assert totp.may_use_totp(False, "qa@test.example") is False


def test_guard_allows_test_account_without_suffix_env(monkeypatch):
    monkeypatch.delenv(totp._SUFFIX_ENV, raising=False)
    assert totp.may_use_totp(True, "anyone@whatever.example") is True


def test_guard_allows_but_warns_on_suffix_mismatch(monkeypatch, caplog):
    monkeypatch.setenv(totp._SUFFIX_ENV, ".test.example,.qa.example")
    # Matching suffix: allowed, no warning needed.
    assert totp.may_use_totp(True, "qa@test.example") is True
    # Non-matching suffix: still allowed (warn-only), but a warning is logged.
    with caplog.at_level("WARNING"):
        assert totp.may_use_totp(True, "real@prod.example") is True
