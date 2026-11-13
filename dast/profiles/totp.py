"""TOTP (RFC 6238) code generation for login profiles — TEST ACCOUNTS ONLY.

A profile may store a TOTP seed so the login cascade can generate the 2FA code
itself instead of waiting for an operator to type it. This defeats the second
factor, so a seed may only ever be USED when the profile is explicitly flagged a
test account (``may_use_totp``). The generator here is pure and stateless; the
guard enforces the test-account policy and warns (but does not block) when the
username does not match the out-of-band test-account allowlist.
"""

from __future__ import annotations

import os

import pyotp

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Env var (CSV) of username suffixes that look like throwaway test accounts. No
# default — nothing internal is hardcoded in the repo. When unset, the suffix
# check is skipped and only the test_account flag gates the seed.
_SUFFIX_ENV = "DAST_TEST_ACCOUNT_SUFFIXES"


def normalize_secret(raw: str) -> str:
    """Base32 seeds tolerate human input: strip spaces, uppercase."""
    return (raw or "").replace(" ", "").strip().upper()


def is_valid_secret(raw: str) -> bool:
    """True if ``raw`` is a usable base32 TOTP seed (an empty seed is not valid)."""
    norm = normalize_secret(raw)
    if not norm:
        return False
    try:
        pyotp.TOTP(norm).now()
        return True
    except Exception:
        return False


def current_code(secret: str) -> str:
    """The current 6-digit TOTP code for ``secret``. Raises if the seed is invalid."""
    return pyotp.TOTP(normalize_secret(secret)).now()


def _test_account_suffixes() -> list[str]:
    raw = os.environ.get(_SUFFIX_ENV, "")
    return [s.strip().lower() for s in raw.split(",") if s.strip()]


def may_use_totp(test_account: bool, username: str) -> bool:
    """Whether a stored TOTP seed may be USED for this profile/credential.

    Hard gate: only test accounts. Soft check (warn-only): when the allowlist env
    is set and the username matches no suffix, log a warning but still allow — the
    operator owns the decision, the warning exists so an accidental real account
    is noisy rather than silent.
    """
    if not test_account:
        return False
    suffixes = _test_account_suffixes()
    user = (username or "").lower()
    if suffixes and not any(user.endswith(s) for s in suffixes):
        logger.warning(
            "TOTP armed for a profile whose username does not match the "
            "test-account allowlist — proceeding, but confirm this is a "
            "disposable test account",
            username=username,
        )
    return True
