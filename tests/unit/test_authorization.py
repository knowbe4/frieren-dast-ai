"""
Unit tests for the engagement-authorization gate (dast/authorization.py) and its
effect on the copilot system prompt.

Covers:
  - the flag defaults to False (no assumed consent),
  - set/is round-trips,
  - the copilot system prompt gains the authorization directive only when the flag
    is set, and reverts when it is cleared.
"""

from __future__ import annotations

import pytest

from dast import authorization
from dast.ai.copilot import session


@pytest.fixture(autouse=True)
def _reset_authorization():
    """Keep the process-global flag isolated per test (default off)."""
    original = authorization.is_full_authorization()
    authorization.set_full_authorization(False)
    yield
    authorization.set_full_authorization(original)


def test_default_is_not_authorized():
    assert authorization.is_full_authorization() is False


def test_set_and_read_round_trip():
    authorization.set_full_authorization(True)
    assert authorization.is_full_authorization() is True
    authorization.set_full_authorization(False)
    assert authorization.is_full_authorization() is False


def test_system_prompt_omits_directive_by_default():
    prompt = session._system_prompt()
    assert authorization.AUTHORIZED_ENGAGEMENT_DIRECTIVE not in prompt
    assert "AUTHORIZATION STATUS" not in prompt


def test_system_prompt_appends_directive_when_authorized():
    authorization.set_full_authorization(True)
    prompt = session._system_prompt()
    assert prompt.endswith(authorization.AUTHORIZED_ENGAGEMENT_DIRECTIVE)
    assert "need_authorization" in prompt


def test_toggling_off_restores_base_prompt():
    base = session._system_prompt()
    authorization.set_full_authorization(True)
    assert session._system_prompt() != base
    authorization.set_full_authorization(False)
    assert session._system_prompt() == base
