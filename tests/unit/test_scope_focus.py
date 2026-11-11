"""Tests for the focus-host membership check used by the copilot scope gate:
a run pinned to a focus host must not reach a fabricated sibling host even when the
broad scope preset would admit it."""

from __future__ import annotations

import pytest

from dast.ai.copilot.session import _host_in_focus

FOCUS = ["app.example.com"]


@pytest.mark.parametrize("host", [
    "app.example.com",            # exact
    "api.app.example.com",        # subdomain
    "a.b.app.example.com",        # deeper subdomain
])
def test_in_focus(host: str) -> None:
    assert _host_in_focus(host, FOCUS) is True


@pytest.mark.parametrize("host", [
    "sibling.example.com",      # fabricated sibling — the bug
    "example.com",                     # parent, not focus
    "app.example.com.evil.com",   # suffix trick
    "evilapp.example.com",        # not a dot-subdomain
    "",
])
def test_out_of_focus(host: str) -> None:
    assert _host_in_focus(host, FOCUS) is False


def test_empty_focus_matches_nothing() -> None:
    assert _host_in_focus("app.example.com", []) is False
