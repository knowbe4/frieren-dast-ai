"""Tests for the focus-host membership check used by the copilot scope gate:
a run pinned to a focus host must not reach a fabricated sibling host even when the
broad scope preset would admit it."""

from __future__ import annotations

import pytest

from dast.ai.copilot.session import _host_in_focus

FOCUS = ["training.knowbe4.com"]


@pytest.mark.parametrize("host", [
    "training.knowbe4.com",            # exact
    "api.training.knowbe4.com",        # subdomain
    "a.b.training.knowbe4.com",        # deeper subdomain
])
def test_in_focus(host: str) -> None:
    assert _host_in_focus(host, FOCUS) is True


@pytest.mark.parametrize("host", [
    "kmsat-tenant-a.knowbe4.com",      # fabricated sibling — the bug
    "knowbe4.com",                     # parent, not focus
    "training.knowbe4.com.evil.com",   # suffix trick
    "eviltraining.knowbe4.com",        # not a dot-subdomain
    "",
])
def test_out_of_focus(host: str) -> None:
    assert _host_in_focus(host, FOCUS) is False


def test_empty_focus_matches_nothing() -> None:
    assert _host_in_focus("training.knowbe4.com", []) is False
