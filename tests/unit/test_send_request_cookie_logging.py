"""Unit tests for P3 — send_request guest-cookie observability.

send_request logs whether a likely session cookie was pulled from the jar for the target
host, and WARNs (steering toward browser_fetch) when none is present. The decision hinges on
``_session_cookie_present``; these tests pin that detection (the WARN fires iff it is False).
Generic placeholder cookie names only.
"""

from __future__ import annotations

from dast.tools.http_tools import _session_cookie_present


def test_detects_plain_session_cookie():
    assert _session_cookie_present(["session"]) is True


def test_detects_underscore_session_cookie():
    assert _session_cookie_present(["csrf", "_session_id"]) is True


def test_detects_sid_cookie():
    assert _session_cookie_present(["JSESSIONID"]) is True
    assert _session_cookie_present(["sid"]) is True


def test_detection_is_case_insensitive():
    assert _session_cookie_present(["SESSION"]) is True
    assert _session_cookie_present(["PHPSESSID"]) is True


def test_no_session_cookie_present():
    # A jar with only non-session cookies -> guest request -> WARN path.
    assert _session_cookie_present(["theme", "lang", "csrftoken"]) is False


def test_empty_jar_is_no_session():
    assert _session_cookie_present([]) is False


def test_ignores_none_names():
    assert _session_cookie_present([None, ""]) is False
