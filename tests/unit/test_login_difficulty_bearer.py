"""Login-difficulty harness - SPA/bearer tiers (T6-T8), LLM-free path.

These tiers exercise the token-auth flow where login does NOT set a gating cookie
but hands back a JWT the client then sends as ``Authorization: Bearer`` on API
calls. We drive the deterministic machinery directly (no browser, no model):

    CopilotSession._capture_bearer_tokens  - scrape a Bearer from proxy history
    CopilotSession._apply_session_auth     - inject the captured session on a call

A fake proxy store is seeded with request history (a non-copilot API call carrying
the token), mirroring what the real store holds after the operator/browser logs in.
The success signal for a token flow is an authenticated API call (Authorization set),
not a /login -> /dashboard redirect.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from dast.ai.copilot.session import CopilotSession
from dast.profiles.flow import has_captcha
from tests.fixtures.login_pages.server import _T0, _T5, issue_jwt


class _Entry:
    """A proxy-history entry supporting both ``.get()`` (used by the bearer
    capture) and attribute access (used by ``extract_auth_headers``)."""

    def __init__(self, **fields: Any) -> None:
        self._fields = fields

    def get(self, key: str, default: Any = None) -> Any:
        return self._fields.get(key, default)

    def __getattr__(self, name: str) -> Any:
        return self._fields.get(name)


class _Store:
    def __init__(self, entries: List[_Entry],
                 cookies: Optional[Dict[str, List[Dict[str, str]]]] = None) -> None:
        self._entries = entries
        self._cookies = cookies or {}

    def all_entries(self) -> List[_Entry]:
        return list(self._entries)

    def get_cookies_for_host(self, host: str) -> List[Dict[str, str]]:
        return self._cookies.get(host, [])


def _ctx(store: _Store) -> Any:
    return SimpleNamespace(store=store)


def _bearer_entry(host: str, token: str, source: str = "proxy",
                  path: str = "/api/auth/login") -> _Entry:
    return _Entry(host=host, path=path, id=f"entry-{host}", source=source,
                  request_headers={"Authorization": f"Bearer {token}"})


# --------------------------------------------------------------- capture (T6)


def test_captures_fresh_bearer_from_history_with_host_family_match() -> None:
    token = issue_jwt(ttl_seconds=3600)
    store = _Store([_bearer_entry("api.testapp.local", token)])
    session = CopilotSession("s1")

    session._capture_bearer_tokens(store, "testapp.local")

    cached = session._bearer_tokens.get("api.testapp.local")
    assert cached is not None
    assert cached["token"] == token
    assert cached["exp"] is not None and cached["exp"] > time.time()


def test_skips_expired_bearer_token() -> None:
    expired = issue_jwt(ttl_seconds=-30)
    store = _Store([_bearer_entry("api.testapp.local", expired)])
    session = CopilotSession("s2")

    session._capture_bearer_tokens(store, "testapp.local")

    assert session._bearer_tokens == {}


def test_skips_copilot_sourced_entries() -> None:
    token = issue_jwt(ttl_seconds=3600)
    store = _Store([_bearer_entry("api.testapp.local", token, source="copilot")])
    session = CopilotSession("s3")

    session._capture_bearer_tokens(store, "testapp.local")

    assert session._bearer_tokens == {}


# ------------------------------------------------------ apply injection (T6)


def test_apply_injects_captured_bearer_on_api_call() -> None:
    token = issue_jwt(ttl_seconds=3600)
    store = _Store([_bearer_entry("app.local", token)])
    session = CopilotSession("s4")
    tool_args: Dict[str, Any] = {"url": "http://app.local/api/me"}

    session._apply_session_auth(_ctx(store), tool_args)

    assert tool_args["headers"].get("Authorization") == f"Bearer {token}"


# --------------------------------------------------- expiry / refresh (T7)


def test_expired_cached_bearer_is_not_injected() -> None:
    """An expired cache entry must not be injected - the real flow relies on the
    401 fast-path refresh instead. Isolated from the borrowed-header path by
    giving history no Authorization header, only a session cookie."""
    session = CopilotSession("s5")
    session._bearer_tokens["app.local"] = {
        "token": "stale", "captured_at": time.time() - 100,
        "source_entry_id": "x", "auth_endpoint": "/api/auth/login",
        "exp": time.time() - 10,
    }
    store = _Store(
        entries=[_Entry(host="app.local", path="/", id="e", source="proxy",
                        request_headers={})],
        cookies={"app.local": [{"name": "fixture_session", "value": "ok"}]},
    )
    tool_args: Dict[str, Any] = {"url": "http://app.local/api/me"}

    session._apply_session_auth(_ctx(store), tool_args)

    assert "Authorization" not in tool_args.get("headers", {})


# ----------------------------------------------- hybrid cookie+csrf+bearer (T8)


def test_apply_injects_cookie_csrf_and_bearer_together() -> None:
    token = issue_jwt(ttl_seconds=3600)
    store = _Store(
        entries=[_bearer_entry("app.local", token)],
        cookies={"app.local": [
            {"name": "fixture_session", "value": "ok"},
            {"name": "CSRF-TOKEN", "value": "csrf-fixture-token"},
        ]},
    )
    session = CopilotSession("s6")
    tool_args: Dict[str, Any] = {"url": "http://app.local/api/orders"}

    session._apply_session_auth(_ctx(store), tool_args)

    headers = tool_args["headers"]
    assert headers.get("Authorization") == f"Bearer {token}"
    assert "fixture_session=ok" in headers.get("Cookie", "")
    assert headers.get("X-CSRF-Token") == "csrf-fixture-token"
    assert headers.get("X-Requested-With") == "XMLHttpRequest"


# ------------------------------------------------------ captcha graceful bail (T5)


def test_captcha_page_is_detected_and_clean_page_is_not() -> None:
    """The CAPTCHA tier must be recognised so the flow bails cleanly instead of
    hammering the form. ``has_captcha`` is the signal the login flow checks."""
    assert has_captcha(_T5) is True
    assert has_captcha(_T0) is False
