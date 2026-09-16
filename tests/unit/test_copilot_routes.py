"""
Unit tests for the Exploration Copilot route helpers.

Focus: the "Login done" auth handoff. The browser the operator logs into routes
through the proxy, so its Set-Cookie responses land in the shared proxy jar — NOT
in the header-less UI entry list the client can read. ``_collect_jar_cookies``
sources those cookies server-side for the paused host so the copilot can retry
authenticated.
"""

from __future__ import annotations

from dast.proxy.api.copilot_routes import _collect_jar_cookies


class _Store:
    def __init__(self, cookies_by_host):
        self._cookies_by_host = cookies_by_host
        self.asked_for = []

    def get_cookies_for_host(self, host):
        self.asked_for.append(host)
        return self._cookies_by_host.get(host, [])


class _Ctx:
    def __init__(self, store):
        self.store = store


def _pause(host="", url=""):
    payload = {"status": 200}
    if host:
        payload["host"] = host
    if url:
        payload["url"] = url
    return {"kind": "auth", "payload": payload}


def test_collect_jar_cookies_by_host():
    store = _Store({"app.acme-corp.com": [
        {"name": "session", "value": "abc123", "domain": "app.acme-corp.com"},
        {"name": "csrf", "value": "tok", "domain": "app.acme-corp.com"},
    ]})
    cookies = _collect_jar_cookies(_Ctx(store), _pause(host="app.acme-corp.com"))
    assert cookies == {"session": "abc123", "csrf": "tok"}
    assert store.asked_for == ["app.acme-corp.com"]


def test_collect_jar_cookies_falls_back_to_url_host():
    store = _Store({"app.acme-corp.com": [
        {"name": "session", "value": "xyz", "domain": "app.acme-corp.com"},
    ]})
    # No explicit host on the payload — derive it from the paused URL.
    cookies = _collect_jar_cookies(
        _Ctx(store), _pause(url="https://app.acme-corp.com/lx/dashboard")
    )
    assert cookies == {"session": "xyz"}


def test_collect_jar_cookies_no_store():
    assert _collect_jar_cookies(_Ctx(None), _pause(host="app.acme-corp.com")) == {}


def test_collect_jar_cookies_no_host():
    store = _Store({"app.acme-corp.com": [{"name": "s", "value": "v"}]})
    assert _collect_jar_cookies(_Ctx(store), _pause()) == {}


def test_collect_jar_cookies_skips_valueless():
    store = _Store({"app.acme-corp.com": [
        {"name": "good", "value": "v"},
        {"name": "noval"},          # missing value -> skipped
        {"value": "orphan"},        # missing name -> skipped
    ]})
    cookies = _collect_jar_cookies(_Ctx(store), _pause(host="app.acme-corp.com"))
    assert cookies == {"good": "v"}
