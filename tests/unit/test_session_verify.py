"""Unit tests for the shared login verification (dast/session/account_state).

Covers the tri-state AuthVerdict matrix of ``verify_authenticated`` — the structural
replacement for the lying success signals (``bool(cookies)``, "URL has no /login") —
plus its consumers: the flow replayer's verified success and the LLM strategy's
``_confirmed_authenticated`` fallback for hash-routed SPAs.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import pytest

from dast.session.account_state import (
    AuthProbeConfig,
    _json_path_get,
    _looks_like_session_cookie,
    _normalize_cookies,
    api_get_fetch,
    session_endpoint_state,
    session_is_authenticated,
    verify_authenticated,
)

BASE = "https://app.test"
ROOT = f"{BASE}/"
PROVISIONED = '{"account": {"id": 42}, "user": {"id": 5}}'
GUEST = '{"account": {"id": -1}, "user": null}'


def _resp(status: int = 200, text: str = "", ok: Optional[bool] = None) -> Dict[str, Any]:
    return {"ok": (200 <= status < 300) if ok is None else ok, "status": status, "text": text}


def _fetch(routes: Dict[str, Dict[str, Any]]):
    async def _fetch_one(url: str) -> Dict[str, Any]:
        return routes.get(url, _resp())
    return _fetch_one


class _Browser:
    """Minimal AgentBrowser stand-in: api_get from a routing table."""

    def __init__(self, routes: Dict[str, Dict[str, Any]]):
        self._routes = routes

    async def api_get(self, url: str) -> Dict[str, Any]:
        return self._routes.get(url, _resp())


# ── small helpers ─────────────────────────────────────────────────────────────

def test_json_path_get():
    assert _json_path_get({"user": {"id": 7}}, "user.id") == 7
    assert _json_path_get({"user": {}}, "user.id") is None
    assert _json_path_get({"a": [1]}, "a.0") is None  # arrays are not traversed
    assert _json_path_get({}, "anything") is None


def test_session_cookie_heuristic_ignores_analytics():
    # The whole point vs the old bool(cookies): cf_bm/_ga never count.
    assert _looks_like_session_cookie({"cf_bm": "x", "_ga": "y"}) is None
    assert _looks_like_session_cookie({"cf_bm": "x", "sessionid": "abc"}) == "sessionid"
    assert _looks_like_session_cookie({"__Secure-next-auth.session-token": "t"}) is not None
    assert _looks_like_session_cookie({"JSESSIONID": "j"}) is not None


def test_normalize_cookies_accepts_both_shapes():
    assert _normalize_cookies(None) == {}
    assert _normalize_cookies({"a": "1"}) == {"a": "1"}
    assert _normalize_cookies([{"name": "a", "value": "1"},
                               {"name": "b", "value": "2"}]) == {"a": "1", "b": "2"}
    assert _normalize_cookies([{"name": "a"}, "junk"]) == {"a": ""}


def test_probe_config_from_profile_and_configured():
    class _P:
        probe_url = "/api/me"
        probe_expect_json_path = "user.id"
        probe_expect_cookie = "app_session"

    cfg = AuthProbeConfig.from_profile(_P())
    assert cfg.configured is True
    assert cfg.expect_json_path == "user.id"
    assert AuthProbeConfig().configured is False
    # A profile predating the probe fields degrades to the default (no crash).
    assert AuthProbeConfig.from_profile(object()).probe_url == ""


# ── verify_authenticated verdict matrix ──────────────────────────────────────

@pytest.mark.asyncio
async def test_root_401_contradicts_even_with_cookies():
    verdict = await verify_authenticated(
        _fetch({ROOT: _resp(401, "unauthorized")}), base_url=BASE,
        session_cookies=[{"name": "sessionid", "value": "abc"}])
    assert verdict.authenticated is False
    assert "wall" in verdict.reason


@pytest.mark.asyncio
async def test_root_200_with_only_analytics_cookies_is_indeterminate():
    """The old behavior counted ANY cookie as success; the heuristic tier requires a
    session-looking cookie, so a bare 200 SPA shell with cf_bm/_ga stays None."""
    verdict = await verify_authenticated(
        _fetch({ROOT: _resp(200, "<html>app</html>")}), base_url=BASE,
        session_cookies=[{"name": "cf_bm", "value": "x"}, {"name": "_ga", "value": "y"}])
    assert verdict.authenticated is None


@pytest.mark.asyncio
async def test_session_cookie_is_positive_evidence():
    verdict = await verify_authenticated(
        _fetch({ROOT: _resp(200, "ok")}), base_url=BASE,
        session_cookies=[{"name": "cf_bm", "value": "x"}, {"name": "sessionid", "value": "s"}])
    assert verdict.authenticated is True
    assert verdict.evidence.get("session_cookie") == "sessionid"


@pytest.mark.asyncio
async def test_provisioned_endpoint_is_positive_evidence_without_cookies():
    routes = {ROOT: _resp(200, "<html/>"), f"{BASE}/spa/session": _resp(200, PROVISIONED)}
    verdict = await verify_authenticated(_fetch(routes), base_url=BASE, session_cookies=None)
    assert verdict.authenticated is True


@pytest.mark.asyncio
async def test_guest_endpoint_contradicts():
    routes = {ROOT: _resp(200, "<html/>"), f"{BASE}/spa/session": _resp(200, GUEST)}
    verdict = await verify_authenticated(_fetch(routes), base_url=BASE)
    assert verdict.authenticated is False


@pytest.mark.asyncio
async def test_endpoint_404_falls_through_to_cookie_tier():
    routes = {ROOT: _resp(200, "<html/>"), f"{BASE}/spa/session": _resp(404, "nope")}
    verdict = await verify_authenticated(
        _fetch(routes), base_url=BASE, session_cookies={"sessionid": "s"})
    assert verdict.authenticated is True


@pytest.mark.asyncio
async def test_probe_config_json_path_truthy_is_positive():
    probe = AuthProbeConfig(probe_url="/api/me", expect_json_path="user.id")
    routes = {ROOT: _resp(200, "<html/>"), f"{BASE}/api/me": _resp(200, '{"user": {"id": 7}}')}
    verdict = await verify_authenticated(_fetch(routes), base_url=BASE, probe=probe)
    assert verdict.authenticated is True


@pytest.mark.asyncio
async def test_probe_config_json_path_missing_is_not_a_contradiction():
    """A 200 without the expected path is 'can't tell' — the app may shape the endpoint
    differently. Only a wall or an explicitly guest body contradicts."""
    probe = AuthProbeConfig(probe_url="/api/me", expect_json_path="user.id")
    routes = {ROOT: _resp(200, "<html/>"), f"{BASE}/api/me": _resp(200, '{"ok": true}')}
    verdict = await verify_authenticated(_fetch(routes), base_url=BASE, probe=probe)
    assert verdict.authenticated is None


@pytest.mark.asyncio
async def test_probe_endpoint_wall_contradicts():
    probe = AuthProbeConfig(probe_url="/api/me")
    routes = {ROOT: _resp(200, "<html/>"), f"{BASE}/api/me": _resp(403, "forbidden")}
    verdict = await verify_authenticated(_fetch(routes), base_url=BASE, probe=probe)
    assert verdict.authenticated is False


@pytest.mark.asyncio
async def test_expect_cookie_is_a_hard_expectation():
    probe = AuthProbeConfig(expect_cookie="app_session")
    cookies = [{"name": "sessionid", "value": "s"}]  # session-looking but NOT the one
    verdict = await verify_authenticated(
        _fetch({ROOT: _resp(200, "ok")}), base_url=BASE, probe=probe, session_cookies=cookies)
    assert verdict.authenticated is False
    assert verdict.evidence.get("expected_cookie") == "app_session"

    verdict2 = await verify_authenticated(
        _fetch({ROOT: _resp(200, "ok")}), base_url=BASE, probe=probe,
        session_cookies={"app_session": "v"})
    assert verdict2.authenticated is True


@pytest.mark.asyncio
async def test_expect_cookie_without_a_jar_does_not_contradict():
    """The caller didn't hand over cookies — absence proves nothing (None, not False)."""
    probe = AuthProbeConfig(expect_cookie="app_session")
    verdict = await verify_authenticated(
        _fetch({ROOT: _resp(200, "<html/>")}), base_url=BASE, probe=probe, session_cookies=None)
    assert verdict.authenticated is None


@pytest.mark.asyncio
async def test_transport_error_fails_open():
    async def _boom(url):
        raise RuntimeError("dns down")
    verdict = await verify_authenticated(_boom, base_url=BASE)
    assert verdict.authenticated is None


@pytest.mark.asyncio
async def test_bad_base_url_is_indeterminate():
    verdict = await verify_authenticated(_fetch({}), base_url="not-a-url")
    assert verdict.authenticated is None


# ── session_endpoint_state (the shared /spa/session classifier) ──────────────

@pytest.mark.asyncio
async def test_session_endpoint_state_default_and_custom():
    routes = {f"{BASE}/spa/session": _resp(200, PROVISIONED)}
    assert await session_endpoint_state(_fetch(routes), BASE) is True
    routes2 = {f"{BASE}/api/me": _resp(200, '{"user": {"id": 3}}')}
    cfg = AuthProbeConfig(probe_url="/api/me")
    assert await session_endpoint_state(_fetch(routes2), BASE, cfg) is True
    routes3 = {f"{BASE}/api/me": _resp(401, "")}
    assert await session_endpoint_state(_fetch(routes3), BASE, cfg) is False
    # Non-JSON / missing endpoint → None (fail open).
    assert await session_endpoint_state(_fetch({}), BASE) is None


@pytest.mark.asyncio
async def test_session_is_authenticated_uses_browser_api_get_and_ignores_expect_cookie():
    """session_is_authenticated has no jar access, so expect_cookie must NOT read as
    a contradiction there."""
    browser = _Browser({ROOT: _resp(200, "<html/>"), f"{BASE}/spa/session": _resp(200, PROVISIONED)})
    assert await session_is_authenticated(browser, BASE) is True
    guest = _Browser({ROOT: _resp(200, "<html/>"), f"{BASE}/spa/session": _resp(200, GUEST)})
    assert await session_is_authenticated(guest, BASE) is False
    # A 302 to a NON-login URL is not a wall (no Location in the fetch shape); a
    # 401 root is.
    wall = _Browser({ROOT: _resp(401, "")})
    assert await session_is_authenticated(wall, BASE) is False
    cfg = AuthProbeConfig(expect_cookie="never_present")
    ok_browser = _Browser({ROOT: _resp(200, "<html/>"), f"{BASE}/spa/session": _resp(200, PROVISIONED)})
    assert await session_is_authenticated(ok_browser, BASE, cfg) is True


@pytest.mark.asyncio
async def test_api_get_fetch_adapter_wraps_browser():
    browser = _Browser({"https://x.test/": _resp(200, "hello")})
    fetch = api_get_fetch(browser)
    assert (await fetch("https://x.test/"))["text"] == "hello"


# ── flow replayer: verified success ──────────────────────────────────────────

class _FakeResponse:
    def __init__(self, status, text):
        self.status = status
        self._text = text

    @property
    def ok(self):
        return 200 <= self.status < 300

    async def text(self):
        return self._text


class _FakeRequest:
    def __init__(self, routes):
        self._routes = routes

    async def get(self, url, headers=None, timeout=None):
        r = self._routes.get(url)
        if not r:
            return _FakeResponse(200, "")
        # Routes built via _resp() carry a precomputed "ok" key — status/text drive it.
        return _FakeResponse(r.get("status", 200), r.get("text", ""))


class _FakePage:
    def __init__(self, routes):
        self.request = _FakeRequest(routes)
        self.url = f"{BASE}/login"

    async def goto(self, *a, **k):
        return None

    async def content(self):
        return ""

    def on(self, *a, **k):
        return None

    async def wait_for_url(self, *a, **k):
        return None


class _FakeContext:
    def __init__(self, page, cookies):
        self._page = page
        self._cookies = cookies

    async def new_page(self):
        return self._page

    async def cookies(self):
        return self._cookies

    async def storage_state(self):
        return {"cookies": self._cookies, "origins": []}


class _FakePWBrowser:
    def __init__(self, context):
        self._context = context

    async def new_context(self, **k):
        return self._context

    async def close(self):
        return None


class _FakePlaywright:
    def __init__(self, browser):
        self._browser = browser
        self.chromium = self

    async def launch(self, **k):
        return self._browser

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _install_fake_playwright(monkeypatch, routes, cookies):
    import sys
    import types
    context = _FakeContext(_FakePage(routes), cookies)
    fake = types.SimpleNamespace(
        async_playwright=lambda: _FakePlaywright(_FakePWBrowser(context)))
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake)
    return context


def _flow_dict(**extra):
    flow = {
        "start_url": f"{BASE}/login",
        "steps": [{"action": "navigate", "value": f"{BASE}/login"}],
    }
    flow.update(extra)
    return flow


@pytest.mark.asyncio
async def test_replayer_verified_success(monkeypatch):
    from dast.session.flow_replayer import replay_login_flow
    routes = {ROOT: _resp(200, "<html/>"), f"{BASE}/spa/session": _resp(200, PROVISIONED)}
    _install_fake_playwright(monkeypatch, routes,
                             [{"name": "cf_bm", "value": "x"}])  # NO session cookie!
    result = await replay_login_flow(
        proxy_port=8080, flow=__import__("dast.profiles.flow", fromlist=["LoginFlow"]).LoginFlow.from_dict(_flow_dict()))
    # Old behavior: cf_bm-only jar still read success=False only by luck of empty jar;
    # now the provisioned endpoint positively confirms even without a session cookie.
    assert result["success"] is True
    assert result["verified"] is True


@pytest.mark.asyncio
async def test_replayer_contradicted_success_becomes_failure(monkeypatch):
    """THE lying-success killer: an analytics-only jar on an auth-walled origin used to
    report success=True (`bool(cookies)`) and feed stale state into re-auth loops."""
    from dast.profiles.flow import LoginFlow
    from dast.session.flow_replayer import replay_login_flow
    routes = {ROOT: _resp(401, "unauthorized")}
    _install_fake_playwright(monkeypatch, routes,
                             [{"name": "cf_bm", "value": "x"},
                              {"name": "_ga", "value": "y"}])
    result = await replay_login_flow(
        proxy_port=8080, flow=LoginFlow.from_dict(_flow_dict()))
    assert result["success"] is False
    assert result["verified"] is False
    assert result["cookies"]  # evidence is still returned for debugging


@pytest.mark.asyncio
async def test_replayer_indeterminate_keeps_legacy_behavior(monkeypatch):
    """No wall, no session cookie, no endpoint → verified=None → legacy bool(cookies)."""
    from dast.profiles.flow import LoginFlow
    from dast.session.flow_replayer import replay_login_flow
    routes = {ROOT: _resp(200, "<html>shell</html>")}
    cookies = [{"name": "cf_bm", "value": "x"}, {"name": "_ga", "value": "y"}]
    _install_fake_playwright(monkeypatch, routes, cookies)
    result = await replay_login_flow(
        proxy_port=8080, flow=LoginFlow.from_dict(_flow_dict()))
    assert result["verified"] is None
    assert result["success"] is bool(cookies)


@pytest.mark.asyncio
async def test_replayer_probe_config_reaches_verification(monkeypatch):
    from dast.profiles.flow import LoginFlow
    from dast.session.account_state import AuthProbeConfig
    from dast.session.flow_replayer import replay_login_flow
    routes = {
        ROOT: _resp(200, "<html>shell</html>"),
        f"{BASE}/api/me": _resp(200, '{"user": {"id": 9}}'),
    }
    _install_fake_playwright(monkeypatch, routes, [{"name": "cf_bm", "value": "x"}])
    result = await replay_login_flow(
        proxy_port=8080, flow=LoginFlow.from_dict(_flow_dict()),
        probe=AuthProbeConfig(probe_url="/api/me", expect_json_path="user.id"))
    assert result["success"] is True
    assert result["verified"] is True


# ── LLM strategy: hash-routed SPAs can finally "succeed" ─────────────────────

class _LlmBrowser:
    """Browser for _confirmed_authenticated: unchanged URL (hash-routed SPA) + probe."""

    def __init__(self, routes, cookies):
        self._routes = routes
        self._cookies = cookies

    async def api_get(self, url):
        return self._routes.get(url, _resp())

    async def export_cookies(self):
        return self._cookies

    async def snapshot(self):
        return {"url": f"{BASE}/#/dashboard"}


@pytest.mark.asyncio
async def test_llm_confirmed_authenticated_on_unchanged_url():
    """The old gate required `url != ctx.url` — a hash-routed SPA never left the login
    URL and a WORKING login read as failed. Now the structural probe decides."""
    from dast.browser.login_strategies.llm import _confirmed_authenticated
    from dast.browser.login_strategies.base import LoginContext

    routes = {ROOT: _resp(200, "<html/>"), f"{BASE}/spa/session": _resp(200, PROVISIONED)}
    ctx = LoginContext(browser=_LlmBrowser(routes, {}), url=f"{BASE}/login",
                       email="e", password="p")
    assert await _confirmed_authenticated(ctx, f"{BASE}/login") is True  # SAME url!


@pytest.mark.asyncio
async def test_llm_confirmed_authenticated_rejects_wall():
    from dast.browser.login_strategies.llm import _confirmed_authenticated
    from dast.browser.login_strategies.base import LoginContext

    routes = {ROOT: _resp(401, "")}
    ctx = LoginContext(browser=_LlmBrowser(routes, {}), url=f"{BASE}/login",
                       email="e", password="p")
    assert await _confirmed_authenticated(ctx, f"{BASE}/login") is False
