"""Copilot reliability guards: model-pasted session headers on browser_fetch are rejected at
dispatch (while the copilot's OWN injected session still flows), the header-strip watchdog
guides before it kills, and dedup state resets on every auth-state change."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dast.ai.copilot.session import _MAX_HEADER_STRIPS, CopilotSession
from tests.unit.test_copilot_session import (
    _TOOLS,
    _collector,
    _deny_human,
    _FakeCtx,
    _FakeStore,
    _FakeTool,
)

_FETCH_TOOLS = _TOOLS + [_FakeTool("browser_fetch")]


def _fetch_step(headers: Dict[str, str] | None = None, url: str = "https://in.scope/api") -> Dict[str, Any]:
    args: Dict[str, Any] = {"url": url, "method": "GET"}
    if headers is not None:
        args["headers"] = headers
    return {"action": "call_tool", "thought": "p", "tool_name": "browser_fetch", "tool_args": args}


_REPLY = {"action": "reply", "thought": "d", "message": "ok"}


async def _drive(session: CopilotSession, ctx: Any, steps: List[Dict[str, Any]], run_tool):
    events, on_event = _collector()
    with patch("dast.tools.all_tools", return_value=_FETCH_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("go", ctx, on_event=on_event, wait_for_human=_deny_human())
    observations = [e["observation"] for e in events if e.get("type") == "observation"]
    return reply, observations


def _jar_ctx() -> _FakeCtx:
    ctx = _FakeCtx()
    ctx.store = _FakeStore(cookies=[{"name": "session", "value": "ACTIVE"}], entries=[])
    return ctx


# ── browser_fetch: reject model-pasted Cookie/Authorization at dispatch ──

@pytest.mark.asyncio
@pytest.mark.parametrize("header", ["Cookie", "cookie", "COOKIE", "Authorization", "authorization"])
async def test_browser_fetch_pasted_session_header_is_rejected_not_sent(header):
    run_tool = AsyncMock(return_value={"ok": True, "status": 200})
    reply, obs = await _drive(CopilotSession("s-rej"), _jar_ctx(),
                              [_fetch_step({header: "x"}), _REPLY], run_tool)
    run_tool.assert_not_called()
    assert any("NOT sent" in o and header in o for o in obs)
    assert reply.message == "ok"


@pytest.mark.asyncio
async def test_browser_fetch_copilot_injected_session_is_not_rejected():
    # Regression: _apply_session_auth writes the jar Cookie into browser_fetch's tool_args.
    # That injected session is legitimate and must reach the tool (which hands auth to the
    # browser context) — only the MODEL's own pasted headers are rejected.
    from dast.tools.browser_tools import _fetch

    response = MagicMock(status=200, headers={})
    response.text = AsyncMock(return_value="{}")
    page = MagicMock(url="https://in.scope/app")
    page.request.fetch = AsyncMock(return_value=response)
    browser = MagicMock()
    browser.ensure_fresh_cookies = AsyncMock()
    browser._ensure_page = AsyncMock(return_value=page)
    browser.export_cookies = AsyncMock(return_value={"session": "ACTIVE"})
    tool_ctx = SimpleNamespace(browser=browser, store=None, is_in_scope=lambda _u: True)
    captured: List[Dict[str, Any]] = []

    async def run_tool(_ctx, name, args):
        captured.append(dict(args))
        return await _fetch(tool_ctx, args)  # the REAL handler, with copilot-injected args

    _, obs = await _drive(CopilotSession("s-inj"), _jar_ctx(),
                          [_fetch_step({"Accept": "application/json"}), _REPLY], run_tool)
    assert "Cookie" in captured[0]["headers"]  # the copilot injected the session
    page.request.fetch.assert_awaited_once()  # and the real handler still sent it
    sent_headers = page.request.fetch.await_args.kwargs["headers"]
    assert not any(k.lower() == "cookie" for k in sent_headers)  # browser context owns the jar
    assert not any("NOT sent" in o for o in obs)


@pytest.mark.asyncio
async def test_browser_fetch_without_headers_runs():
    run_tool = AsyncMock(return_value={"ok": True, "status": 200})
    await _drive(CopilotSession("s-noh"), _FakeCtx(), [_fetch_step(), _REPLY], run_tool)
    run_tool.assert_awaited_once()


# ── header-strip watchdog: guidance at the warn threshold, kill at 2x ──

@pytest.mark.asyncio
async def test_header_strip_warn_injects_guidance_once():
    run_tool = AsyncMock(return_value={"ok": True, "status": 200})
    steps = [
        {"action": "call_tool", "thought": "p", "tool_name": "send_request",
         "tool_args": {"url": f"https://in.scope/e{i}", "headers": {"Cookie": "session=STALE"}}}
        for i in range(_MAX_HEADER_STRIPS)
    ] + [_REPLY]
    reply, obs = await _drive(CopilotSession("s-warn"), _jar_ctx(), steps, run_tool)
    guided = [o for o in obs if o.startswith("[SYSTEM]")]
    assert len(guided) == 1
    assert "NEVER set them" in guided[0]
    assert reply.blocked_reason == ""


@pytest.mark.asyncio
async def test_header_strip_guidance_survives_tool_failure():
    run_tool = AsyncMock(return_value={"ok": False, "error": "boom"})
    steps = [
        {"action": "call_tool", "thought": "p", "tool_name": "send_request",
         "tool_args": {"url": f"https://in.scope/f{i}", "headers": {"Cookie": "session=STALE"}}}
        for i in range(_MAX_HEADER_STRIPS)
    ] + [_REPLY]
    _, obs = await _drive(CopilotSession("s-warnfail"), _jar_ctx(), steps, run_tool)
    assert any(o.startswith("[SYSTEM]") for o in obs)


# ── dedup reset on auth-state change ──

@pytest.mark.asyncio
async def test_reset_dedup_makes_identical_call_retryable():
    session = CopilotSession("s-dedup")
    run_tool = AsyncMock(return_value={"ok": True, "status": 403})
    step = {"action": "call_tool", "thought": "p", "tool_name": "send_request",
            "tool_args": {"url": "https://in.scope/me", "method": "GET"}}

    await _drive(session, _FakeCtx(), [step, _REPLY], run_tool)
    _, obs = await _drive(session, _FakeCtx(), [step, _REPLY], run_tool)
    assert run_tool.await_count == 1
    assert any("suppressed" in o for o in obs)

    session.reset_dedup("relogin")
    await _drive(session, _FakeCtx(), [step, _REPLY], run_tool)
    assert run_tool.await_count == 2


def test_reset_dedup_keeps_header_strip_counters():
    session = CopilotSession("s-keep")
    session._seen_calls.add("k")
    session._repeat_sigs["sig"] = 2
    session._stripped_header_count = 3
    session._header_strip_warned = True
    session.reset_dedup("relogin")
    assert not session._seen_calls and not session._repeat_sigs
    assert session._stripped_header_count == 3 and session._header_strip_warned


@pytest.mark.asyncio
async def test_tier_relogin_success_resets_dedup():
    session = CopilotSession("s-relog")
    session._last_login = {"url": "https://in.scope/login", "email": "u", "password": "p"}
    session._seen_calls.add("k")
    browser = MagicMock()
    browser.export_cookies = AsyncMock(return_value={"session": "NEW"})
    cascade = SimpleNamespace(ok=True, engine="form", error="")
    with patch("dast.browser.login_cascade.adaptive_login", new=AsyncMock(return_value=cascade)):
        assert await session._tier_relogin(None, "in.scope", browser, _FakeCtx())
    assert not session._seen_calls


@pytest.mark.asyncio
async def test_tier_relogin_failure_keeps_dedup():
    session = CopilotSession("s-relogfail")
    session._last_login = {"url": "https://in.scope/login", "email": "u", "password": "p"}
    session._seen_calls.add("k")
    cascade = SimpleNamespace(ok=False, engine="form", error="bad creds")
    with patch("dast.browser.login_cascade.adaptive_login", new=AsyncMock(return_value=cascade)):
        assert not await session._tier_relogin(None, "in.scope", MagicMock(), _FakeCtx())
    assert session._seen_calls == {"k"}


def test_refresh_session_resets_dedup():
    from dast.proxy.api.copilot_service import CopilotService

    engine = CopilotSession("s-refresh", focus_hosts=["in.scope"])
    engine._seen_calls.add("k")
    store = MagicMock()
    store.get_cookies_for_host.return_value = [{"name": "session", "value": "NEW"}]
    fake = SimpleNamespace(_sessions={"sid": {"engine": engine}}, _ctx=SimpleNamespace(store=store))
    out = CopilotService.refresh_session(fake, "sid")
    assert out["ok"] and out["cookies_refreshed"] == 1
    assert not engine._seen_calls


@pytest.mark.asyncio
async def test_activate_login_profile_saved_session_resets_dedup():
    from dast.tools.session_tools import _activate_login_profile

    engine = CopilotSession("s-act")
    engine._seen_calls.add("k")
    profile = SimpleNamespace(slug="p1", name="Admin", privilege_level="admin",
                              saved_session={"cookies": [{"name": "session", "value": "v"}]})
    store = MagicMock()
    store.import_playwright_cookies.return_value = 1
    ctx = SimpleNamespace(store=store, session=engine)
    with patch("dast.profiles.store.load_profile", return_value=profile):
        out = await _activate_login_profile(ctx, {"slug": "p1"})
    assert out["ok"]
    assert not engine._seen_calls


@pytest.mark.asyncio
async def test_browser_login_tool_resets_dedup():
    from dast.tools.login_tools import _adaptive_login

    engine = CopilotSession("s-bl")
    engine._seen_calls.add("k")
    browser = MagicMock()
    browser.export_cookies = AsyncMock(return_value={"session": "NEW"})
    ctx = SimpleNamespace(browser=browser, session=engine, store=None, is_in_scope=lambda _u: True)
    result = SimpleNamespace(ok=True, to_dict=lambda: {"ok": True})
    with patch("dast.browser.login_cascade.adaptive_login", new=AsyncMock(return_value=result)):
        out = await _adaptive_login(ctx, {"url": "https://in.scope/login", "email": "a@b.example",
                                          "password": "pw-real-1"})
    assert out["ok"]
    assert not engine._seen_calls


# ── 2a: saved-session profile activation arms the expiry relogin ──

@pytest.mark.asyncio
@pytest.mark.parametrize("has_creds", [True, False])
async def test_activate_saved_profile_seeds_relogin_credentials(has_creds):
    from dast.tools.session_tools import _activate_login_profile

    engine = CopilotSession("s-arm")
    creds = [SimpleNamespace(username="u@x.example", secret="pw")] if has_creds else []
    profile = SimpleNamespace(slug="p1", name="Admin", privilege_level="admin",
                              credentials=creds, auth_url="https://in.scope/login",
                              saved_session={"cookies": [{"name": "session", "value": "v"}]})
    store = MagicMock()
    store.import_playwright_cookies.return_value = 1
    with patch("dast.profiles.store.load_profile", return_value=profile):
        out = await _activate_login_profile(SimpleNamespace(store=store, session=engine), {"slug": "p1"})
    assert out["ok"]
    if has_creds:
        assert engine._last_login == {"url": "https://in.scope/login", "email": "u@x.example",
                                      "password": "pw"}
    else:
        assert engine._last_login is None


# ── 2b: expiry detection on a 2xx -> 401/403 flip (incl. browser_fetch) ──

def _req(path: str, tool: str = "send_request") -> Dict[str, Any]:
    return {"action": "call_tool", "thought": "p", "tool_name": tool,
            "tool_args": {"url": f"https://in.scope{path}", "method": "GET"}}


def _armed_session(sid: str) -> CopilotSession:
    session = CopilotSession(sid)
    session._last_login = {"url": "https://in.scope/login", "email": "u", "password": "p"}
    session.refresh_bearer = AsyncMock(return_value=SimpleNamespace(acted=True))
    return session


def _status_by_path(statuses: Dict[str, List[int]]):
    calls: List[str] = []

    async def run_tool(_ctx, _name, args):
        path = args["url"].split("in.scope", 1)[1]
        calls.append(path)
        seq = statuses[path]
        return {"ok": True, "status": seq.pop(0) if len(seq) > 1 else seq[0]}

    return run_tool, calls


@pytest.mark.asyncio
async def test_403_flip_on_distinct_paths_triggers_relogin_and_retry():
    session = _armed_session("s-flip")
    run_tool, calls = _status_by_path({"/a": [200], "/b": [403], "/c": [403, 200]})
    await _drive(session, _FakeCtx(), [_req("/a"), _req("/b"), _req("/c"), _REPLY], run_tool)
    session.refresh_bearer.assert_awaited_once()
    assert session.refresh_bearer.await_args.kwargs["reason"] == "auth-flip"
    assert calls == ["/a", "/b", "/c", "/c"]  # retried once after the relogin
    assert not session._host_authfail


@pytest.mark.asyncio
async def test_single_403_after_2xx_is_an_authz_result_not_expiry():
    session = _armed_session("s-one403")
    run_tool, _ = _status_by_path({"/a": [200], "/admin": [403]})
    await _drive(session, _FakeCtx(), [_req("/a"), _req("/admin"), _REPLY], run_tool)
    session.refresh_bearer.assert_not_awaited()


@pytest.mark.asyncio
async def test_403s_on_a_never_ok_host_do_not_trigger_relogin():
    session = _armed_session("s-never")
    run_tool, _ = _status_by_path({"/b": [403], "/c": [403]})
    await _drive(session, _FakeCtx(), [_req("/b"), _req("/c"), _REPLY], run_tool)
    session.refresh_bearer.assert_not_awaited()


@pytest.mark.asyncio
async def test_2xx_between_403s_resets_the_flip():
    session = _armed_session("s-reset")
    run_tool, _ = _status_by_path({"/a": [200], "/b": [403], "/ok": [200], "/c": [403]})
    await _drive(session, _FakeCtx(), [_req("/a"), _req("/b"), _req("/ok"), _req("/c"), _REPLY],
                 run_tool)
    session.refresh_bearer.assert_not_awaited()


@pytest.mark.asyncio
async def test_browser_fetch_401_now_triggers_expiry_relogin():
    session = _armed_session("s-bf401")
    run_tool, calls = _status_by_path({"/api": [401, 200]})
    await _drive(session, _FakeCtx(), [_req("/api", tool="browser_fetch"), _REPLY], run_tool)
    session.refresh_bearer.assert_awaited_once()
    assert calls == ["/api", "/api"]


@pytest.mark.asyncio
async def test_flip_without_relogin_credentials_does_nothing():
    session = CopilotSession("s-nocreds")
    session.refresh_bearer = AsyncMock(return_value=SimpleNamespace(acted=True))
    run_tool, _ = _status_by_path({"/a": [200], "/b": [403], "/c": [403]})
    await _drive(session, _FakeCtx(), [_req("/a"), _req("/b"), _req("/c"), _REPLY], run_tool)
    session.refresh_bearer.assert_not_awaited()


# ── 2c: autonomous uniform-failure breaker tries ONE re-login per run ──

def _breaker_fake(engine):
    return SimpleNamespace(_build_tool_ctx=lambda _s: SimpleNamespace(browser=object()),
                           _ctx=SimpleNamespace(store=None))


@pytest.mark.asyncio
async def test_breaker_reauth_once_per_run():
    from dast.proxy.api.copilot_service import CopilotService

    engine = MagicMock(_last_login={"url": "https://in.scope/login", "email": "u", "password": "p"})
    engine._tier_relogin = AsyncMock(return_value=True)
    session = {"engine": engine, "autonomous": {}}
    fake = _breaker_fake(engine)
    assert await CopilotService._breaker_reauth(fake, "sid", session) is True
    assert await CopilotService._breaker_reauth(fake, "sid", session) is None
    engine._tier_relogin.assert_awaited_once()
    assert engine._tier_relogin.await_args.args[1] == "in.scope"


@pytest.mark.asyncio
async def test_breaker_reauth_failure_reports_false():
    from dast.proxy.api.copilot_service import CopilotService

    engine = MagicMock(_last_login={"url": "https://in.scope/login", "email": "u", "password": "p"})
    engine._tier_relogin = AsyncMock(return_value=False)
    assert await CopilotService._breaker_reauth(
        _breaker_fake(engine), "sid", {"engine": engine, "autonomous": {}}) is False


@pytest.mark.asyncio
async def test_breaker_reauth_skipped_without_credentials():
    from dast.proxy.api.copilot_service import CopilotService

    engine = MagicMock(_last_login=None)
    engine._tier_relogin = AsyncMock(return_value=True)
    assert await CopilotService._breaker_reauth(
        _breaker_fake(engine), "sid", {"engine": engine, "autonomous": {}}) is None
    engine._tier_relogin.assert_not_awaited()
