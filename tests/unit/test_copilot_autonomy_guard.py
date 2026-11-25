"""Tests for the copilot autonomy-guard improvements (PR #77):

1. Soft-warn before hard-block: a [SYSTEM] warning appears in the observation when the
   noprogress threshold is reached, giving the model one chance to pivot.
2. browser_snapshot exempt from noprogress guard: identical snapshots don't trigger
   the no-progress watchdog (the absolute _MAX_NORMALIZED_REPEATS cap still bounds them).
3. Browser cleanup on terminal blocked reasons (stuck_loop, error, safety_blocked).
4. Session browser reaper closes idle browsers after the TTL.
5. DELETE /api/copilot/session/{sid} cancels, closes browser, and removes the session.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dast.ai.copilot.session import (
    _MAX_NOPROGRESS_REPEATS,
    _NOPROGRESS_EXEMPT_TOOLS,
    CopilotSession,
)
from tests.unit.test_copilot_session import (
    _TOOLS,
    _collector,
    _deny_human,
    _FakeCtx,
    _FakeTool,
)


_SNAPSHOT_TOOLS = _TOOLS + [_FakeTool("browser_snapshot", tags=["browser", "read"])]

_REPLY = {"action": "reply", "thought": "done", "message": "ok"}


def _send_step(url: str, method: str = "GET",
               headers: Dict[str, str] | None = None) -> Dict[str, Any]:
    args: Dict[str, Any] = {"url": url, "method": method}
    if headers is not None:
        args["headers"] = headers
    return {
        "action": "call_tool", "thought": "p",
        "tool_name": "send_request", "tool_args": args,
    }


def _snapshot_step() -> Dict[str, Any]:
    return {
        "action": "call_tool", "thought": "observe",
        "tool_name": "browser_snapshot", "tool_args": {},
    }


async def _drive(session, ctx, steps, run_tool, tools=None):
    events, on_event = _collector()
    with patch("dast.tools.all_tools", return_value=tools or _TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("go", ctx, on_event=on_event,
                                   wait_for_human=_deny_human())
    observations = [e["observation"] for e in events if e.get("type") == "observation"]
    return reply, observations


# ── 1. Soft-warn before hard-block ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_noprogress_warning_appears_before_hard_block():
    """After _MAX_NOPROGRESS_REPEATS identical outcomes, the observation should contain
    a [SYSTEM] warning. The turn should NOT be killed yet — the model gets one chance.

    To bypass the exact-dedup layer (which blocks identical call_keys), each call uses
    a different header value. The normalized signature strips headers, so they all hit
    the same noprogress counter."""
    same_result = {"ok": True, "status": 200, "body": "same"}
    run_tool = AsyncMock(return_value=same_result)

    # _MAX_NOPROGRESS_REPEATS + 1 calls (3): noprogress goes 0→1→2 (threshold)
    # Each call has a different header to bypass exact-dedup but same normalized sig
    n = _MAX_NOPROGRESS_REPEATS + 1
    steps = [
        _send_step("https://in.scope/api", headers={"X-Req": str(i)})
        for i in range(n)
    ] + [_REPLY]

    reply, obs = await _drive(CopilotSession("s-warn"), _FakeCtx(), steps, run_tool)

    warned = [o for o in obs if "[SYSTEM]" in o and "no progress" in o]
    assert len(warned) == 1, f"Expected 1 warning, got {len(warned)}"
    assert "MUST change approach" in warned[0]
    assert reply.message == "ok"
    assert reply.blocked_reason == ""


@pytest.mark.asyncio
async def test_noprogress_hard_block_fires_after_warning():
    """After the warning, if the model issues one more identical call, the turn is killed."""
    same_result = {"ok": True, "status": 200, "body": "same"}
    run_tool = AsyncMock(return_value=same_result)

    # _MAX_NOPROGRESS_REPEATS + 2 calls (4): warning on call 3, kill on call 4
    n = _MAX_NOPROGRESS_REPEATS + 2
    steps = [
        _send_step("https://in.scope/api", headers={"X-Req": str(i)})
        for i in range(n)
    ] + [_REPLY]

    reply, obs = await _drive(CopilotSession("s-kill"), _FakeCtx(), steps, run_tool)

    assert reply.blocked_reason == "stuck_loop"
    assert "Stopped:" in reply.message


@pytest.mark.asyncio
async def test_noprogress_resets_on_different_outcome():
    """A call that returns a different result resets the noprogress streak."""
    call_count = 0

    async def varying_tool(_ctx, _name, _args):
        nonlocal call_count
        call_count += 1
        return {"ok": True, "status": 200, "body": f"response-{call_count}"}

    # 6 calls to the same endpoint with varying headers (bypass exact-dedup),
    # all returning different bodies — noprogress should never trigger
    steps = [
        _send_step("https://in.scope/api", headers={"X-Req": str(i)})
        for i in range(6)
    ] + [_REPLY]

    reply, obs = await _drive(CopilotSession("s-vary"), _FakeCtx(), steps, varying_tool)

    warned = [o for o in obs if "[SYSTEM]" in o and "no progress" in o]
    assert len(warned) == 0
    assert reply.blocked_reason == ""


# ── 2. browser_snapshot exempt from noprogress ──────────────────────────────

def test_browser_snapshot_in_exempt_set():
    assert "browser_snapshot" in _NOPROGRESS_EXEMPT_TOOLS


@pytest.mark.asyncio
async def test_browser_snapshot_does_not_trigger_noprogress():
    """browser_snapshot called many times with identical results should NOT trigger
    the noprogress guard. The absolute _MAX_NORMALIZED_REPEATS cap is higher (8),
    so we test below that."""
    snapshot_result = {"ok": True, "url": "https://app/page", "title": "Page",
                       "forms": [], "fields": [], "buttons": [], "links": []}

    call_count = 0

    async def snapshot_tool(_ctx, _name, _args):
        nonlocal call_count
        call_count += 1
        return dict(snapshot_result)

    # Interleave browser_navigate to DIFFERENT pages (clears _seen_calls each time
    # and each nav has a unique normalized sig so it won't trigger noprogress itself)
    # with browser_snapshot. The snapshot normalized sig is always "browser_snapshot||||"
    # but the exempt set should prevent noprogress from accumulating.
    nav_tools = _SNAPSHOT_TOOLS + [_FakeTool("browser_navigate", tags=["browser", "active"])]
    steps = []
    for i in range(5):
        steps.append({"action": "call_tool", "thought": "nav",
                      "tool_name": "browser_navigate",
                      "tool_args": {"url": f"https://app/page-{i}"}})
        steps.append(_snapshot_step())
    steps.append(_REPLY)

    reply, obs = await _drive(CopilotSession("s-snap"), _FakeCtx(), steps,
                              snapshot_tool, tools=nav_tools)

    warned = [o for o in obs if "[SYSTEM]" in o and "no progress" in o]
    assert len(warned) == 0, f"browser_snapshot should not trigger noprogress: {warned}"
    assert reply.blocked_reason == ""
    assert reply.message == "ok"


# ── 3. Browser cleanup on terminal blocked reasons ─────────────────────────

def _make_service():
    from dast.proxy.api.copilot_service import CopilotService

    mock_ctx = MagicMock()
    mock_ctx.store = MagicMock()
    mock_ctx.scopes = []
    return CopilotService(mock_ctx)


def _inject_session(service, sid: str = "test-sid") -> dict:
    """Inject a minimal session dict into the service, bypassing the real new_session
    which needs a full DashboardContext with engine init."""
    session = {
        "engine": MagicMock(),
        "status": "idle",
        "created_at": time.time(),
        "updated_at": time.time(),
        "trace": [],
        "pause": None,
        "last_reply": None,
        "origin": "operator",
        "escalation": None,
        "hypothesis": None,
        "profile_slug": None,
        "_downgrade_armed": False,
        "_profile_activated": False,
        "_pause_event": asyncio.Event(),
        "_pause_result": None,
        "approved_hosts": set(),
        "_task": None,
        "_agent_browser": None,
        "autonomous": None,
    }
    service._sessions[sid] = session
    return session


@pytest.mark.asyncio
async def test_cleanup_session_called_on_stuck_loop():
    """When a turn ends with blocked_reason='stuck_loop', the service should call
    _cleanup_session to close the browser."""
    service = _make_service()
    sid = "s-stuck"
    session = _inject_session(service, sid)

    mock_browser = MagicMock()
    mock_browser.close = AsyncMock()
    session["_agent_browser"] = mock_browser

    mock_reply = MagicMock()
    mock_reply.message = "Stopped: stuck"
    mock_reply.blocked_reason = "stuck_loop"
    mock_reply.transcript = []

    session["engine"].send = AsyncMock(return_value=mock_reply)

    with patch.object(service, "_cleanup_session", wraps=service._cleanup_session) as spy:
        await service._run_turn(sid, "test")

    spy.assert_called_once()


@pytest.mark.asyncio
async def test_no_cleanup_on_idle_finish():
    """When a turn ends normally (no blocked_reason), _cleanup_session is NOT called."""
    service = _make_service()
    sid = "s-ok"
    session = _inject_session(service, sid)

    mock_reply = MagicMock()
    mock_reply.message = "done"
    mock_reply.blocked_reason = ""
    mock_reply.transcript = []

    session["engine"].send = AsyncMock(return_value=mock_reply)

    with patch.object(service, "_cleanup_session") as spy:
        await service._run_turn(sid, "test")

    spy.assert_not_called()


# ── 4. Session browser reaper ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_session_reaper_closes_idle_browser():
    """The reaper should close browsers for sessions idle longer than the TTL."""
    service = _make_service()
    sid = "s-idle"
    session = _inject_session(service, sid)
    session["status"] = "idle"
    session["updated_at"] = time.time() - 700  # well past 600s TTL
    mock_browser = MagicMock()
    mock_browser.close = AsyncMock()
    session["_agent_browser"] = mock_browser

    with patch.object(service, "_cleanup_session", wraps=service._cleanup_session) as spy:
        now = time.time()
        for s_id, s in list(service._sessions.items()):
            status = s.get("status")
            updated = s.get("updated_at", 0)
            browser = s.get("_agent_browser")
            if (browser is not None
                    and status in ("idle", "blocked", "error")
                    and now - updated > service._SESSION_BROWSER_TTL_S):
                service._cleanup_session(s)

    spy.assert_called_once()
    assert session.get("_agent_browser") is None


@pytest.mark.asyncio
async def test_session_reaper_skips_running_sessions():
    """The reaper must NOT close browsers for sessions that are still running."""
    service = _make_service()
    sid = "s-running"
    session = _inject_session(service, sid)
    session["status"] = "running"
    session["updated_at"] = time.time() - 700
    mock_browser = MagicMock()
    mock_browser.close = AsyncMock()
    session["_agent_browser"] = mock_browser

    now = time.time()
    for s_id, s in list(service._sessions.items()):
        status = s.get("status")
        updated = s.get("updated_at", 0)
        browser = s.get("_agent_browser")
        if (browser is not None
                and status in ("idle", "blocked", "error")
                and now - updated > service._SESSION_BROWSER_TTL_S):
            service._cleanup_session(s)

    assert session.get("_agent_browser") is mock_browser  # untouched


# ── 5. DELETE /api/copilot/session/{sid} ────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_session_endpoint_removes_session():
    """DELETE /api/copilot/session/{sid} should close the browser and remove the session."""
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from dast.proxy.api.copilot_routes import make_router

    service = _make_service()
    sid = "s-del"
    session = _inject_session(service, sid)
    mock_browser = MagicMock()
    mock_browser.close = AsyncMock()
    session["_agent_browser"] = mock_browser

    mock_ctx = MagicMock()
    mock_ctx.copilot = service
    mock_ctx.store = MagicMock()

    app = FastAPI()
    router = make_router(mock_ctx)
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.delete(f"/api/copilot/session/{sid}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert sid not in service._sessions


@pytest.mark.asyncio
async def test_delete_session_endpoint_returns_404_for_unknown():
    """DELETE for an unknown session ID should return 404."""
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from dast.proxy.api.copilot_routes import make_router

    service = _make_service()

    mock_ctx = MagicMock()
    mock_ctx.copilot = service
    mock_ctx.store = MagicMock()

    app = FastAPI()
    router = make_router(mock_ctx)
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.delete("/api/copilot/session/nonexistent-id")

    assert resp.status_code == 404
