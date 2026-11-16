"""Intra-turn session keep-alive: ping focus host DURING a turn so short-lived
sessions (e.g. console's 5-min sliding window) survive the AI thinking phase."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from dast.proxy.api.copilot_service import CopilotService


def _make_service() -> CopilotService:
    ctx = SimpleNamespace(
        store=None, settings=None, proxy_port=8080,
        dashboard_port=8088, broadcast_copilot=AsyncMock(),
    )
    return CopilotService(ctx)


def _mock_browser(hosts=None):
    page = AsyncMock()
    page.request = AsyncMock()
    page.request.fetch = AsyncMock(return_value=AsyncMock(status=200))
    browser = AsyncMock()
    browser._ensure_page = AsyncMock(return_value=page)
    return browser, page


@pytest.mark.asyncio
async def test_keepalive_pings_after_interval():
    """The keepalive fires page.request.fetch after the interval."""
    svc = _make_service()
    browser, page = _mock_browser()
    session = {
        "_agent_browser": browser,
        "autonomous": {"hosts": ["console.target.test"]},
        "engine": None,
    }
    svc._sessions["test-ka"] = session

    with patch.object(svc, "refresh_session", return_value={"cookies_refreshed": 0}):
        task = asyncio.create_task(
            svc._intra_turn_keepalive("test-ka", session, interval=0.05)
        )
        await asyncio.sleep(0.15)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert page.request.fetch.call_count >= 2
    call_args = page.request.fetch.call_args_list[0]
    assert call_args[0][0] == "https://console.target.test/"
    assert call_args[1]["method"] == "GET"


@pytest.mark.asyncio
async def test_keepalive_noop_no_browser():
    """No browser → coroutine returns immediately without pinging."""
    svc = _make_service()
    session = {"_agent_browser": None, "autonomous": {"hosts": ["h.test"]}}
    svc._sessions["test-nb"] = session

    task = asyncio.create_task(
        svc._intra_turn_keepalive("test-nb", session, interval=0.01)
    )
    await asyncio.sleep(0.05)
    assert task.done()


@pytest.mark.asyncio
async def test_keepalive_noop_no_hosts():
    """No hosts → coroutine returns immediately."""
    svc = _make_service()
    browser, _ = _mock_browser()
    engine = SimpleNamespace(_focus_hosts=[])
    session = {"_agent_browser": browser, "autonomous": None, "engine": engine}
    svc._sessions["test-nh"] = session

    task = asyncio.create_task(
        svc._intra_turn_keepalive("test-nh", session, interval=0.01)
    )
    await asyncio.sleep(0.05)
    assert task.done()


@pytest.mark.asyncio
async def test_keepalive_uses_engine_focus_hosts():
    """Interactive path: reads hosts from engine._focus_hosts when no autonomous config."""
    svc = _make_service()
    browser, page = _mock_browser()
    engine = SimpleNamespace(_focus_hosts=["interactive.target.test"])
    session = {"_agent_browser": browser, "autonomous": None, "engine": engine}
    svc._sessions["test-ih"] = session

    with patch.object(svc, "refresh_session", return_value={"cookies_refreshed": 0}):
        task = asyncio.create_task(
            svc._intra_turn_keepalive("test-ih", session, interval=0.05)
        )
        await asyncio.sleep(0.08)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert page.request.fetch.call_count >= 1
    assert page.request.fetch.call_args[0][0] == "https://interactive.target.test/"


@pytest.mark.asyncio
async def test_keepalive_survives_fetch_error():
    """A fetch failure does NOT kill the loop — it continues pinging."""
    svc = _make_service()
    browser, page = _mock_browser()
    page.request.fetch = AsyncMock(side_effect=Exception("network error"))
    session = {
        "_agent_browser": browser,
        "autonomous": {"hosts": ["err.target.test"]},
        "engine": None,
    }
    svc._sessions["test-err"] = session

    with patch.object(svc, "refresh_session", return_value={"cookies_refreshed": 0}):
        task = asyncio.create_task(
            svc._intra_turn_keepalive("test-err", session, interval=0.03)
        )
        await asyncio.sleep(0.12)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert page.request.fetch.call_count >= 3


@pytest.mark.asyncio
async def test_keepalive_calls_refresh_session():
    """After each ping, refresh_session is called to propagate cookies to the engine."""
    svc = _make_service()
    browser, _ = _mock_browser()
    session = {
        "_agent_browser": browser,
        "autonomous": {"hosts": ["refresh.target.test"]},
        "engine": None,
    }
    svc._sessions["test-rs"] = session

    with patch.object(svc, "refresh_session",
                      return_value={"cookies_refreshed": 2}) as mock_refresh:
        task = asyncio.create_task(
            svc._intra_turn_keepalive("test-rs", session, interval=0.05)
        )
        await asyncio.sleep(0.08)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert mock_refresh.call_count >= 1
    mock_refresh.assert_called_with("test-rs")
