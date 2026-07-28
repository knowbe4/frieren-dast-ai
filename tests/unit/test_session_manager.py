"""
Unit tests for dast.session.manager.SessionManager — checkpoint/rollback and
health-check logic. No real Playwright browser is used: BrowserContext/Page
are replaced with minimal AsyncMock-based fakes.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from dast.session.manager import SessionManager


def _make_context(storage_state=None):
    context = MagicMock()
    context.storage_state = AsyncMock(return_value=storage_state or {"cookies": [{"name": "session", "value": "abc"}]})
    context.clear_cookies = AsyncMock()
    context.add_cookies = AsyncMock()
    return context


def _make_page(goto_result="default", final_url="https://example.com/dashboard"):
    page = MagicMock()
    page.url = final_url
    page.close = AsyncMock()
    if goto_result == "default":
        resp = MagicMock()
        resp.status = 200
        page.goto = AsyncMock(return_value=resp)
    elif goto_result == "none":
        page.goto = AsyncMock(return_value=None)
    elif goto_result == "raises":
        page.goto = AsyncMock(side_effect=RuntimeError("navigation failed"))
    else:
        page.goto = AsyncMock(return_value=goto_result)
    return page


def _context_with_page(page):
    context = _make_context()
    context.new_page = AsyncMock(return_value=page)
    return context


# ── save_checkpoint / has_checkpoint ────────────────────────────────────────

@pytest.mark.asyncio
async def test_has_checkpoint_false_before_any_save():
    manager = SessionManager()
    assert manager.has_checkpoint is False


@pytest.mark.asyncio
async def test_save_checkpoint_captures_storage_state_and_resets_rollback_count():
    manager = SessionManager()
    manager._rollback_count = 2
    context = _make_context(storage_state={"cookies": [{"name": "a", "value": "1"}]})

    await manager.save_checkpoint(context, health_url="https://example.com/health")

    assert manager.has_checkpoint is True
    assert manager._checkpoint.storage_state == {"cookies": [{"name": "a", "value": "1"}]}
    assert manager._checkpoint.health_url == "https://example.com/health"
    assert manager._rollback_count == 0
    context.storage_state.assert_awaited_once()


# ── rollback ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rollback_with_no_checkpoint_returns_false():
    manager = SessionManager()
    context = _make_context()

    result = await manager.rollback(context)

    assert result is False
    context.clear_cookies.assert_not_awaited()


@pytest.mark.asyncio
async def test_rollback_succeeds_restores_cookies():
    manager = SessionManager()
    context = _make_context(storage_state={"cookies": [{"name": "session", "value": "abc"}]})
    await manager.save_checkpoint(context)

    result = await manager.rollback(context)

    assert result is True
    context.clear_cookies.assert_awaited_once()
    context.add_cookies.assert_awaited_once_with([{"name": "session", "value": "abc"}])
    assert manager._rollback_count == 1


@pytest.mark.asyncio
async def test_rollback_exceeding_max_attempts_returns_false_without_touching_context():
    manager = SessionManager()
    context = _make_context()
    await manager.save_checkpoint(context)

    # Exhaust the 3 allowed attempts.
    for _ in range(SessionManager._MAX_ROLLBACK_ATTEMPTS):
        assert await manager.rollback(context) is True

    context.clear_cookies.reset_mock()
    context.add_cookies.reset_mock()

    result = await manager.rollback(context)

    assert result is False
    context.clear_cookies.assert_not_awaited()
    context.add_cookies.assert_not_awaited()


# ── is_healthy ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_is_healthy_true_when_no_health_url_configured():
    manager = SessionManager(health_url=None)
    context = _make_context()
    context.new_page = AsyncMock()

    result = await manager.is_healthy(context)

    assert result is True
    context.new_page.assert_not_called()


@pytest.mark.asyncio
async def test_is_healthy_false_when_redirected_to_login():
    manager = SessionManager(health_url="https://example.com/health")
    page = _make_page(final_url="https://example.com/login?next=/health")
    context = _context_with_page(page)

    result = await manager.is_healthy(context)

    assert result is False
    page.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_is_healthy_false_when_goto_returns_none():
    manager = SessionManager(health_url="https://example.com/health")
    page = _make_page(goto_result="none")
    context = _context_with_page(page)

    result = await manager.is_healthy(context)

    assert result is False
    page.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_is_healthy_true_when_status_below_400():
    manager = SessionManager(health_url="https://example.com/health")
    page = _make_page(goto_result="default")
    context = _context_with_page(page)

    result = await manager.is_healthy(context)

    assert result is True
    page.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_is_healthy_false_when_status_is_400_or_above():
    manager = SessionManager(health_url="https://example.com/health")
    resp = MagicMock()
    resp.status = 500
    page = _make_page(goto_result=resp)
    context = _context_with_page(page)

    result = await manager.is_healthy(context)

    assert result is False
    page.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_is_healthy_false_on_navigation_exception_and_still_closes_page():
    manager = SessionManager(health_url="https://example.com/health")
    page = _make_page(goto_result="raises")
    context = _context_with_page(page)

    result = await manager.is_healthy(context)

    assert result is False
    page.close.assert_awaited_once()
