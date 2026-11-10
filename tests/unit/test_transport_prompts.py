"""Phase 2: the transport prompts no longer contradict each other and defer to the automatic
API->browser fallback + the learned capability hint, instead of hand-written "use X not Y"
guidance (session.py had "use send_request not browser_fetch — proxy interference"; the
autonomous playbook had "browser_fetch more reliable than send_request")."""

from __future__ import annotations


def test_copilot_system_prompt_reconciled():
    from dast.ai.copilot.session import _SYSTEM_COPILOT
    assert "proxy interference" not in _SYSTEM_COPILOT
    assert "automatically re-issues it via the browser" in _SYSTEM_COPILOT
    assert "Transport capability" in _SYSTEM_COPILOT


def test_autonomous_playbook_reconciled():
    from dast.proxy.api.copilot_service import _AUTONOMOUS_START
    assert "more reliable than" not in _AUTONOMOUS_START
    assert "automatically re-issues it via browser_fetch" in _AUTONOMOUS_START
    assert "Transport capability" in _AUTONOMOUS_START


def test_send_request_description_reconciled():
    from dast.tools.base import get_tool
    desc = get_tool("send_request").description
    assert "drive it with browser_fetch instead" not in desc
    assert "automatically re-issued via the browser session" in desc
