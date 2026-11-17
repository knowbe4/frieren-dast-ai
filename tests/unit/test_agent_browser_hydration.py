"""
AgentBrowser SPA-hydration wait: a heavy client-rendered SPA area can still be
fetching when the first hydration wait fires, so a single
short wait caught the pre-hydration shell. `_wait_for_hydration` now retries with
a bounded settle between tries and a longer budget. These tests drive the method
with a fake Playwright page (no real browser) to assert the retry + best-effort
behavior.
"""

from __future__ import annotations

import asyncio

from dast.browser.agent_browser import AgentBrowser


class _FakePage:
    def __init__(self, fail_times: int) -> None:
        self.calls = 0
        self._fail = fail_times
        self.settles = 0

    async def wait_for_function(self, js, arg=None, timeout=None):
        self.calls += 1
        if self.calls <= self._fail:
            raise TimeoutError("not hydrated yet")
        return True

    async def wait_for_load_state(self, state, timeout=None):
        self.settles += 1


def _browser() -> AgentBrowser:
    # _wait_for_hydration only touches the page argument, so skip __init__.
    return object.__new__(AgentBrowser)


def test_hydration_retries_until_content_mounts():
    page = _FakePage(fail_times=1)  # first wait times out, second succeeds
    ok = asyncio.run(_browser()._wait_for_hydration(page, timeout_ms=4000, attempts=2))
    assert ok is True
    assert page.calls == 2        # retried after the first timeout
    assert page.settles == 1      # settled once between the two attempts


def test_hydration_times_out_without_raising():
    page = _FakePage(fail_times=99)  # never hydrates
    ok = asyncio.run(_browser()._wait_for_hydration(page, timeout_ms=4000, attempts=2))
    assert ok is False
    assert page.calls == 2        # tried the full attempt budget, then gave up


def test_hydration_succeeds_first_try_no_settle():
    page = _FakePage(fail_times=0)
    ok = asyncio.run(_browser()._wait_for_hydration(page, timeout_ms=4000, attempts=2))
    assert ok is True
    assert page.calls == 1
    assert page.settles == 0      # no retry needed


# ── navigate(): commit-on-response + never hard-fail (PhishER redirect-chain entry) ──

class _Resp:
    def __init__(self, status: int) -> None:
        self.status = status


class _NavPage:
    """Fake Playwright page for AgentBrowser.navigate (no real browser)."""

    def __init__(self, raise_on_goto: bool = False, status: int = 200,
                 url: str = "https://app.example.com/current") -> None:
        self._raise = raise_on_goto
        self._status = status
        self.url = url
        self.goto_kwargs: dict | None = None

    async def goto(self, url, wait_until=None, timeout=None):
        self.goto_kwargs = {"wait_until": wait_until, "timeout": timeout}
        if self._raise:
            raise TimeoutError("goto stalled on a redirect hop")
        self.url = url
        return _Resp(self._status)

    async def wait_for_function(self, js, arg=None, timeout=None):
        return True                      # hydrates immediately

    async def wait_for_load_state(self, state, timeout=None):
        return None

    async def title(self):
        return "T"


def _browser_with_page(page) -> AgentBrowser:
    b = object.__new__(AgentBrowser)

    async def _ensure():
        return page

    b._ensure_page = _ensure            # instance attr shadows the method (no self passed)
    return b


def test_navigate_uses_commit_wait():
    page = _NavPage()
    res = asyncio.run(_browser_with_page(page).navigate("https://app.example.com/dash"))
    assert res["ok"] is True
    assert res["timed_out"] is False
    assert res["status"] == 200
    assert page.goto_kwargs["wait_until"] == "commit"   # not domcontentloaded/networkidle


def test_navigate_soft_result_when_goto_times_out():
    # A stalled redirect hop (PhishER goto_phisher) must NOT hard-fail: return the current
    # page so the agent can inspect captured traffic instead of looping on an error.
    page = _NavPage(raise_on_goto=True, url="https://app.example.com/partial")
    res = asyncio.run(_browser_with_page(page).navigate("https://app.example.com/dash"))
    assert res["ok"] is True
    assert res["timed_out"] is True
    assert res["status"] is None
    assert res["url"] == "https://app.example.com/partial"
    assert "note" in res


# ── JS dialog capture: an XSS alert() must be accepted (never block) + recorded ──

class _DialogPage:
    """Fake Playwright page that records the dialog handler AgentBrowser registers."""

    def __init__(self) -> None:
        self.handlers: dict = {}

    def on(self, event, handler):
        self.handlers[event] = handler


class _FakeDialog:
    def __init__(self, dtype: str, message: str) -> None:
        self.type = dtype
        self.message = message
        self.accepted = False

    async def accept(self):
        self.accepted = True


def test_dialog_handler_captures_and_accepts():
    async def run():
        b = object.__new__(AgentBrowser)
        b._last_dialog = None
        b._dialog_count = 0
        page = _DialogPage()
        b._register_dialog_handler(page)
        assert "dialog" in page.handlers            # handler registered on the page

        dlg = _FakeDialog("alert", "xss-pwned")
        page.handlers["dialog"](dlg)                # Playwright calls the sync callback
        await asyncio.sleep(0)                       # let the scheduled accept() task run

        assert b.last_dialog == {"type": "alert", "message": "xss-pwned"}
        assert b._dialog_count == 1
        assert dlg.accepted is True                  # accepted, not left blocking

        # pop clears it so the next navigation starts clean
        assert b.pop_last_dialog() == {"type": "alert", "message": "xss-pwned"}
        assert b.last_dialog is None

    asyncio.run(run())


def test_dialog_count_increments_across_dialogs():
    async def run():
        b = object.__new__(AgentBrowser)
        b._last_dialog = None
        b._dialog_count = 0
        page = _DialogPage()
        b._register_dialog_handler(page)
        page.handlers["dialog"](_FakeDialog("alert", "1"))
        page.handlers["dialog"](_FakeDialog("confirm", "2"))
        await asyncio.sleep(0)
        assert b._dialog_count == 2
        assert b.last_dialog == {"type": "confirm", "message": "2"}

    asyncio.run(run())


def test_navigate_surfaces_fired_dialog():
    page = _NavPage()
    b = _browser_with_page(page)
    b._last_dialog = {"type": "alert", "message": "1"}   # a dialog fired during the load
    b._dialog_count = 1
    res = asyncio.run(b.navigate("https://app.example.com/x"))
    assert res["dialog"] == {"type": "alert", "message": "1"}
    assert "script executed" in res["note"]
    assert b.last_dialog is None                          # popped out of the browser state
