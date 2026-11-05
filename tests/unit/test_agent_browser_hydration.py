"""
AgentBrowser SPA-hydration wait: a heavy client-rendered app (modstore3 / CCM
studio) can still be fetching when the first hydration wait fires, so a single
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
