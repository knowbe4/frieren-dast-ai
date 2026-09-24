"""
Regression test for the authenticated-scan auth handoff.

The context pool hands out browser contexts round-robin (a FIFO queue). An
earlier version captured the post-login ``storage_state`` from a *freshly
acquired* context instead of the one that actually logged in, so whenever
``parallel_workers > 1`` the auth cookies were read from an unauthenticated
context and never propagated. Every crawl/attack request then silently hit the
login page and no authenticated finding could ever be confirmed.

This test locks in the fix: the storage_state applied to the pool must be the
one belonging to the context AuthAgent logged into, regardless of pool size.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import dast.orchestrator as orchestrator_module
from dast.models import ScanConfig
from dast.orchestrator import ScanOrchestrator


class _FakeContext:
    """A stand-in browser context whose storage_state is unique per context."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._authenticated = False

    async def storage_state(self) -> dict:
        # Only an authenticated context carries the session cookie.
        cookies = [{"name": "PHPSESSID", "value": f"sess-{self.name}"}] if self._authenticated else []
        return {"cookies": cookies, "context": self.name}


class _FakePool:
    """Round-robin pool mirroring ContextPool's FIFO acquire semantics."""

    def __init__(self, size: int) -> None:
        self._all_contexts = [_FakeContext(f"ctx{i}") for i in range(size)]
        self._queue: list[_FakeContext] = list(self._all_contexts)
        self.applied_state: dict | None = None

    @asynccontextmanager
    async def acquire(self):
        ctx = self._queue.pop(0)
        try:
            yield ctx
        finally:
            self._queue.append(ctx)  # returned to the BACK, like the real queue

    async def apply_auth_state(self, storage_state: dict) -> None:
        self.applied_state = storage_state
        for ctx in self._all_contexts:
            ctx.applied = storage_state


class _FakeAuthAgent:
    """Logs in by marking exactly the context it was handed as authenticated."""

    def __init__(self, context, session_manager, auth_url, username, password) -> None:
        self._context = context

    async def login(self) -> bool:
        self._context._authenticated = True
        return True


class _FakeAudit:
    def auth_attempt(self, *args, **kwargs) -> None:
        pass


def _make_orchestrator(workers: int, monkeypatch) -> ScanOrchestrator:
    config = ScanConfig(
        target_url="http://target.test/",
        auth_url="http://target.test/login",
        username="admin",
        password="password",
        parallel_workers=workers,
    )
    orch = ScanOrchestrator(config)
    orch._pool = _FakePool(workers)
    monkeypatch.setattr(orchestrator_module, "AuthAgent", _FakeAuthAgent)
    return orch


def test_auth_state_captured_from_authenticated_context(monkeypatch):
    orch = _make_orchestrator(workers=4, monkeypatch=monkeypatch)

    ok = asyncio.run(orch._authenticate(_FakeAudit()))

    assert ok is True
    # The captured state must carry the session cookie — i.e. it came from the
    # context that logged in (ctx0), not a later unauthenticated one.
    assert orch._auth_state is not None
    assert orch._auth_state["cookies"] == [{"name": "PHPSESSID", "value": "sess-ctx0"}]
    assert orch._auth_state["context"] == "ctx0"


def test_applied_state_is_authenticated_for_multi_worker_pool(monkeypatch):
    orch = _make_orchestrator(workers=4, monkeypatch=monkeypatch)

    async def _drive() -> None:
        assert await orch._authenticate(_FakeAudit()) is True
        # Mirror run(): apply the captured auth state to the whole pool.
        assert orch._auth_state
        await orch._pool.apply_auth_state(orch._auth_state)

    asyncio.run(_drive())

    # Every context in the pool now carries the authenticated cookie.
    assert orch._pool.applied_state is not None
    assert orch._pool.applied_state["cookies"], "auth cookies must not be empty"
    for ctx in orch._pool._all_contexts:
        assert ctx.applied["cookies"] == [{"name": "PHPSESSID", "value": "sess-ctx0"}]


def test_single_worker_pool_still_authenticates(monkeypatch):
    orch = _make_orchestrator(workers=1, monkeypatch=monkeypatch)

    ok = asyncio.run(orch._authenticate(_FakeAudit()))

    assert ok is True
    assert orch._auth_state["cookies"] == [{"name": "PHPSESSID", "value": "sess-ctx0"}]
