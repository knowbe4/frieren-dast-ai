"""Unit tests for the session-state routes (GET /api/session/state +
POST /api/session/reauth/reset) — the recovery surface for the re-auth breaker.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from dast.proxy.api.session_state_routes import make_router, reset_refresh_breaker
from dast.session.refresh_worker import SessionRefreshWorker, _MAX_REAUTH_FAILURES


def _worker() -> SessionRefreshWorker:
    return SessionRefreshWorker(
        auth_url="https://app.example.com/login",
        username="u", password="p",
        pool=object(), session_manager=object(),
    )


@dataclass
class _Ctx:
    runner: object = None


def _client(ctx: _Ctx) -> TestClient:
    app = FastAPI()
    app.include_router(make_router(ctx))
    return TestClient(app)


def test_state_inactive_without_runner():
    body = _client(_Ctx(runner=None)).get("/api/session/state").json()
    assert body["active"] is False
    assert "reason" in body


def test_state_inactive_when_runner_has_no_worker():
    # A runner that never wired the worker (no auth credentials at startup).
    body = _client(_Ctx(runner=SimpleNamespace())).get("/api/session/state").json()
    assert body["active"] is False


def test_state_reports_breaker_and_failures():
    w = _worker()
    w._register_failure("credentials rejected")
    ctx = _Ctx(runner=SimpleNamespace(refresh_worker=w))
    body = _client(ctx).get("/api/session/state").json()
    assert body["active"] is True
    assert body["consecutive_failures"] == 1
    assert body["gave_up"] is False
    assert body["last_failure_reason"] == "credentials rejected"
    assert body["auth_url"] == "https://app.example.com/login"


def test_reset_endpoint_recovers_a_tripped_breaker():
    w = _worker()
    for _ in range(_MAX_REAUTH_FAILURES):
        w._register_failure("fail")
    assert w._gave_up
    ctx = _Ctx(runner=SimpleNamespace(refresh_worker=w))
    body = _client(ctx).post("/api/session/reauth/reset").json()
    assert body["reset"] is True
    assert body["state"]["gave_up"] is False
    assert body["state"]["consecutive_failures"] == 0


def test_reset_returns_404_without_a_worker():
    r = _client(_Ctx(runner=SimpleNamespace())).post("/api/session/reauth/reset")
    assert r.status_code == 404
    assert reset_refresh_breaker(_Ctx(runner=None), "x") is False
