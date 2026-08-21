"""
Unit tests for the proxy bind-host settings route.

Locks in: the Setup tab can read and change the interface the proxy listens on
(Burp-style), the change is validated + persisted, applied live via the runner,
and non-loopback binds are flagged so the UI can warn about the open-proxy risk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient

from dast.proxy.api.settings_routes import make_router, _normalize_bind_host


class _FakeSettings:
    def __init__(self) -> None:
        self._bind_host = "127.0.0.1"
        self._bind_port = 0

    def get_bind_host(self) -> str:
        return self._bind_host

    def set_bind_host(self, host: str) -> None:
        self._bind_host = host or "127.0.0.1"

    def get_bind_port(self) -> int:
        return self._bind_port

    def set_bind_port(self, port: int) -> None:
        self._bind_port = int(port or 0)


class _FakeRunner:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[str] = []

    async def restart_proxy_listener(self, host: str, port=None) -> dict:
        self.calls.append((host, port))
        if self.fail:
            return {"ok": False, "error": "cannot assign requested address",
                    "host": "127.0.0.1", "port": 8080}
        return {"ok": True, "host": host, "port": port or 8080}


@dataclass
class _Ctx:
    settings: Optional[_FakeSettings] = None
    runner: Optional[_FakeRunner] = None
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    status_cache: dict = field(default_factory=dict)
    status_cache_ts: list = field(default_factory=lambda: [0.0])
    _scan_cfg: dict = field(default_factory=dict)


def _client(ctx: _Ctx) -> TestClient:
    app = FastAPI()
    app.include_router(make_router(ctx))
    return TestClient(app)


def test_normalize_accepts_ips_and_localhost():
    assert _normalize_bind_host("127.0.0.1") == ("127.0.0.1", None, True)
    assert _normalize_bind_host("localhost") == ("127.0.0.1", None, True)
    assert _normalize_bind_host("192.168.0.1")[2] is False
    assert _normalize_bind_host("0.0.0.0")[2] is False
    assert _normalize_bind_host("nope")[0] is None
    assert _normalize_bind_host("")[0] is None


def test_get_bind_host_returns_current():
    ctx = _Ctx(settings=_FakeSettings(), proxy_port=8080)
    body = _client(ctx).get("/api/settings/bind-host").json()
    assert body == {"host": "127.0.0.1", "port": 8080, "is_loopback": True}


def test_set_bind_host_applies_live_and_persists():
    settings, runner = _FakeSettings(), _FakeRunner()
    ctx = _Ctx(settings=settings, runner=runner)
    res = _client(ctx).post("/api/settings/bind-host", json={"host": "192.168.0.1"}).json()
    assert res["ok"] is True and res["applied"] is True
    assert res["host"] == "192.168.0.1" and res["is_loopback"] is False
    assert settings.get_bind_host() == "192.168.0.1"       # persisted
    assert runner.calls == [("192.168.0.1", None)]         # applied live
    assert ctx.proxy_host == "192.168.0.1"                 # ctx updated


def test_set_bind_host_with_port_rebinds_and_persists():
    settings, runner = _FakeSettings(), _FakeRunner()
    ctx = _Ctx(settings=settings, runner=runner)
    res = _client(ctx).post("/api/settings/bind-host",
                            json={"host": "127.0.0.1", "port": 9091}).json()
    assert res["ok"] is True and res["port"] == 9091
    assert runner.calls == [("127.0.0.1", 9091)]
    assert settings.get_bind_port() == 9091
    assert ctx.proxy_port == 9091


def test_set_bind_host_rejects_out_of_range_port():
    ctx = _Ctx(settings=_FakeSettings(), runner=_FakeRunner())
    r = _client(ctx).post("/api/settings/bind-host",
                          json={"host": "127.0.0.1", "port": 70000})
    assert r.status_code == 400


def test_set_bind_host_invalid_is_400_and_not_persisted():
    settings = _FakeSettings()
    ctx = _Ctx(settings=settings, runner=_FakeRunner())
    r = _client(ctx).post("/api/settings/bind-host", json={"host": "garbage"})
    assert r.status_code == 400
    assert settings.get_bind_host() == "127.0.0.1"


def test_set_bind_host_without_runner_saves_for_restart():
    settings = _FakeSettings()
    ctx = _Ctx(settings=settings, runner=None)
    res = _client(ctx).post("/api/settings/bind-host", json={"host": "0.0.0.0"}).json()
    assert res["ok"] is True and res["applied"] is False
    assert settings.get_bind_host() == "0.0.0.0"


def test_set_bind_host_rebind_failure_reports_error():
    ctx = _Ctx(settings=_FakeSettings(), runner=_FakeRunner(fail=True))
    res = _client(ctx).post("/api/settings/bind-host", json={"host": "10.0.0.99"}).json()
    assert res["ok"] is False and res["applied"] is False
    assert "error" in res
