"""Unit tests for the login-profile API routes (Discovery > Logins backend)."""

from __future__ import annotations

import importlib
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    # Reload so the profiles store writes under the temp HOME.
    from dast.profiles import crypto as crypto_mod
    importlib.reload(crypto_mod)
    from dast.profiles import models as models_mod
    importlib.reload(models_mod)
    from dast.profiles import store as store_mod
    importlib.reload(store_mod)
    from dast.proxy.api import profiles_routes
    importlib.reload(profiles_routes)

    from dast.proxy.session_store import SessionStore

    class _Ctx:
        store = SessionStore()

    app = FastAPI()
    app.include_router(profiles_routes.make_router(_Ctx()))
    tc = TestClient(app)
    tc.ctx = _Ctx.store  # type: ignore[attr-defined]
    return tc


def test_create_list_get_delete(client):
    r = client.post("/api/profiles", json={
        "name": "Training", "host_pattern": "*.example.com",
        "auth_url": "https://app.example.com/login",
        "credentials": [{"label": "admin", "username": "a@b.com", "secret": "pw"}],
    })
    assert r.status_code == 200
    assert r.json()["slug"] == "training"
    assert r.json()["credentials"][0]["secret_set"] is True

    lst = client.get("/api/profiles").json()
    assert any(p["slug"] == "training" for p in lst["profiles"])

    got = client.get("/api/profiles/training").json()
    assert "pw" not in json.dumps(got)  # secret never leaves the server

    assert client.delete("/api/profiles/training").json()["deleted"] is True
    assert client.get("/api/profiles/training").status_code == 404


def test_update_preserves_secret_when_omitted(client):
    client.post("/api/profiles", json={
        "name": "P", "credentials": [{"label": "admin", "username": "a", "secret": "keep"}],
    })
    # Update without a secret field -> secret preserved.
    client.post("/api/profiles", json={
        "slug": "p", "name": "P renamed",
        "credentials": [{"label": "admin", "username": "a2"}],
    })
    from dast.profiles.store import load_profile
    p = load_profile("p")
    assert p.name == "P renamed"
    assert p.credentials[0].username == "a2"
    assert p.credentials[0].secret == "keep"


def test_name_required(client):
    assert client.post("/api/profiles", json={"name": "  "}).status_code == 400


def test_totp_seed_and_test_account(client):
    r = client.post("/api/profiles", json={
        "name": "T", "test_account": True,
        "credentials": [{"label": "default", "username": "qa@test.example",
                         "secret": "pw", "totp_secret": "JBSWY3DPEHPK3PXP"}],
    })
    assert r.status_code == 200
    body = r.json()
    assert body["test_account"] is True
    assert body["credentials"][0]["totp_set"] is True

    # The seed never leaves the server.
    got = client.get("/api/profiles/t").json()
    assert "JBSWY3DPEHPK3PXP" not in json.dumps(got)

    # Update omitting totp_secret preserves the stored seed.
    client.post("/api/profiles", json={
        "slug": "t", "name": "T", "test_account": True,
        "credentials": [{"label": "default", "username": "qa@test.example"}],
    })
    from dast.profiles.store import load_profile
    p = load_profile("t")
    assert p.credentials[0].totp_secret == "JBSWY3DPEHPK3PXP"
    assert p.test_account is True


def test_invalid_totp_seed_rejected(client):
    r = client.post("/api/profiles", json={
        "name": "Bad", "test_account": True,
        "credentials": [{"label": "default", "username": "x", "totp_secret": "not base32!!!"}],
    })
    assert r.status_code == 400


def test_session_import_then_activate(client):
    client.post("/api/profiles", json={"name": "S", "host_pattern": "app.example.com"})
    r = client.post("/api/profiles/s/session-import", json={
        "target_url": "https://app.example.com/", "cookie_header": "sid=abc; t=1",
    })
    assert r.status_code == 200
    assert r.json()["session_set"] is True

    act = client.post("/api/profiles/s/activate")
    assert act.status_code == 200
    assert act.json()["activated"] is True
    assert act.json()["cookies_imported"] == 2

    # Cookies must now be in the live store jar.
    cookies = client.ctx.get_cookies_for_host("app.example.com")  # type: ignore[attr-defined]
    assert {c["name"] for c in cookies} >= {"sid", "t"}


def test_import_empty_rejected(client):
    client.post("/api/profiles", json={"name": "E"})
    r = client.post("/api/profiles/e/session-import", json={})
    assert r.status_code == 400


def test_activate_without_session_rejected(client):
    client.post("/api/profiles", json={"name": "N"})
    assert client.post("/api/profiles/n/activate").status_code == 400


def test_capture_from_proxy_prefers_fresh_history_over_stale_jar(client):
    """After an SSO login the authenticated cookies ride the newest proxy request,
    but the in-memory jar may still hold the pre-auth value. Capture must save the
    FRESH cookie that actually transited the proxy, not the stale jar one."""
    from dast.proxy.session_store import ProxyEntry
    from dast.profiles.store import load_profile

    client.post("/api/profiles", json={"name": "Cap", "host_pattern": "app.example.com"})
    store = client.ctx
    # stale pre-auth cookie sitting in the jar
    store._ingest_cookies("app.example.com", {"set-cookie": "sid=STALE; Path=/"})
    # the newest authenticated request that actually transited the proxy
    store.add_synthetic_entry(ProxyEntry(
        id="e1", method="GET", url="https://app.example.com/dashboard",
        host="app.example.com", path="/dashboard",
        request_headers={"Cookie": "sid=FRESH; extra=1"}, request_body=None))

    r = client.post("/api/profiles/cap/capture-from-proxy", json={"host": "app.example.com"})
    assert r.status_code == 200
    assert r.json()["captured"]["cookies"] == 2

    p = load_profile("cap")
    cookies = {c["name"]: c["value"] for c in p.saved_session["cookies"]}
    assert cookies["sid"] == "FRESH"   # not the stale jar value
    assert cookies["extra"] == "1"


def test_capture_from_proxy_falls_back_to_jar(client):
    """With no matching history entry, capture still uses the jar (legacy path)."""
    from dast.profiles.store import load_profile

    client.post("/api/profiles", json={"name": "Jar", "host_pattern": "app.example.com"})
    client.ctx._ingest_cookies("app.example.com", {"set-cookie": "sid=jarval; Path=/"})

    r = client.post("/api/profiles/jar/capture-from-proxy", json={"host": "app.example.com"})
    assert r.status_code == 200
    p = load_profile("jar")
    assert {c["name"]: c["value"] for c in p.saved_session["cookies"]} == {"sid": "jarval"}


def test_capture_from_proxy_404_when_nothing_seen(client):
    client.post("/api/profiles", json={"name": "Empty", "host_pattern": "app.example.com"})
    r = client.post("/api/profiles/empty/capture-from-proxy", json={"host": "app.example.com"})
    assert r.status_code == 404
