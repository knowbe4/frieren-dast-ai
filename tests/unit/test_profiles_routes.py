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
        "name": "Training", "host_pattern": "*.knowbe4.com",
        "auth_url": "https://training.knowbe4.com/login",
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
