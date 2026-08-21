"""Unit tests for the login-profiles package (crypto, model, store, import)."""

from __future__ import annotations

import importlib
import json

import pytest


@pytest.fixture()
def profiles_env(tmp_path, monkeypatch):
    """Point the profiles package at a temp home so tests never touch ~/.dast-ai."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # Reload modules so module-level path constants pick up the patched HOME.
    from dast.profiles import crypto as crypto_mod
    importlib.reload(crypto_mod)
    from dast.profiles import models as models_mod
    importlib.reload(models_mod)
    from dast.profiles import store as store_mod
    importlib.reload(store_mod)
    from dast.profiles import session_import as import_mod
    importlib.reload(import_mod)
    return crypto_mod, models_mod, store_mod, import_mod


def test_crypto_round_trip_and_key_perms(profiles_env, tmp_path):
    crypto_mod, _, _, _ = profiles_env
    token = crypto_mod.encrypt("hunter2")
    assert token != "hunter2"
    assert crypto_mod.decrypt(token) == "hunter2"
    key_path = tmp_path / ".dast-ai" / "profiles" / ".key"
    assert key_path.exists()
    assert oct(key_path.stat().st_mode)[-3:] == "600"


def test_decrypt_tampered_returns_empty(profiles_env):
    crypto_mod, _, _, _ = profiles_env
    assert crypto_mod.decrypt("not-a-valid-token") == ""


def test_save_load_encrypts_secret_on_disk(profiles_env, tmp_path):
    _, models_mod, store_mod, _ = profiles_env
    profile = models_mod.LoginProfile(
        name="Training App",
        host_pattern="*.knowbe4.com",
        auth_url="https://training.knowbe4.com/login",
        credentials=[
            models_mod.Credential(label="admin", username="a@b.com", secret="s3cr3t"),
            models_mod.Credential(label="user", username="u@b.com", secret="p4ss"),
        ],
    )
    store_mod.save_profile(profile)

    # Raw file must not contain the plaintext secret.
    raw = (tmp_path / ".dast-ai" / "profiles" / "training-app.json").read_text()
    assert "s3cr3t" not in raw and "p4ss" not in raw
    assert json.loads(raw)["credentials"][0]["secret_enc"]

    loaded = store_mod.load_profile("training-app")
    assert loaded is not None
    assert loaded.credentials[0].secret == "s3cr3t"
    assert loaded.credentials[1].secret == "p4ss"


def test_public_dict_hides_secrets(profiles_env):
    _, models_mod, _, _ = profiles_env
    profile = models_mod.LoginProfile(
        name="X", credentials=[models_mod.Credential(secret="top")]
    )
    pub = profile.to_public_dict()
    assert "top" not in json.dumps(pub)
    assert pub["credentials"][0]["secret_set"] is True
    assert pub["session_set"] is False


def test_host_matching(profiles_env):
    _, models_mod, _, _ = profiles_env
    wild = models_mod.LoginProfile(name="w", host_pattern="*.example.com")
    assert wild.matches_host("api.example.com")
    assert wild.matches_host("example.com")
    assert not wild.matches_host("evil.com")

    exact = models_mod.LoginProfile(name="e", host_pattern="app.test.com")
    assert exact.matches_host("app.test.com")
    assert not exact.matches_host("other.test.com")


def test_resolve_for_host_prefers_most_specific(profiles_env):
    _, _, store_mod, _ = profiles_env
    from dast.profiles.models import LoginProfile
    store_mod.save_profile(LoginProfile(name="broad", host_pattern="example.com"))
    store_mod.save_profile(LoginProfile(name="narrow", host_pattern="*.stg.example.com"))
    resolved = store_mod.resolve_for_host("https://uk1.stg.example.com/x")
    assert resolved is not None
    assert resolved.name == "narrow"


def test_delete_profile(profiles_env):
    _, models_mod, store_mod, _ = profiles_env
    store_mod.save_profile(models_mod.LoginProfile(name="temp"))
    assert store_mod.load_profile("temp") is not None
    assert store_mod.delete_profile("temp") is True
    assert store_mod.load_profile("temp") is None
    assert store_mod.delete_profile("temp") is False


def test_session_import_cookie_header(profiles_env):
    _, _, _, import_mod = profiles_env
    imported = import_mod.build_session(
        target_url="https://app.example.com/", cookie_header="sid=abc; csrf=xyz"
    )
    assert not imported.is_empty
    names = {c["name"] for c in imported.cookies}
    assert names == {"sid", "csrf"}
    assert all(c["domain"] == "app.example.com" for c in imported.cookies)


def test_session_import_storage_state(profiles_env):
    _, _, _, import_mod = profiles_env
    ss = json.dumps({"cookies": [{"name": "s", "value": "1", "domain": "x.com", "path": "/"}], "origins": []})
    imported = import_mod.build_session(storage_state_json=ss)
    assert len(imported.cookies) == 1
    assert imported.storage_state["cookies"][0]["name"] == "s"


def test_session_import_auth_token_normalized(profiles_env):
    _, _, _, import_mod = profiles_env
    imported = import_mod.build_session(auth_token="eyJhbGci")
    assert imported.auth_headers["Authorization"] == "Bearer eyJhbGci"
    imported2 = import_mod.build_session(auth_token="Bearer eyJhbGci")
    assert imported2.auth_headers["Authorization"] == "Bearer eyJhbGci"


def test_session_import_empty(profiles_env):
    _, _, _, import_mod = profiles_env
    assert import_mod.build_session().is_empty
