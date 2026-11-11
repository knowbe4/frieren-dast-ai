"""Tests for the local app-knowledge store, its context-brief block, and the
get_app_token / record_app_knowledge tools."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest

import dast.app_knowledge.store as store
from dast.tools.app_knowledge_tools import _decode_jwt_account, _get_app_token, _record_app_knowledge


@pytest.fixture()
def kb_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "_KNOWLEDGE_DIR", tmp_path)
    return tmp_path


def test_store_round_trip_and_parent_resolve(kb_dir):
    assert store.load_for_host("app.example.com") == ""        # nothing yet
    assert store.append_note("app.example.com", "use user.attributes.alphaJwt") \
        == "app.example.com"
    note = store.load_for_host("app.example.com")
    assert "user.attributes.alphaJwt" in note
    # a subdomain resolves to the parent-domain note
    assert "user.attributes.alphaJwt" in store.load_for_host("api.app.example.com")


def test_context_brief_includes_app_knowledge(kb_dir):
    store.append_note("app.example.com", "betaJwt authenticates /beta/graphql")
    from dast.ai.copilot.context_brief import _app_knowledge_block
    block = _app_knowledge_block("app.example.com")
    assert "App knowledge" in block and "betaJwt" in block


@pytest.mark.asyncio
async def test_record_app_knowledge_tool(kb_dir):
    ctx = SimpleNamespace(is_in_scope=lambda u: True)
    r = await _record_app_knowledge(ctx, {"host": "app.example.com", "note": "x"})
    assert r["ok"] is True and r["host"] == "app.example.com"
    assert "x" in store.load_for_host("app.example.com")
    # out-of-scope is refused
    ctx2 = SimpleNamespace(is_in_scope=lambda u: False)
    assert (await _record_app_knowledge(ctx2, {"host": "h", "note": "x"}))["ok"] is False


def test_decode_jwt_account():
    payload = {"account": {"id": 625289, "ai_translations_active": True,
                           "can_download_modules": False}, "exp": 123}
    seg = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    claims = _decode_jwt_account(f"h.{seg}.sig")
    assert claims["account_id"] == 625289
    assert claims["entitlements"]["ai_translations_active"] is True
    assert claims["entitlements"]["can_download_modules"] is False


class _FakeResp:
    def __init__(self, payload=None, status=200):
        self._payload = payload
        self.status_code = status
    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, get_payload, post_status: int = 200):
        self._get_payload = get_payload
        self._post_status = post_status
        self.posted = []
        self.got = []
    async def __aenter__(self):
        return self
    async def __aexit__(self, *a):
        return False
    async def get(self, url, headers=None):
        self.got.append(url)
        return _FakeResp(self._get_payload)
    async def post(self, url, headers=None, content=None):
        self.posted.append((url, headers))
        return _FakeResp({}, status=self._post_status)


class _TokenStore:
    """Minimal store for scan_history_bearer: one /beta/graphql request carrying a Bearer."""
    def __init__(self, host, path, token):
        self._entries = [{"host": host, "path": path, "source": "proxy", "id": "e1",
                          "request_headers": {"Authorization": f"Bearer {token}"}}]
    def all_entries(self):
        return self._entries


@pytest.mark.asyncio
async def test_get_app_token_extracts_decodes_caches_without_leaking(monkeypatch):
    payload = {"account": {"id": 625289, "ai_translations_active": True,
                           "can_download_modules": False}, "exp": 999}
    seg = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    jwt = f"h.{seg}.sig"
    spa = {"user": {"attributes": {"alphaJwt": "x.y.z", "betaJwt": jwt}}}

    import dast.tools.app_knowledge_tools as akt
    monkeypatch.setattr(akt.httpx, "AsyncClient", lambda **kw: _FakeClient(spa))

    engine = SimpleNamespace(_bearer_tokens={}, _session_cookies={})
    ctx = SimpleNamespace(is_in_scope=lambda u: True, proxy_url="http://127.0.0.1:8080",
                          store=None, _session=engine)
    # "beta" is an app in the placeholder sub-app map seeded by the conftest fixture.
    r = await _get_app_token(ctx, {"host": "app.example.com", "app": "beta"})

    assert r["ok"] is True and r["app"] == "beta"
    assert r["account_id"] == 625289
    assert r["entitlements"]["ai_translations_active"] is True
    assert "token_preview" in r and jwt not in json.dumps(r)        # raw token never echoed
    assert engine._bearer_tokens["app.example.com"]["token"] == jwt  # cached for the engine


@pytest.mark.asyncio
async def test_get_app_token_prefers_captured_history_token(monkeypatch):
    # When the app's real token was already captured on the service path in proxy history,
    # prefer it over minting from /spa/session (the field token may be a non-working variant).
    payload = {"account": {"id": 1}, "exp": 9999999999}   # not expired (history freshness filter)
    seg = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    captured_jwt = f"h.{seg}.sig"

    import dast.tools.app_knowledge_tools as akt
    fake = _FakeClient({"user": {"attributes": {}}}, post_status=200)
    monkeypatch.setattr(akt.httpx, "AsyncClient", lambda **kw: fake)

    engine = SimpleNamespace(_bearer_tokens={}, _session_cookies={})
    store = _TokenStore("app.example.com", "/beta/graphql", captured_jwt)
    ctx = SimpleNamespace(is_in_scope=lambda u: True, proxy_url="http://127.0.0.1:8080",
                          store=store, _session=engine)
    r = await _get_app_token(ctx, {"host": "app.example.com", "app": "beta"})

    assert r["ok"] is True and r["source"] == "captured" and r["verified"] is True
    assert fake.got == []                                   # /spa/session NOT fetched
    assert engine._bearer_tokens["app.example.com"]["by_app"]["beta"]["token"] == captured_jwt


@pytest.mark.asyncio
async def test_get_app_token_does_not_cache_unverified_token(monkeypatch):
    # A /spa/session field token that fails the probe (403 "could not verify") must NOT be
    # cached — the engine must never attach a dead Bearer. The claims are still returned.
    payload = {"account": {"id": 2}, "exp": 999}
    seg = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    jwt = f"h.{seg}.sig"
    spa = {"user": {"attributes": {"betaJwt": jwt}}}

    import dast.tools.app_knowledge_tools as akt
    monkeypatch.setattr(akt.httpx, "AsyncClient", lambda **kw: _FakeClient(spa, post_status=403))

    engine = SimpleNamespace(_bearer_tokens={}, _session_cookies={})
    ctx = SimpleNamespace(is_in_scope=lambda u: True, proxy_url="http://127.0.0.1:8080",
                          store=None, _session=engine)
    r = await _get_app_token(ctx, {"host": "app.example.com", "app": "beta"})

    assert r["ok"] is True and r["source"] == "spa_session"
    assert r["verified"] is False and r["probe_status"] == 403
    assert "priming" in r["note"] or "navigation" in r["note"].lower() or "mints" in r["note"]
    assert engine._bearer_tokens == {}                      # dead token NOT cached
    assert r["account_id"] == 2                             # claims still surfaced


@pytest.mark.asyncio
async def test_get_app_token_rejects_out_of_scope_and_bad_app():
    ctx = SimpleNamespace(is_in_scope=lambda u: False, proxy_url="http://127.0.0.1:8080",
                          store=None, _session=None)
    assert (await _get_app_token(ctx, {"host": "h", "app": "beta"}))["ok"] is False  # out of scope
    ctx2 = SimpleNamespace(is_in_scope=lambda u: True, proxy_url="x", store=None, _session=None)
    assert (await _get_app_token(ctx2, {"host": "h", "app": "nope"}))["ok"] is False  # unknown app
