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
    assert store.load_for_host("training.knowbe4.com") == ""        # nothing yet
    assert store.append_note("training.knowbe4.com", "use user.attributes.modstoreJwt") \
        == "training.knowbe4.com"
    note = store.load_for_host("training.knowbe4.com")
    assert "user.attributes.modstoreJwt" in note
    # a subdomain resolves to the parent-domain note
    assert "user.attributes.modstoreJwt" in store.load_for_host("api.training.knowbe4.com")


def test_context_brief_includes_app_knowledge(kb_dir):
    store.append_note("training.knowbe4.com", "ccmJwt authenticates /customercontent/graphql")
    from dast.ai.copilot.context_brief import _app_knowledge_block
    block = _app_knowledge_block("training.knowbe4.com")
    assert "App knowledge" in block and "ccmJwt" in block


@pytest.mark.asyncio
async def test_record_app_knowledge_tool(kb_dir):
    ctx = SimpleNamespace(is_in_scope=lambda u: True)
    r = await _record_app_knowledge(ctx, {"host": "training.knowbe4.com", "note": "x"})
    assert r["ok"] is True and r["host"] == "training.knowbe4.com"
    assert "x" in store.load_for_host("training.knowbe4.com")
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
    def __init__(self, get_payload):
        self._get_payload = get_payload
        self.posted = []
    async def __aenter__(self):
        return self
    async def __aexit__(self, *a):
        return False
    async def get(self, url, headers=None):
        return _FakeResp(self._get_payload)
    async def post(self, url, headers=None, content=None):
        self.posted.append((url, headers))
        return _FakeResp({}, status=200)


@pytest.mark.asyncio
async def test_get_app_token_extracts_decodes_caches_without_leaking(monkeypatch):
    payload = {"account": {"id": 625289, "ai_translations_active": True,
                           "can_download_modules": False}, "exp": 999}
    seg = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    jwt = f"h.{seg}.sig"
    spa = {"user": {"attributes": {"modstoreJwt": "x.y.z", "ccmJwt": jwt}}}

    import dast.tools.app_knowledge_tools as akt
    monkeypatch.setattr(akt.httpx, "AsyncClient", lambda **kw: _FakeClient(spa))

    engine = SimpleNamespace(_bearer_tokens={}, _session_cookies={})
    ctx = SimpleNamespace(is_in_scope=lambda u: True, proxy_url="http://127.0.0.1:8080",
                          store=None, _session=engine)
    r = await _get_app_token(ctx, {"host": "training.knowbe4.com", "app": "ccm"})

    assert r["ok"] is True and r["app"] == "ccm"
    assert r["account_id"] == 625289
    assert r["entitlements"]["ai_translations_active"] is True
    assert "token_preview" in r and jwt not in json.dumps(r)        # raw token never echoed
    assert engine._bearer_tokens["training.knowbe4.com"]["token"] == jwt  # cached for the engine


@pytest.mark.asyncio
async def test_get_app_token_rejects_out_of_scope_and_bad_app():
    ctx = SimpleNamespace(is_in_scope=lambda u: False, proxy_url="http://127.0.0.1:8080",
                          store=None, _session=None)
    assert (await _get_app_token(ctx, {"host": "h", "app": "ccm"}))["ok"] is False
    ctx2 = SimpleNamespace(is_in_scope=lambda u: True, proxy_url="x", store=None, _session=None)
    assert (await _get_app_token(ctx2, {"host": "h", "app": "nope"}))["ok"] is False
