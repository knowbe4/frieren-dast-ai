"""authz_differential_probe — deterministic same-owner authorization differential.

Fires the SAME operation against the caller's own resource (control) and another
tenant's resource (target), then classifies on the pair. These tests drive each
branch of the verdict matrix plus the scope / read-only / recording guards."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from dast.tools.authz_diff_tools import _authz_differential_probe

CONTROL = "https://settings-api.target.test/api/sync/adi/own/rotate"
TARGET = "https://settings-api.target.test/api/sync/adi/other/rotate"
READBACK = "https://settings-api.target.test/api/sync/adi/other"


class _Resp:
    def __init__(self, status: int, text: str = ""):
        self.status_code = status
        self.text = text


class _FakeClient:
    """Patches httpx.AsyncClient: returns a scripted response per URL."""

    def __init__(self, by_url):
        self._by_url = by_url
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def request(self, method, url, headers=None, content=None):
        self.calls.append((method, url, headers, content))
        return self._by_url[url]


class _Entry:
    def __init__(self, host, cookie):
        self.host = host
        self.request_headers = {"Cookie": cookie} if cookie else {}


class _Store:
    def __init__(self, entries=None, jar=None):
        self._entries = entries or []
        self._jar = jar or []
        self.recorded = []

    def entries_newest_first(self):
        return self._entries

    def get_cookies_for_host(self, host):
        return self._jar

    def record_manual_finding(self, finding, url, method):
        self.recorded.append((finding, url, method))
        return "entry-1"


def _ctx(store=None, read_only=False):
    return SimpleNamespace(
        is_in_scope=lambda u: True,
        proxy_url="http://127.0.0.1:8080",
        store=store if store is not None else _Store(),
        read_only=read_only,
        source_label="copilot",
    )


def _patch_client(monkeypatch, by_url):
    client = _FakeClient(by_url)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: client)
    return client


# ── verdict matrix ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_inconclusive_when_control_fails(monkeypatch):
    _patch_client(monkeypatch, {CONTROL: _Resp(500), TARGET: _Resp(500)})
    r = await _authz_differential_probe(
        _ctx(), {"target_url": TARGET, "control_url": CONTROL, "method": "POST"})
    assert r["ok"] is True
    assert r["confirmed"] is False
    assert "INCONCLUSIVE" in r["verdict"]


@pytest.mark.asyncio
async def test_enforced_when_control_ok_target_rejected(monkeypatch):
    _patch_client(monkeypatch, {CONTROL: _Resp(200, '"newtoken"'), TARGET: _Resp(500)})
    r = await _authz_differential_probe(
        _ctx(), {"target_url": TARGET, "control_url": CONTROL, "method": "POST"})
    assert r["confirmed"] is False
    assert "enforced" in r["verdict"]


@pytest.mark.asyncio
async def test_param_ignored_when_own_marker_in_target(monkeypatch):
    _patch_client(monkeypatch, {
        CONTROL: _Resp(200, '{"email":"me@own.test"}'),
        TARGET: _Resp(200, '{"email":"me@own.test"}'),
    })
    r = await _authz_differential_probe(_ctx(), {
        "target_url": TARGET, "control_url": CONTROL, "method": "GET",
        "own_marker": "me@own.test", "victim_marker": "victim@other.test"})
    assert r["confirmed"] is False
    assert "param ignored" in r["verdict"]


@pytest.mark.asyncio
async def test_confirmed_cross_tenant_read_records_finding(monkeypatch):
    _patch_client(monkeypatch, {
        CONTROL: _Resp(200, '{"email":"me@own.test"}'),
        TARGET: _Resp(200, '{"email":"victim@other.test"}'),
    })
    store = _Store()
    r = await _authz_differential_probe(_ctx(store=store), {
        "target_url": TARGET, "control_url": CONTROL, "method": "GET",
        "own_marker": "me@own.test", "victim_marker": "victim@other.test"})
    assert r["confirmed"] is True
    assert "cross-tenant read" in r["verdict"]
    assert r["recorded_entry_id"] == "entry-1"
    assert len(store.recorded) == 1
    assert store.recorded[0][0]["validated_by"] == ["authz_differential_probe"]


@pytest.mark.asyncio
async def test_confirmed_mutation_via_readback(monkeypatch):
    _patch_client(monkeypatch, {
        CONTROL: _Resp(204),
        TARGET: _Resp(204),
        READBACK: _Resp(200, '{"name":"pwned-by-caller"}'),
    })
    store = _Store()
    r = await _authz_differential_probe(_ctx(store=store), {
        "target_url": TARGET, "control_url": CONTROL, "method": "PUT",
        "victim_readback_url": READBACK, "victim_cookie": "victim=abc",
        "victim_readback_marker": "pwned-by-caller"})
    assert r["confirmed"] is True
    assert "cross-tenant mutation" in r["verdict"]
    assert len(store.recorded) == 1


@pytest.mark.asyncio
async def test_needs_review_bare_2xx_no_markers(monkeypatch):
    _patch_client(monkeypatch, {CONTROL: _Resp(200, "ok"), TARGET: _Resp(200, "ok")})
    store = _Store()
    r = await _authz_differential_probe(_ctx(store=store), {
        "target_url": TARGET, "control_url": CONTROL, "method": "GET"})
    assert r["confirmed"] is False
    assert "NEEDS REVIEW" in r["verdict"]
    assert store.recorded == []


@pytest.mark.asyncio
async def test_needs_review_mutation_readback_no_effect(monkeypatch):
    _patch_client(monkeypatch, {
        CONTROL: _Resp(204), TARGET: _Resp(204),
        READBACK: _Resp(200, '{"name":"unchanged"}'),
    })
    r = await _authz_differential_probe(_ctx(), {
        "target_url": TARGET, "control_url": CONTROL, "method": "PUT",
        "victim_readback_url": READBACK, "victim_readback_marker": "pwned"})
    assert r["confirmed"] is False
    assert "NEEDS REVIEW" in r["verdict"]


# ── guards ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_requires_both_urls(monkeypatch):
    r = await _authz_differential_probe(_ctx(), {"target_url": TARGET})
    assert r["ok"] is False
    assert "required" in r["error"]


@pytest.mark.asyncio
async def test_scope_gate_refuses_out_of_scope(monkeypatch):
    ctx = _ctx()
    ctx.is_in_scope = lambda u: u != TARGET
    r = await _authz_differential_probe(
        ctx, {"target_url": TARGET, "control_url": CONTROL})
    assert r["ok"] is False
    assert "out of scope" in r["error"]


@pytest.mark.asyncio
async def test_read_only_refuses_mutation(monkeypatch):
    r = await _authz_differential_probe(
        _ctx(read_only=True),
        {"target_url": TARGET, "control_url": CONTROL, "method": "PUT"})
    assert r["ok"] is False
    assert "read-only" in r["error"]


@pytest.mark.asyncio
async def test_read_only_allows_get(monkeypatch):
    _patch_client(monkeypatch, {CONTROL: _Resp(200, "ok"), TARGET: _Resp(403)})
    r = await _authz_differential_probe(
        _ctx(read_only=True),
        {"target_url": TARGET, "control_url": CONTROL, "method": "GET"})
    assert r["ok"] is True
    assert "enforced" in r["verdict"]


# ── cookie acquisition ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_prefers_freshest_history_cookie_over_jar(monkeypatch):
    store = _Store(
        entries=[_Entry("settings-api.target.test", "live=fresh")],
        jar=[{"name": "stale", "value": "old"}])
    client = _patch_client(monkeypatch, {CONTROL: _Resp(200, "ok"), TARGET: _Resp(403)})
    await _authz_differential_probe(_ctx(store=store), {
        "target_url": TARGET, "control_url": CONTROL, "method": "GET"})
    # every sub-request carried the fresh history cookie, not the stale jar one
    sent = [h.get("cookie") for (_, _, h, _) in client.calls]
    assert sent and all(c == "live=fresh" for c in sent)


@pytest.mark.asyncio
async def test_falls_back_to_jar_when_no_history(monkeypatch):
    store = _Store(entries=[], jar=[{"name": "jarck", "value": "v1"}])
    client = _patch_client(monkeypatch, {CONTROL: _Resp(200, "ok"), TARGET: _Resp(403)})
    await _authz_differential_probe(_ctx(store=store), {
        "target_url": TARGET, "control_url": CONTROL, "method": "GET"})
    sent = [h.get("cookie") for (_, _, h, _) in client.calls]
    assert sent and all(c == "jarck=v1" for c in sent)
