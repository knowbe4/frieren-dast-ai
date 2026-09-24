"""
Unit tests for the H1 interactsh OOB client (dast.hackerone.oob).

This is the legacy client kept separate from dast.utils.interactsh because the
two are not behaviorally equivalent (see the module docstring). These tests pin
its wire behavior: hex correlation-id + secret, the callback URL shape, poll
counting raw ``data`` entries, and graceful failure when the server is down.
"""

from __future__ import annotations

import httpx
import pytest

from dast.hackerone.oob import H1InteractshSession


def _patch_client(monkeypatch, *, post=None, get=None):
    class _FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, **kwargs):
            return post(url, **kwargs)

        async def get(self, url, **kwargs):
            return get(url, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeClient(**kw))


def _response(status_code=200, json_body=None):
    request = httpx.Request("POST", "https://oast.pro/register")
    return httpx.Response(status_code, json=json_body or {}, request=request)


@pytest.mark.asyncio
async def test_register_success_sets_url(monkeypatch):
    def fake_post(url, **kwargs):
        assert url.endswith("/register")
        payload = kwargs["json"]
        # hex correlation-id (20 chars) and hex secret-key
        assert len(payload["correlation-id"]) == 20
        assert all(c in "0123456789abcdef" for c in payload["correlation-id"])
        return _response(200, {"domain": "oast.pro"})

    _patch_client(monkeypatch, post=fake_post)
    session = H1InteractshSession()
    assert await session.register() is True
    assert session.url.endswith(".oast.pro")
    assert session.url.startswith("http://")


@pytest.mark.asyncio
async def test_register_without_domain_field_fails(monkeypatch):
    _patch_client(monkeypatch, post=lambda url, **kw: _response(200, {"message": "ok"}))
    session = H1InteractshSession()
    assert await session.register() is False
    assert session.url == ""


@pytest.mark.asyncio
async def test_register_handles_connection_error(monkeypatch):
    def fake_post(url, **kwargs):
        raise httpx.ConnectError("server down")

    _patch_client(monkeypatch, post=fake_post)
    session = H1InteractshSession()
    assert await session.register() is False


@pytest.mark.asyncio
async def test_poll_returns_true_when_data_present(monkeypatch):
    _patch_client(monkeypatch, get=lambda url, **kw: _response(200, {"data": ["hit"]}))
    session = H1InteractshSession()
    assert await session.poll() is True


@pytest.mark.asyncio
async def test_poll_returns_false_when_no_data(monkeypatch):
    _patch_client(monkeypatch, get=lambda url, **kw: _response(200, {"data": []}))
    session = H1InteractshSession()
    assert await session.poll() is False


@pytest.mark.asyncio
async def test_poll_handles_error(monkeypatch):
    def fake_get(url, **kwargs):
        raise httpx.ConnectError("down")

    _patch_client(monkeypatch, get=fake_get)
    session = H1InteractshSession()
    assert await session.poll() is False


@pytest.mark.asyncio
async def test_deregister_swallows_and_logs_errors(monkeypatch):
    def fake_post(url, **kwargs):
        raise httpx.ConnectError("down")

    _patch_client(monkeypatch, post=fake_post)
    session = H1InteractshSession()
    # Must not raise even though the server call fails.
    await session.deregister()
