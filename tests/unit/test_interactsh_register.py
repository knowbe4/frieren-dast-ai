"""
Unit tests for interactsh OOB session registration.

Regression coverage for two bugs that made "Generate URL" always fail:
  * `Settings` was missing `interactsh_token` / `interactsh_server`, so
    `register()` raised AttributeError before contacting any server;
  * servers were probed sequentially, so an unreachable public server's DNS
    timeout (~8s each) stacked up before a live one was reached. Registration
    now races all servers and takes the first that returns a domain.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import httpx

from dast.config import Settings
from dast.utils.interactsh import InteractshSession


def test_settings_expose_interactsh_fields():
    s = Settings()
    # Both must exist as attributes — register() reads `interactsh_token`
    # directly (not via getattr), so a missing field is an AttributeError crash.
    # Value may be overridden by the local .env; we only assert access works.
    assert hasattr(s, "interactsh_token")
    assert hasattr(s, "interactsh_server")
    # A fresh Settings with the fields explicitly cleared defaults to None.
    s2 = Settings(interactsh_token=None, interactsh_server=None)
    assert s2.interactsh_token is None
    assert s2.interactsh_server is None


def test_register_picks_first_responding_server_and_skips_dead_ones():
    """A dead server (raises) must not block a later live one from registering."""
    session = InteractshSession()

    async def fake_post(self, url, *args, **kwargs):
        # The first public server is unreachable; the second answers 200.
        if url.startswith("https://oast.pro"):
            raise httpx.ConnectError("name resolution timed out")
        req = httpx.Request("POST", url)
        return httpx.Response(200, json={"message": "registration successful"}, request=req)

    with patch.object(httpx.AsyncClient, "post", new=fake_post):
        ok = asyncio.run(session.register())

    assert ok is True
    # Domain is derived from the winning server's hostname when none is returned.
    assert session.url.endswith(".oast.live") or session.url.endswith(".oast.site") \
        or session.url.endswith(".oast.me")
    assert session._server != "https://oast.pro"


def test_register_returns_false_when_all_servers_fail():
    session = InteractshSession()

    async def fake_post(self, url, *args, **kwargs):
        raise httpx.ConnectError("all dead")

    with patch.object(httpx.AsyncClient, "post", new=fake_post):
        ok = asyncio.run(session.register())

    assert ok is False
    assert session.url == ""


def test_custom_server_is_tried_and_can_win():
    session = InteractshSession()

    async def fake_post(self, url, *args, **kwargs):
        req = httpx.Request("POST", url)
        if url.startswith("https://oob.internal"):
            return httpx.Response(200, json={"domain": "oob.internal"}, request=req)
        raise httpx.ConnectError("public servers unreachable")

    class _Cfg:
        interactsh_token = ""
        interactsh_server = "https://oob.internal"

    with patch("dast.config.settings", _Cfg()), \
         patch.object(httpx.AsyncClient, "post", new=fake_post):
        ok = asyncio.run(session.register())

    assert ok is True
    assert session._server == "https://oob.internal"
    assert session.url.endswith(".oob.internal")
