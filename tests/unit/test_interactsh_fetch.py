"""fetch_interactions parses polled interactions; display sessions show them."""

from __future__ import annotations

from typing import Any, Dict

import pytest

from dast.proxy.api import interactions_routes
from dast.utils import interactsh
from dast.utils.interactsh import InteractshSession


class _Response:
    def __init__(self, payload: Dict[str, Any]) -> None:
        self.status_code = 200
        self._payload = payload

    def json(self) -> Dict[str, Any]:
        return self._payload


class _Client:
    def __init__(self, payload: Dict[str, Any]) -> None:
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url: str, params: Dict[str, str]):
        return _Response(self._payload)


def _session() -> InteractshSession:
    session = InteractshSession()
    session._server = "https://oast.test"
    session._url = "http://corrid0000000000000nonce00000.oast.test"
    session._private_key = object()
    return session


@pytest.mark.asyncio
async def test_fetch_interactions_returns_parsed_objects(monkeypatch):
    payload = {"data": ["x"], "aes_key": "k", "extra": ['{"protocol": "dns", "full-id": "a.corr"}']}
    monkeypatch.setattr("httpx.AsyncClient", lambda **kwargs: _Client(payload))
    monkeypatch.setattr(interactsh, "_decrypt_entries",
                        lambda key, aes, entries: ['{"protocol": "http", "full-id": "b.corr"}', "not json"])

    interactions = await _session().fetch_interactions()

    assert interactions[0] == {"protocol": "dns", "full-id": "a.corr"}
    assert interactions[1]["protocol"] == "http"
    assert interactions[2] == {"protocol": "unknown", "raw-request": "not json"}


@pytest.mark.asyncio
async def test_poll_is_true_only_when_something_arrived(monkeypatch):
    monkeypatch.setattr("httpx.AsyncClient", lambda **kwargs: _Client({"data": []}))
    assert await _session().poll() is False


def test_marker_host_prefixes_the_session_host():
    assert _session().marker_host("frabc") == "frabc.corrid0000000000000nonce00000.oast.test"
    assert InteractshSession().marker_host("frabc") == ""


@pytest.mark.asyncio
async def test_display_session_receives_published_callbacks():
    session_id = interactions_routes.register_display_session("http://corr.oast.test", label="unit")
    try:
        await interactions_routes.publish_callbacks(
            session_id, [{"protocol": "dns", "full-id": "frabc.corr", "remote-address": "8.8.8.8"}])
        session = interactions_routes._sessions[session_id]
        assert session["callbacks"][0]["type"] == "dns"
        assert "frabc.corr" in session["callbacks"][0]["raw"]
        assert "_interactsh" not in session    # display-only: never polled by the tab
    finally:
        interactions_routes._sessions.pop(session_id, None)
