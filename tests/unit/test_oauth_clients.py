"""OAuth client-credentials vault + routes tests (4-G).

SAFETY pin: the plaintext secret never leaves the store module except into
the agent's exchange request — reads are masked, evidence/logs redacted.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from dast.profiles import oauth_clients as vault


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "_OAUTH_DIR", tmp_path / "oauth_clients")
    yield


def test_round_trip_secret_encrypted_at_rest():
    vault.set_for_host("idp.example.com", "web-app", "sekrit-123")
    path = vault._path_for("idp.example.com")
    raw = path.read_text(encoding="utf-8")
    assert "sekrit-123" not in raw                       # never plaintext at rest
    assert "client_secret_enc" in raw
    creds = vault.credentials_for_host("idp.example.com")
    assert creds.client_id == "web-app"
    assert creds.client_secret == "sekrit-123"


def test_url_and_host_keys_resolve_to_the_same_entry():
    vault.set_for_host("https://idp.example.com/authorize", "web-app", "s1")
    creds = vault.credentials_for_host("idp.example.com")
    assert creds is not None and creds.client_id == "web-app"


@pytest.mark.asyncio
async def test_agent_exchange_uses_vault_credentials(monkeypatch):
    from dast.agents.oauth_agent import OAuthAgent
    from dast.scanners.active_checks import CheckTarget

    vault.set_for_host("idp.example.com", "web-app", "sekrit-123")
    secret_seen = []

    async def fake_send(client, method, url, headers, body, **kw):
        if body and b"client_secret=sekrit-123" in body:
            secret_seen.append(body)
            return SimpleNamespace(status_code=200, headers={},
                                   text='{"access_token": "at"}',
                                   content=b'{"access_token": "at"}',
                                   request=SimpleNamespace(method="POST", url=url,
                                                           headers={}, content=b""))
        return SimpleNamespace(status_code=302, headers={"location":
                              "https://idp.example.com/cb?code=abc123"}, text="",
                              content=b"",
                              request=SimpleNamespace(method="GET", url=url,
                                                      headers=headers, content=b""))

    monkeypatch.setattr("dast.agents.oauth_agent._send", fake_send)
    target = CheckTarget(
        method="GET",
        url="https://idp.example.com/authorize?response_type=code&client_id=web-app"
            "&redirect_uri=https://idp.example.com/cb",
        headers={}, body=None, params=[])
    findings = await OAuthAgent()._check_code_single_use(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].confirmed is True
    assert secret_seen, "the vault secret reached the exchange"
    assert "sekrit-123" not in findings[0].evidence      # never in evidence


def test_reset_clears_everything():
    vault.set_for_host("idp.example.com", "web-app", "s1")
    vault.reset()
    assert vault.credentials_for_host("idp.example.com") is None
    assert vault.list_hosts() == []


# ── routes ───────────────────────────────────────────────────────────────────

class TestRoutes:
    def _client(self):
        from types import SimpleNamespace

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from dast.proxy.api.oauth_client_routes import make_router

        app = FastAPI()
        app.include_router(make_router(SimpleNamespace()))
        return TestClient(app)

    def test_set_then_masked_read(self):
        c = self._client()
        r = c.put("/api/oauth-clients", json={
            "host": "idp.example.com", "client_id": "web", "client_secret": "s3"})
        assert r.status_code == 200
        hosts = c.get("/api/oauth-clients").json()["hosts"]
        assert hosts[0]["client_secret_set"] is True
        assert "s3" not in __import__("json").dumps(hosts)

    def test_missing_fields_return_400(self):
        c = self._client()
        r = c.put("/api/oauth-clients", json={"host": "idp.example.com"})
        assert r.status_code == 400

    def test_delete_removes(self):
        c = self._client()
        c.put("/api/oauth-clients", json={
            "host": "idp.example.com", "client_id": "web", "client_secret": "s3"})
        c.request("DELETE", "/api/oauth-clients",
                  json={"host": "idp.example.com"})
        assert c.get("/api/oauth-clients").json()["hosts"] == []
