"""
Unit tests for the Claude apps gateway auth layer (dast.ai.gateway_auth).

Covers credential loading (explicit JWT env, macOS Keychain, graceful degradation
on non-macOS/missing session), token-expiry logic, and the send() request shape
including 401-triggered refresh. No network or Keychain access is performed — the
Keychain subprocess and urllib are monkeypatched.
"""

from __future__ import annotations

import json

import pytest

from dast.ai import gateway_auth


@pytest.fixture(autouse=True)
def _clear_shared_transport(monkeypatch):
    """Reset the process-wide transport so tests never share state."""
    monkeypatch.setattr(gateway_auth, "_shared_transport", None)
    monkeypatch.setattr(gateway_auth, "_shared_base_url", "")
    # Keep env pristine unless a test sets it.
    for var in ("GATEWAY_JWT", "GATEWAY_BASE_URL", "GATEWAY_KEYCHAIN_SERVICE"):
        monkeypatch.delenv(var, raising=False)


# ── credential loading ────────────────────────────────────────────────────────

def test_explicit_jwt_short_circuits_keychain(monkeypatch):
    monkeypatch.setenv("GATEWAY_JWT", "explicit-token")
    monkeypatch.setenv("GATEWAY_BASE_URL", "https://gw.example")
    creds = gateway_auth.load_gateway_credentials()
    assert creds["jwt"] == "explicit-token"
    assert creds["url"] == "https://gw.example"


def test_non_darwin_without_jwt_raises(monkeypatch):
    monkeypatch.setattr(gateway_auth.sys, "platform", "linux")
    with pytest.raises(gateway_auth.GatewayError):
        gateway_auth.load_gateway_credentials()


def test_credentials_available_false_on_error(monkeypatch):
    monkeypatch.setattr(gateway_auth.sys, "platform", "linux")
    assert gateway_auth.credentials_available() is False


def test_credentials_available_true_with_explicit_jwt(monkeypatch):
    monkeypatch.setenv("GATEWAY_JWT", "t")
    assert gateway_auth.credentials_available() is True


def test_keychain_session_parsed(monkeypatch):
    monkeypatch.setattr(gateway_auth.sys, "platform", "darwin")
    payload = json.dumps({
        "enterpriseGateway": {
            "jwt": "kc-token",
            "url": "https://gw.internal",
            "expiresAt": 9999999999000,
        }
    }).encode()
    monkeypatch.setattr(gateway_auth.subprocess, "check_output", lambda *a, **k: payload)
    creds = gateway_auth.load_gateway_credentials()
    assert creds["jwt"] == "kc-token"
    assert creds["url"] == "https://gw.internal"


def test_keychain_missing_entry_raises(monkeypatch):
    import subprocess as _sp
    monkeypatch.setattr(gateway_auth.sys, "platform", "darwin")

    def _fail(*a, **k):
        raise _sp.CalledProcessError(1, "security")

    monkeypatch.setattr(gateway_auth.subprocess, "check_output", _fail)
    with pytest.raises(gateway_auth.GatewayError):
        gateway_auth.load_gateway_credentials()


# ── transport construction / base URL resolution ──────────────────────────────

def test_base_url_arg_overrides_keychain_url(monkeypatch):
    monkeypatch.setenv("GATEWAY_JWT", "t")
    transport = gateway_auth.GatewayTransport(base_url="https://override.example/")
    # Trailing slash trimmed.
    assert transport.base_url == "https://override.example"


def test_missing_base_url_raises(monkeypatch):
    # Explicit JWT with no GATEWAY_BASE_URL and no url field → no base URL.
    monkeypatch.setenv("GATEWAY_JWT", "t")
    with pytest.raises(gateway_auth.GatewayError):
        gateway_auth.GatewayTransport(base_url="")


# ── token expiry ───────────────────────────────────────────────────────────────

def test_token_expired_when_past(monkeypatch):
    monkeypatch.setenv("GATEWAY_JWT", "t")
    monkeypatch.setenv("GATEWAY_BASE_URL", "https://gw")
    transport = gateway_auth.GatewayTransport()
    transport._creds["expiresAt"] = 1000  # far in the past (ms epoch)
    assert transport._token_expired() is True


def test_token_not_expired_without_metadata(monkeypatch):
    """An explicit JWT with no expiresAt is assumed valid (401 handles renewal)."""
    monkeypatch.setenv("GATEWAY_JWT", "t")
    monkeypatch.setenv("GATEWAY_BASE_URL", "https://gw")
    transport = gateway_auth.GatewayTransport()
    transport._creds.pop("expiresAt", None)
    assert transport._token_expired() is False


# ── send(): request shape + 401 refresh ────────────────────────────────────────

class _FakeHTTPResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_send_posts_bearer_and_returns_json(monkeypatch):
    monkeypatch.setenv("GATEWAY_JWT", "the-token")
    monkeypatch.setenv("GATEWAY_BASE_URL", "https://gw.example")
    transport = gateway_auth.GatewayTransport()

    seen = {}

    def _fake_urlopen(req, timeout=0):
        seen["url"] = req.full_url
        seen["auth"] = req.headers.get("Authorization")
        seen["version"] = req.headers.get("Anthropic-version")
        return _FakeHTTPResponse({"content": [{"type": "text", "text": "ok"}]})

    monkeypatch.setattr(gateway_auth.urllib.request, "urlopen", _fake_urlopen)
    result = transport.send({"model": "claude-sonnet-5", "messages": []})

    assert result["content"][0]["text"] == "ok"
    assert seen["url"] == "https://gw.example/v1/messages"
    assert seen["auth"] == "Bearer the-token"
    assert seen["version"] == gateway_auth.ANTHROPIC_VERSION


def test_send_refreshes_on_401_then_succeeds(monkeypatch):
    import urllib.error

    monkeypatch.setenv("GATEWAY_BASE_URL", "https://gw.example")
    monkeypatch.setattr(gateway_auth.sys, "platform", "darwin")
    payload = json.dumps({
        "enterpriseGateway": {
            "jwt": "stale-token",
            "idpRefreshToken": "refresh-abc",
            "expiresAt": 9999999999000,
        }
    }).encode()
    monkeypatch.setattr(gateway_auth.subprocess, "check_output", lambda *a, **k: payload)
    transport = gateway_auth.GatewayTransport(base_url="https://gw.example")

    calls = {"n": 0}

    def _fake_urlopen(req, timeout=0):
        # The token refresh POST hits the token endpoint.
        if req.full_url.endswith("/oauth/token"):
            return _FakeHTTPResponse({"access_token": "fresh-token", "expires_in": 3600})
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.HTTPError(req.full_url, 401, "unauthorized", {}, None)
        return _FakeHTTPResponse({"content": [{"type": "text", "text": "after-refresh"}]})

    monkeypatch.setattr(gateway_auth.urllib.request, "urlopen", _fake_urlopen)
    result = transport.send({"model": "m", "messages": []})
    assert result["content"][0]["text"] == "after-refresh"
    assert transport._token == "fresh-token"


def test_get_shared_transport_rebuilds_on_url_change(monkeypatch):
    monkeypatch.setenv("GATEWAY_JWT", "t")
    first = gateway_auth.get_shared_transport(base_url="https://one.example")
    same = gateway_auth.get_shared_transport(base_url="https://one.example")
    assert first is same
    changed = gateway_auth.get_shared_transport(base_url="https://two.example")
    assert changed is not first
    assert changed.base_url == "https://two.example"
