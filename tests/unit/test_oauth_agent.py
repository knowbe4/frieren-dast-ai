"""OAuth agent tests (4-C): mechanism findings + the confirmed redirect_uri
takeover. GET-only probes; nothing is ever redeemed (no code exchange)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import dast.agents  # noqa: F401 — populates the Coordinator registry
import pytest

from dast.ai.coordinator import Coordinator
from dast.scanners.active_checks import CheckTarget


def _target(params="response_type=code&client_id=web&redirect_uri=https://app.example.com/cb"):
    return CheckTarget(
        method="GET",
        url=f"https://idp.example.com/authorize?{params}",
        headers={}, body=None, params=[],
    )


def _r(status=200, body="", location=None):
    headers = {"location": location} if location else {}
    return SimpleNamespace(
        status_code=status, text=body, headers=headers, content=body.encode(),
        request=SimpleNamespace(method="GET", url="u", headers={}, content=b""),
    )


@pytest.fixture(autouse=True)
def _fresh_registry():
    from dast.ai import provider_health

    provider_health.reset()
    yield
    provider_health.reset()


def _install(monkeypatch, responder):
    import dast.agents.oauth_agent as mod

    sent: list = []

    async def fake_send(client, method, url, headers, body, **kw):
        sent.append({"url": url, "method": method})
        return responder(url)

    monkeypatch.setattr(mod, "_send", fake_send)
    return sent


def test_registered():
    assert "oauth" in Coordinator._registry


@pytest.mark.asyncio
async def test_missing_state_and_pkce_are_mechanism_findings(monkeypatch):
    from dast.agents.oauth_agent import OAuthAgent

    sent = _install(monkeypatch, lambda url: _r(200, "no redirect"))
    findings = await OAuthAgent().run(_target(), MagicMock(), None)

    titles = [f.title for f in findings]
    assert any("state Parameter Missing" in t for t in titles)
    assert any("PKCE Missing" in t for t in titles)
    assert all(f.confirmed is False for f in findings)
    assert all(s["method"] == "GET" for s in sent)  # never a code exchange


@pytest.mark.asyncio
async def test_redirect_uri_swap_confirmed_when_location_attacker(monkeypatch):
    from dast.agents.oauth_agent import OAuthAgent, _EVIL_REDIRECT

    def responder(url):
        if "evil-attacker.test" in url:
            return _r(302, "", location="https://evil-attacker.test/callback?code=leaked")
        return _r(200, "authorize page")

    sent = _install(monkeypatch, responder)
    findings = await OAuthAgent().run(_target(), MagicMock(), None)

    takeover = [f for f in findings if "Takeover" in f.title]
    assert len(takeover) == 1
    assert takeover[0].severity == "high"
    assert takeover[0].confirmed is True
    from urllib.parse import unquote
    assert _EVIL_REDIRECT in unquote(sent[-1]["url"])  # the swapped probe went out


@pytest.mark.asyncio
async def test_redirect_uri_rejected_is_not_a_finding(monkeypatch):
    from dast.agents.oauth_agent import OAuthAgent

    def responder(url):
        if "evil-attacker.test" in url:
            return _r(400, "invalid redirect_uri")
        return _r(200, "authorize page")

    _install(monkeypatch, responder)
    findings = await OAuthAgent().run(_target(), MagicMock(), None)
    assert all("Takeover" not in f.title for f in findings)


@pytest.mark.asyncio
async def test_implicit_flow_flagged(monkeypatch):
    from dast.agents.oauth_agent import OAuthAgent

    _install(monkeypatch, lambda url: _r(200, "x"))
    findings = await OAuthAgent().run(
        _target(params="response_type=token&client_id=web"), MagicMock(), None)
    assert any("Implicit" in f.title for f in findings)


def _install_method(monkeypatch, responder):
    """Like _install but the responder sees (method, url, body) so a test can
    distinguish the authorize GET from the token-exchange POSTs."""
    import dast.agents.oauth_agent as mod

    async def fake_send(client, method, url, headers, body, **kw):
        return responder(method, url, body)

    monkeypatch.setattr(mod, "_send", fake_send)


@pytest.mark.asyncio
async def test_code_reuse_not_confirmed_when_second_exchange_dropped(monkeypatch):
    """Regression: the second token exchange returns None (request dropped). A
    single successful redemption must NOT be reported as 'redeemable twice'."""
    from dast.agents.oauth_agent import OAuthAgent

    token_posts = {"n": 0}

    def responder(method, url, body):
        if body is None:
            # authorize GET → same-host redirect carrying a code
            return _r(302, "", location="https://idp.example.com/authorize?code=abc123")
        token_posts["n"] += 1
        if token_posts["n"] == 1:
            return _r(200, '{"access_token": "t"}')  # first succeeds
        return None  # second exchange dropped on the wire

    _install_method(monkeypatch, responder)
    findings = await OAuthAgent()._check_code_single_use(_target(), MagicMock())

    assert all("Redeemable Twice" not in f.title for f in findings)
    assert token_posts["n"] >= 2  # both exchanges were actually attempted


@pytest.mark.asyncio
async def test_code_reuse_confirmed_when_both_exchanges_succeed(monkeypatch):
    """Both exchanges complete and return an access_token → confirmed finding."""
    from dast.agents.oauth_agent import OAuthAgent

    def responder(method, url, body):
        if body is None:
            return _r(302, "", location="https://idp.example.com/authorize?code=abc123")
        return _r(200, '{"access_token": "t"}')

    _install_method(monkeypatch, responder)
    findings = await OAuthAgent()._check_code_single_use(_target(), MagicMock())

    reuse = [f for f in findings if "Redeemable Twice" in f.title]
    assert len(reuse) == 1
    assert reuse[0].confirmed is True


@pytest.mark.asyncio
async def test_plain_endpoint_skipped(monkeypatch):
    from dast.agents.oauth_agent import OAuthAgent

    sent = _install(monkeypatch, lambda url: _r(200, "x"))
    plain = CheckTarget(method="GET", url="https://example.com/items",
                        headers={}, body=None, params=[])
    findings = await OAuthAgent().run(plain, MagicMock(), None)
    assert findings == []
    assert sent == []
