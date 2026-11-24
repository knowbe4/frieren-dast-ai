"""Unit tests for RateLimitTrustAgent — XFF reflection oracle + path-only
uppercase variant. HTTP layer mocked via
dast.agents.rate_limit_trust_agent._send.

False-positive guards: the XFF finding must require the SPOOFED TEST-NET IP
literal in the body (not a generic "your ip" phrase), and the uppercase path
variant must change only the path, leaving scheme+host lowercase (uppercasing
the whole URL tests host casing, not path normalization).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from dast.agents.rate_limit_trust_agent import _SPOOF_IP, RateLimitTrustAgent
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/api"):
    return CheckTarget(method="GET", url=url, headers={}, body=None, params=[])


def _resp(status=200, body=""):
    return SimpleNamespace(
        status_code=status, text=body, headers={},
        request=SimpleNamespace(method="GET", url="u", headers={}, content=b""),
    )


def _install(monkeypatch, responder):
    import dast.agents.rate_limit_trust_agent as mod

    sent: list = []

    async def fake_send(client, method, url, headers, body, **kw):
        sent.append({"url": url, "headers": dict(headers)})
        return responder(url, headers)

    monkeypatch.setattr(mod, "_send", fake_send)
    return sent


# ── XFF reflection oracle ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_xff_generic_phrase_without_spoofed_ip_not_confirmed(monkeypatch):
    """Body mentions "your IP address" but NOT the spoofed IP → no finding."""
    _install(monkeypatch, lambda url, headers: _resp(200, "your IP address is logged"))
    findings = await RateLimitTrustAgent()._probe_xff_trust(_target(), None)
    assert findings is None


@pytest.mark.asyncio
async def test_xff_spoofed_ip_reflected_confirmed(monkeypatch):
    """The injected TEST-NET IP is reflected → confirmed trust-boundary finding."""
    _install(monkeypatch, lambda url, headers: _resp(200, f"seen from {_SPOOF_IP} ok"))
    finding = await RateLimitTrustAgent()._probe_xff_trust(_target(), None)
    assert finding is not None
    assert finding.confirmed is True
    assert _SPOOF_IP in finding.evidence


# ── path-only uppercase variant ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_uppercase_variant_keeps_scheme_host_lowercase(monkeypatch):
    """The uppercase variant must only uppercase the PATH; scheme+host stay
    lowercase (never HTTPS://EXAMPLE.COM)."""
    sent = _install(monkeypatch, lambda url, headers: _resp(200, "ok"))
    await RateLimitTrustAgent()._probe_path_normalization(
        _target("https://example.com/api"), None)

    urls = [s["url"] for s in sent]
    assert "https://example.com/API" in urls
    assert all(u.startswith("https://example.com/") for u in urls)
    assert not any("EXAMPLE.COM" in u or u.startswith("HTTPS://") for u in urls)
