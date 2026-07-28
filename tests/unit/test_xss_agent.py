"""
Unit tests for XssAgent — reflected/stored XSS detection.

HTTP layer mocked via dast.agents.xss_agent._send. The browser-confirmation
step (_browser_confirm, which launches Playwright) is patched out separately
so tests never touch a real browser. The mutator is patched to return None
by default.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from urllib.parse import unquote

import pytest

from dast.agents.xss_agent import XssAgent
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/search?q=hello", method="GET", params=None, body=None, headers=None):
    return CheckTarget(
        method=method,
        url=url,
        headers=headers or {"content-type": "text/html"},
        body=body,
        params=params or [{"name": "q", "location": "query", "value": "hello"}],
    )


def _resp(status=200, text="", content_type="text/html"):
    m = MagicMock()
    m.status_code = status
    m.text = text
    m.headers = {"content-type": content_type}
    return m


@pytest.fixture(autouse=True)
def _no_mutation(monkeypatch):
    async def _none(*a, **k):
        return None
    monkeypatch.setattr("dast.agents.xss_agent.next_payload", _none)


@pytest.fixture(autouse=True)
def _no_browser(monkeypatch):
    async def _fake_browser_confirm(url, proxy_port):
        return False, "csp_or_sink"
    monkeypatch.setattr("dast.agents.xss_agent._browser_confirm", _fake_browser_confirm)


# ── positive: reflected, unencoded ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_reflected_xss_detected(monkeypatch):
    from dast.agents.xss_agent import _tagged_payload
    monkeypatch.setattr("dast.agents.xss_agent.get_filtered_payloads", lambda *a, **k: ["<img src=x onerror=alert(1)>"])
    tagged = _tagged_payload("<img src=x onerror=alert(1)>", "q")
    target = _target()

    async def fake_send(client, method, url, headers, body):
        decoded = unquote(url)
        if "onerror" in decoded:
            return _resp(200, f"<html><body>{tagged}</body></html>")
        return _resp(200, "<html><body>hello</body></html>")

    with patch("dast.agents.xss_agent._send", side_effect=fake_send):
        findings = await XssAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].attack_type == "xss"
    assert findings[0].cwe == "CWE-79"


# ── negative: clean response ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_response_no_finding():
    target = _target()

    async def fake_send(client, method, url, headers, body):
        return _resp(200, "<html><body>no reflection here</body></html>")

    with patch("dast.agents.xss_agent._send", side_effect=fake_send):
        findings = await XssAgent().run(target, MagicMock())

    assert findings == []


# ── browser confirmation flag propagates onto the finding ──────────────────

@pytest.mark.asyncio
async def test_browser_confirmed_flag_set_when_js_executes(monkeypatch):
    from dast.agents.xss_agent import _tagged_payload
    async def _confirmed(url, proxy_port):
        return True, "confirmed"
    monkeypatch.setattr("dast.agents.xss_agent._browser_confirm", _confirmed)
    tagged = _tagged_payload("<img src=x onerror=alert(1)>", "q")

    target = _target()

    async def fake_send(client, method, url, headers, body):
        decoded = unquote(url)
        if "onerror" in decoded:
            return _resp(200, f"<html><body>{tagged}</body></html>")
        return _resp(200, "clean")

    with patch("dast.agents.xss_agent._send", side_effect=fake_send):
        findings = await XssAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].browser_confirmed is True
    assert findings[0].bypass_validation is True


# ── WAF block then bypass ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_waf_block_then_bypass_records_waf_bypass(monkeypatch):
    from dast.ai.mutator import MutationResult
    from dast.agents.xss_agent import _tagged_payload

    target = _target()
    mutated_tagged = _tagged_payload('<img src=x onerror=alert(1)>', "q")
    responses = iter([
        _resp(200, "clean"),                                     # baseline
        _resp(403, "Request blocked by WAF"),                    # seed payload blocked
        _resp(200, f"<html><body>{mutated_tagged}</body></html>"),  # mutated payload reflected
        _resp(200, "confirm probe response"),                    # DAST_XSS_CONFIRM probe
    ])

    async def fake_send(client, method, url, headers, body):
        return next(responses)

    monkeypatch.setattr("dast.agents.xss_agent.get_filtered_payloads", lambda *a, **k: ["<script>x</script>"])

    call_state = {"n": 0}
    async def fake_next_payload(*a, **k):
        call_state["n"] += 1
        if call_state["n"] == 1:
            return MutationResult(action="mutate", payload='<img src=x onerror=alert(1)>', rationale="tag stripped, use img")
        return None
    monkeypatch.setattr("dast.agents.xss_agent.next_payload", fake_next_payload)

    agent = XssAgent()
    observed = []
    agent.observe = lambda *a, **kw: observed.append((a, kw))

    with patch("dast.agents.xss_agent._send", side_effect=fake_send):
        findings = await agent.run(target, MagicMock())

    assert len(findings) == 1
    assert any(a and a[0] == "waf_bypass" for a, _ in observed)


# ── body location injection ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_body_location_injection_detects_reflection():
    import json
    target = _target(
        url="https://example.com/comments",
        method="POST",
        body=json.dumps({"comment": "hello"}),
        params=[{"name": "comment", "location": "body", "value": "hello"}],
        headers={"content-type": "application/json"},
    )

    async def fake_send(client, method, url, headers, body):
        if body and "onerror" in body:
            return _resp(200, '<html><body>' + body + '</body></html>', content_type="text/html")
        return _resp(200, "<html><body>clean</body></html>")

    with patch("dast.agents.xss_agent._send", side_effect=fake_send):
        findings = await XssAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].parameter == "comment"
