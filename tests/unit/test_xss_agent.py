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
    async def _fake_browser_confirm(url, proxy_port, cookie_header=""):
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


# ── snippet anchors on the reflection, not unrelated page chrome ────────────

@pytest.mark.asyncio
async def test_snippet_anchors_on_reflection_not_page_chrome(monkeypatch):
    """The response snippet (the validator's only target-controlled evidence)
    must contain the reflected payload even when unrelated XSS-tag-shaped markup
    (e.g. a header script) appears earlier in the page. Regression for a
    false-negative where the snippet was extracted around a generic
    _REFLECTED_RE match in the header/nav instead of the actual reflection."""
    from dast.agents.xss_agent import _tagged_payload, _param_marker
    monkeypatch.setattr(
        "dast.agents.xss_agent.get_filtered_payloads",
        lambda *a, **k: ["<img src=x onerror=alert(1)>"],
    )
    tagged = _tagged_payload("<img src=x onerror=alert(1)>", "q")
    marker = _param_marker("q")
    # Decoy XSS-tag-shaped chrome earlier in the document, then the reflection
    # far down the page (beyond the +/-80 char window around the decoy).
    decoy = "<script>window.analytics=1</script>"
    filler = "x" * 500
    target = _target()

    async def fake_send(client, method, url, headers, body):
        decoded = unquote(url)
        if "onerror" in decoded:
            return _resp(200, f"<html><head>{decoy}</head><body>{filler}{tagged}{filler}</body></html>")
        return _resp(200, "<html><body>hello</body></html>")

    with patch("dast.agents.xss_agent._send", side_effect=fake_send):
        findings = await XssAgent().run(target, MagicMock())

    assert len(findings) == 1
    finding = findings[0]
    # The snippet must contain the reflected payload marker, not just the decoy.
    assert marker in finding.raw_response_snippet
    assert marker in finding.evidence
    assert "analytics" not in finding.raw_response_snippet


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
    async def _confirmed(url, proxy_port, cookie_header=""):
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


# ── browser confirmation carries the authenticated session ──────────────────

def test_cookies_from_header_parses_and_scopes_to_url():
    from dast.agents.xss_agent import _cookies_from_header
    cookies = _cookies_from_header("PHPSESSID=abc123; security=low", "http://127.0.0.1:8081/x")
    assert cookies == [
        {"name": "PHPSESSID", "value": "abc123", "url": "http://127.0.0.1:8081/x"},
        {"name": "security", "value": "low", "url": "http://127.0.0.1:8081/x"},
    ]


def test_cookies_from_header_ignores_malformed_pairs():
    from dast.agents.xss_agent import _cookies_from_header
    # Empty header, stray semicolons, and valueless tokens produce no cookies.
    assert _cookies_from_header("", "http://h/") == []
    assert _cookies_from_header(" ; ; flag ; ", "http://h/") == []


@pytest.mark.asyncio
async def test_browser_confirm_receives_session_cookie(monkeypatch):
    """The reflected-XSS path must hand the agent's Cookie header to the browser,
    otherwise an authenticated target bounces it to login and a real XSS is
    misreported as 'did not execute' (the DVWA false negative this fixes)."""
    from dast.agents.xss_agent import _tagged_payload
    monkeypatch.setattr("dast.agents.xss_agent.get_filtered_payloads",
                        lambda *a, **k: ["<img src=x onerror=alert(1)>"])
    tagged = _tagged_payload("<img src=x onerror=alert(1)>", "q")

    seen: dict = {}

    async def _capture(url, proxy_port, cookie_header=""):
        seen["cookie_header"] = cookie_header
        return False, "csp_or_sink"
    monkeypatch.setattr("dast.agents.xss_agent._browser_confirm", _capture)

    target = _target(headers={"content-type": "text/html", "Cookie": "PHPSESSID=abc123; security=low"})

    async def fake_send(client, method, url, headers, body):
        if "onerror" in unquote(url):
            return _resp(200, f"<html><body>{tagged}</body></html>")
        return _resp(200, "<html><body>hello</body></html>")

    with patch("dast.agents.xss_agent._send", side_effect=fake_send):
        await XssAgent().run(target, MagicMock())

    assert seen.get("cookie_header") == "PHPSESSID=abc123; security=low"


# ── blind XSS via OOB callback (5-B-1) ──────────────────────────────────────

class _FakeCollaborator:
    """Minimal CollaboratorService double: issue_token/was_hit backed by a set."""

    def __init__(self, host="127.0.0.1", port=8777):
        self.host = host
        self.port = port
        self._tokens: list = []
        self.hits: set = set()

    def issue_token(self) -> str:
        token = f"dast{100000 + len(self._tokens)}"
        self._tokens.append(token)
        return token

    def was_hit(self, token: str) -> bool:
        return token in self.hits


@pytest.fixture(autouse=True)
def _fast_oob_settle(monkeypatch):
    monkeypatch.setattr("dast.agents.xss_agent._OOB_SETTLE_SECONDS", 0)


@pytest.mark.asyncio
async def test_blind_oob_callback_confirms_finding(monkeypatch):
    """No in-band reflection anywhere; a blind_oob payload's token is hit by the
    collaborator → confirmed high CWE-79 finding, bypass_validation=True."""
    collab = _FakeCollaborator()
    sent_payloads: list = []

    async def fake_send(client, method, url, headers, body):
        sent_payloads.append(unquote(str(url) + str(body or "")))
        return _resp(200, "<html>nothing reflected</html>")

    monkeypatch.setattr("dast.agents.xss_agent._send", fake_send)
    monkeypatch.setattr("dast.agents.xss_agent.get_filtered_payloads",
                        lambda *a, **k: ["<img src=x onerror=alert(1)>"])
    # issue_token is deterministic (dast{100000+n}) — the agent's FIRST token
    # (the script-src payload) is the one the collaborator receives.
    collab.hits.add("dast100000")

    findings = await XssAgent().run(_target(), MagicMock(), collaborator=collab)

    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == "CWE-79" and f.severity == "high"
    assert f.confirmed is True and f.bypass_validation is True
    assert "Blind" in f.title
    # every injected blind payload carried a live collaborator token
    oob_sent = [p for p in sent_payloads if f"//{collab.host}:{collab.port}/" in p]
    assert len(oob_sent) >= 6  # the whole blind_oob group was injected
    assert any("dast100000" in p for p in oob_sent)  # the hit token was among them


@pytest.mark.asyncio
async def test_blind_oob_silent_without_callback(monkeypatch):
    """Tokens never hit → no finding (the blind channel never invents one)."""
    collab = _FakeCollaborator()

    async def fake_send(client, method, url, headers, body):
        return _resp(200, "<html>nothing reflected</html>")

    monkeypatch.setattr("dast.agents.xss_agent._send", fake_send)
    monkeypatch.setattr("dast.agents.xss_agent.get_filtered_payloads",
                        lambda *a, **k: ["<img src=x onerror=alert(1)>"])

    findings = await XssAgent().run(_target(), MagicMock(), collaborator=collab)
    assert findings == []


@pytest.mark.asyncio
async def test_blind_oob_visits_render_pages_when_stored(monkeypatch):
    """JSON/204 inject response (stored) → the likely render pages are fetched
    in the browser (via proxy) to trigger the callback now."""
    collab = _FakeCollaborator()
    visited: list = []

    async def fake_send(client, method, url, headers, body):
        return _resp(204, "", content_type="application/json")

    async def fake_browser_confirm(url, proxy_port, cookie_header=""):
        visited.append(url)
        return False, "csp_or_sink"

    monkeypatch.setattr("dast.agents.xss_agent._send", fake_send)
    monkeypatch.setattr("dast.agents.xss_agent._browser_confirm", fake_browser_confirm)
    monkeypatch.setattr("dast.agents.xss_agent.get_filtered_payloads",
                        lambda *a, **k: ["<img src=x onerror=alert(1)>"])

    findings = await XssAgent().run(_target(url="https://shop.test/api/comments"), MagicMock(),
                                    collaborator=collab)
    assert findings == []  # no callback fired
    assert "https://shop.test/api/comments" in visited  # same-URL GET render check
