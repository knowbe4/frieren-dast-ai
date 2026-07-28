"""
Unit tests for the open-redirect agent's parameter selection.

The key guarantee: the agent only probes parameters that plausibly carry a
redirect destination — a redirect-suggestive NAME or a value that already looks
like a URL. It must NOT spray the canary into unrelated params (e.g. a flash
'message' field), which was pure noise and violated the "understand before
acting" rule.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from dast.agents import open_redirect_agent as orr


def _target(params, url="https://in.scope/page", method="GET"):
    t = MagicMock()
    t.method = method
    t.url = url
    t.headers = {"host": "in.scope"}
    t.body = None
    t.params = params
    return t


def _run(coro):
    return asyncio.run(coro)


def test_non_redirect_param_is_not_probed():
    """A param named 'message' with a plain string value is never a redirect
    sink — the agent must send zero probes."""
    agent = orr.OpenRedirectAgent()
    send = AsyncMock()
    target = _target([{"name": "message", "value": "hello", "location": "query"}])
    with patch.object(orr, "_send", new=send):
        findings = _run(agent.run(target, MagicMock()))
    assert findings == []
    assert send.call_count == 0, "non-redirect param must not be probed"


def test_redirect_named_param_is_probed():
    """A param named 'returnUrl' is a redirect candidate and must be probed."""
    agent = orr.OpenRedirectAgent()

    async def fake_send(client, method, url, headers, body, payload=None):
        r = MagicMock()
        r.status_code = 200
        r.text = "ok"
        r.headers = {}
        r.url = url
        r.request = MagicMock(method=method, url=url, headers={}, content=b"")
        return r

    target = _target([{"name": "returnUrl", "value": "/home", "location": "query"}])
    with patch.object(orr, "_send", new=AsyncMock(side_effect=fake_send)):
        _run(agent.run(target, MagicMock()))
        assert orr._send.call_count > 0, "redirect-named param must be probed"


def test_url_valued_param_is_probed():
    """A param whose current value already looks like a URL is a candidate even
    if its name is not redirect-suggestive."""
    agent = orr.OpenRedirectAgent()

    async def fake_send(client, method, url, headers, body, payload=None):
        r = MagicMock()
        r.status_code = 200
        r.text = "ok"
        r.headers = {}
        r.url = url
        r.request = MagicMock(method=method, url=url, headers={}, content=b"")
        return r

    target = _target([{"name": "img", "value": "https://cdn.example.com/x.png", "location": "query"}])
    with patch.object(orr, "_send", new=AsyncMock(side_effect=fake_send)):
        _run(agent.run(target, MagicMock()))
        assert orr._send.call_count > 0, "URL-valued param must be probed"
