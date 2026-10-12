"""Unit tests for the host header injection agent.

Locks in: OOB callback confirms with bypass_validation=True, reflection only
counts in link contexts (Location / absolute URLs), a plain error echo is NOT a
finding, static content is skipped, and the agent works without a collaborator
using a non-routable marker host.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dast.agents import host_header_agent as hh


@pytest.fixture(autouse=True)
def _clear_probed():
    hh._probed.clear()
    yield
    hh._probed.clear()


def _resp(status=200, body="", location=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    headers = {"content-type": "text/html"}
    if location:
        headers["location"] = location
    r.headers = headers
    r.request = MagicMock()
    r.request.method = "GET"
    r.request.url = "https://in.scope/reset"
    r.request.headers = {}
    r.request.content = b""
    return r


def _target(content_type="text/html"):
    t = MagicMock()
    t.method = "GET"
    t.url = "https://in.scope/reset"
    t.path = "/reset"
    t.headers = {"content-type": content_type}
    t.body = None
    t.params = []
    return t


class _FakeCollaborator:
    host = "127.0.0.1"
    port = 9999

    def __init__(self, hit=False):
        self._hit = hit
        self.tokens = []

    def issue_token(self):
        token = f"tok{len(self.tokens)}"
        self.tokens.append(token)
        return token

    def was_hit(self, token):
        return self._hit


def _run(agent, target, collaborator=None):
    return asyncio.run(agent.run(target, MagicMock(), collaborator))


def test_static_content_skipped():
    agent = hh.HostHeaderAgent()
    send = AsyncMock()
    with patch.object(hh, "_send", new=send), \
         patch.object(hh, "_OOB_SETTLE_SECONDS", 0):
        assert _run(agent, _target(content_type="text/css")) == []
    assert send.call_count == 0


def test_oob_callback_confirms_high():
    agent = hh.HostHeaderAgent()
    collab = _FakeCollaborator(hit=True)
    send = AsyncMock(return_value=_resp())
    with patch.object(hh, "_send", new=send), \
         patch.object(hh, "_OOB_SETTLE_SECONDS", 0):
        findings = _run(agent, _target(), collaborator=collab)
    assert len(findings) == 2  # host + x-forwarded-host both OOB-confirmed
    assert all(f.severity == "high" for f in findings)
    assert all(f.bypass_validation is True for f in findings)
    assert {f.parameter for f in findings} == {"host", "x-forwarded-host"}


def test_location_reflection_flagged_medium():
    agent = hh.HostHeaderAgent()
    # Both probes (Host and X-Forwarded-Host) get the same reflecting response.
    send = AsyncMock(return_value=_resp(location="https://hostprobe.invalid/reset?token=x"))
    with patch.object(hh, "_send", new=send):
        findings = _run(agent, _target())
    assert {f.parameter for f in findings} == {"host", "x-forwarded-host"}
    assert all(f.severity == "medium" for f in findings)
    assert all(f.bypass_validation is True for f in findings)


def test_body_link_reflection_flagged():
    agent = hh.HostHeaderAgent()
    body = '<a href="https://hostprobe.invalid/reset?token=x">click</a>'
    send = AsyncMock(return_value=_resp(body=body))
    with patch.object(hh, "_send", new=send):
        findings = _run(agent, _target())
    assert len(findings) == 2
    assert all("Reflected" in f.title for f in findings)


def test_plain_error_echo_not_flagged():
    agent = hh.HostHeaderAgent()
    body = '{"error": "invalid host hostprobe.invalid provided"}'
    send = AsyncMock(return_value=_resp(body=body))
    with patch.object(hh, "_send", new=send):
        assert _run(agent, _target()) == []


def test_no_reflection_no_finding():
    agent = hh.HostHeaderAgent()
    send = AsyncMock(return_value=_resp(body="<html>nothing here</html>"))
    with patch.object(hh, "_send", new=send), \
         patch.object(hh, "_OOB_SETTLE_SECONDS", 0):
        assert _run(agent, _target(), collaborator=_FakeCollaborator(hit=False)) == []


def test_probes_override_expected_headers():
    agent = hh.HostHeaderAgent()
    sent_headers = []
    responses = iter([
        _resp(body="<html>ok</html>"),
        _resp(body="<html>ok</html>"),
    ])

    async def fake_send(client, method, url, headers, body):
        sent_headers.append(dict(headers))
        return next(responses)

    with patch.object(hh, "_send", new=AsyncMock(side_effect=fake_send)):
        _run(agent, _target())
    assert sent_headers[0].get("Host") == "hostprobe.invalid"
    assert sent_headers[1].get("X-Forwarded-Host") == "hostprobe.invalid"
