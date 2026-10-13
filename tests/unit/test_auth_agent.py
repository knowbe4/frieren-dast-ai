"""AuthAgent header-bypass confirmation — reproducible, non-login 401/403 -> 200 flips only."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dast.agents.auth_agent import AuthAgent, _is_bypass_response
from dast.scanners.active_checks import CheckTarget

_PROTECTED_BODY = '{"accounts": [{"id": 1, "owner": "admin", "balance": 1000}]}' + " " * 120
_LOGIN_BODY = "<html><form><input type='password' name='pw'></form>Please sign in</html>" + " " * 80


def _target() -> CheckTarget:
    return CheckTarget(method="GET", url="https://app.example.com/admin/accounts",
                       headers={}, body=None, params=[])


def _resp(status: int, text: str) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.text = text
    response.headers = {}
    return response


def _fake_send_factory(bypass_header: str, bypass_body: str, flaky: bool = False):
    calls = {"bypass": 0}

    async def fake_send(client, method, url, headers, body, payload=None):
        if bypass_header in headers:
            calls["bypass"] += 1
            if flaky and calls["bypass"] > 1:
                return _resp(403, "Forbidden")
            return _resp(200, bypass_body)
        return _resp(403, "Forbidden")

    return fake_send


@pytest.mark.asyncio
async def test_reproducible_bypass_is_reported():
    fake_send = _fake_send_factory("X-Original-URL", _PROTECTED_BODY)
    with patch("dast.agents.auth_agent._send", side_effect=fake_send), \
         patch("dast.agents.auth_agent._fmt_http_pair", return_value=("req", "resp")), \
         patch("dast.agents.auth_agent.log_event"):
        findings = await AuthAgent().run(_target(), MagicMock())
    assert [f.parameter for f in findings] == ["X-Original-URL"]


@pytest.mark.asyncio
async def test_200_login_page_is_not_a_bypass():
    fake_send = _fake_send_factory("X-Original-URL", _LOGIN_BODY)
    with patch("dast.agents.auth_agent._send", side_effect=fake_send), \
         patch("dast.agents.auth_agent.log_event"):
        findings = await AuthAgent().run(_target(), MagicMock())
    assert findings == []


@pytest.mark.asyncio
async def test_non_reproducible_flip_is_not_a_bypass():
    fake_send = _fake_send_factory("X-Original-URL", _PROTECTED_BODY, flaky=True)
    with patch("dast.agents.auth_agent._send", side_effect=fake_send), \
         patch("dast.agents.auth_agent.log_event"):
        findings = await AuthAgent().run(_target(), MagicMock())
    assert findings == []


def test_identical_to_baseline_body_is_not_a_bypass():
    body = "x" * 200
    assert not _is_bypass_response(_resp(200, body), _resp(403, body))
