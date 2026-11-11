"""Tests for the shared placeholder guard (dast.utils.placeholders) and its use in
send_request. A model stand-in like ``<UNKNOWN>`` must be caught; a real payload
(XSS, HTML, a normal value) must NOT be."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from dast.tools.http_tools import _send_request
from dast.utils.placeholders import looks_like_placeholder


@pytest.mark.parametrize("value", [
    "<UNKNOWN>", "<unknown>", "<jwt>", "<token>", "<your_password>", "<your_email>",
    "<id>", "unknown", "UNKNOWN", "redacted", "placeholder", "changeme", "n/a", "TODO",
    '{"query": "<UNKNOWN>"}', "Bearer <JWT>",
])
def test_flagged(value: str) -> None:
    assert looks_like_placeholder(value) is True


@pytest.mark.parametrize("value", [
    "", "1234password1234", "app.example.com", "tenant-a.example.com",
    "https://app.example.com/graphql", "a < b and c > d",
    '{"query":"<script>alert(1)</script>"}',            # XSS payload, not a placeholder
    '{"q":"<img src=x onerror=alert(1)>"}',             # HTML payload
    "P@ss<w>ord",                                        # 1-char bracket, real value
])
def test_not_flagged(value: str) -> None:
    assert looks_like_placeholder(value) is False


class _FakeStore:
    def get_cookies_for_host(self, host):
        return []


def _ctx():
    return SimpleNamespace(
        store=_FakeStore(), source_label="copilot", read_only=False,
        is_in_scope=lambda url: True, get_settings=lambda: None,
    )


@pytest.mark.asyncio
async def test_send_request_refuses_placeholder_body() -> None:
    result = await _send_request(_ctx(), {
        "method": "POST",
        "url": "https://app.example.com/graphql",
        "body": '{"query": "<UNKNOWN>"}',
    })
    assert result["ok"] is False
    assert "placeholder" in result["error"].lower()
    assert "body" in result["error"]
    # the refusal guides recovery: read real values (extract_response) or use request variables
    assert "extract_response" in result["error"] and "variables" in result["error"]


@pytest.mark.asyncio
async def test_send_request_refuses_placeholder_header() -> None:
    result = await _send_request(_ctx(), {
        "method": "GET",
        "url": "https://app.example.com/admin",
        "headers": {"Authorization": "Bearer <JWT>"},
    })
    assert result["ok"] is False
    assert "placeholder" in result["error"].lower()


@pytest.mark.asyncio
async def test_send_request_does_not_refuse_real_xss_payload() -> None:
    # An XSS probe url contains <...> but is NOT a placeholder; the placeholder gate
    # must not refuse it. (The fake ctx has no proxy, so the actual send fails — we
    # only assert the failure is NOT the placeholder refusal.)
    result = await _send_request(_ctx(), {
        "method": "GET",
        "url": "https://app.example.com/q?x=<script>alert(1)</script>",
    })
    if result.get("ok") is False:
        assert "placeholder" not in result.get("error", "").lower()
