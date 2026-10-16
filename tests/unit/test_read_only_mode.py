"""
Read-only (production-safe) mode: unsafe methods never leave the machine and
probe/attack tools are refused, so an unattended copilot run against a prod app
can map it without changing anything. See dast/utils/read_only.py.
"""

from __future__ import annotations

import asyncio

import pytest

from dast.tools.base import run_tool, Tool
from dast.tools.context import ToolContext
from dast.utils import read_only


class _Recorder:
    def __init__(self) -> None:
        self.continued = False
        self.aborted_reason = None

    def as_route(self, method: str, url: str = "https://app.example.com/x") -> "_Recorder":
        self.request = type("Req", (), {"method": method, "url": url})()
        return self

    async def continue_(self, **kwargs):
        self.continued = True

    async def abort(self, reason: str = ""):
        self.aborted_reason = reason


def test_is_safe_method():
    assert read_only.is_safe_method("get")
    assert read_only.is_safe_method("HEAD")
    assert not read_only.is_safe_method("POST")
    assert not read_only.is_safe_method("DELETE")


def test_is_action_label():
    assert read_only.is_action_label("Delete user")
    assert read_only.is_action_label("Send test phishing")
    assert read_only.is_action_label("Launch campaign")
    assert not read_only.is_action_label("View report")
    assert not read_only.is_action_label("Dashboard")


def test_route_guard_blocks_unsafe_and_allows_safe():
    on_block_calls = []
    guard = read_only.make_route_guard("t", on_block=lambda m, u: on_block_calls.append(m))

    blocked = _Recorder().as_route("POST")
    asyncio.run(guard(blocked))
    assert blocked.aborted_reason == "blockedbyclient"
    assert not blocked.continued
    assert on_block_calls == ["POST"]

    allowed = _Recorder().as_route("GET")
    asyncio.run(guard(allowed))
    assert allowed.continued
    assert allowed.aborted_reason is None


def test_route_guard_uses_custom_forward():
    forwarded = []

    async def _forward(route):
        forwarded.append(route.request.method)

    guard = read_only.make_route_guard("t", forward=_forward)
    asyncio.run(guard(_Recorder().as_route("GET")))
    assert forwarded == ["GET"]


@pytest.fixture
def recording_run_scan():
    """Temporarily swap the real run_scan handler for one that records calls,
    then restore the registry so other tests see the real tool."""
    from dast.tools import base

    ran: list = []

    async def _probe_handler(ctx, args):
        ran.append(True)
        return {"ok": True}

    original = base._REGISTRY.get("run_scan")
    base._REGISTRY["run_scan"] = Tool(
        name="run_scan", description="x", input_schema={"type": "object"}, handler=_probe_handler,
    )
    try:
        yield ran
    finally:
        if original is not None:
            base._REGISTRY["run_scan"] = original
        else:
            base._REGISTRY.pop("run_scan", None)


def test_run_tool_refuses_blocked_tool_in_read_only(recording_run_scan):
    result = asyncio.run(run_tool(ToolContext(read_only=True), "run_scan", {}))
    assert result["ok"] is False
    assert result["read_only"] is True
    assert recording_run_scan == []  # handler never ran


def test_run_tool_allows_blocked_tool_when_not_read_only(recording_run_scan):
    result = asyncio.run(run_tool(ToolContext(read_only=False), "run_scan", {}))
    assert result["ok"] is True
    assert recording_run_scan == [True]


def test_send_request_blocks_write_method_in_read_only():
    from dast.tools import http_tools

    ctx = ToolContext(read_only=True)
    # In-scope so the only thing that can reject it is the read-only method gate.
    ctx.is_in_scope = lambda url: True  # type: ignore[method-assign]
    result = asyncio.run(http_tools._send_request(ctx, {"url": "https://app.example.com/x", "method": "DELETE"}))
    assert result["ok"] is False
    assert result.get("read_only") is True
