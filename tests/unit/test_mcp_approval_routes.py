"""
Unit tests for the MCP interactive request-approval routes.

Covers the Burp-style approval plumbing: the allow-list fast path, the
arm -> resume decision cycle (allow_once / always_host / deny), and the timeout
deny. The routes reuse the login-flow event+broadcast+resume pattern; these tests
exercise a lightweight fake context so no full DashboardContext is needed.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi import FastAPI

import dast.proxy.api.mcp_approval_routes as approval_routes
from dast.proxy.api.mcp_approval_routes import make_router


class _FakeCtx:
    """Minimal stand-in exposing only what the approval routes touch."""

    def __init__(self):
        self.mcp_approved_hosts = set()
        self.mcp_approval_pending = [None]
        self.mcp_approval_decision = [None]
        self.mcp_approval_event = asyncio.Event()
        self.mcp_approval_ws_clients = set()

    async def broadcast_approval(self, payload: dict) -> None:
        pass


def _client(ctx) -> httpx.AsyncClient:
    app = FastAPI()
    app.include_router(make_router(ctx))
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_allow_list_fast_path():
    ctx = _FakeCtx()
    ctx.mcp_approved_hosts.add("trusted.example.com")
    async with _client(ctx) as client:
        resp = await client.post("/api/mcp/approval-request", json={
            "url": "https://trusted.example.com/x", "method": "GET",
            "host": "trusted.example.com",
        })
    assert resp.json()["decision"] == "allow"


@pytest.mark.asyncio
async def test_arm_then_resume_always_host():
    ctx = _FakeCtx()
    async with _client(ctx) as client:
        async def resolve_soon():
            # Let the request arm the event before answering.
            await asyncio.sleep(0.05)
            return await client.post("/api/mcp/approval-resume",
                                     json={"decision": "always_host"})

        req = client.post("/api/mcp/approval-request", json={
            "url": "https://newtarget.example.com/x", "method": "POST",
            "host": "newtarget.example.com", "port": 443,
        })
        request_resp, resume_resp = await asyncio.gather(req, resolve_soon())

    assert request_resp.json()["decision"] == "allow"
    assert resume_resp.json()["ok"] is True
    # always_host persisted the host for the session.
    assert "newtarget.example.com" in ctx.mcp_approved_hosts


@pytest.mark.asyncio
async def test_arm_then_resume_deny():
    ctx = _FakeCtx()
    async with _client(ctx) as client:
        async def resolve_soon():
            await asyncio.sleep(0.05)
            return await client.post("/api/mcp/approval-resume", json={"decision": "deny"})

        req = client.post("/api/mcp/approval-request", json={
            "url": "https://newtarget.example.com/x", "method": "GET",
            "host": "newtarget.example.com",
        })
        request_resp, _ = await asyncio.gather(req, resolve_soon())

    assert request_resp.json()["decision"] == "deny"
    assert "newtarget.example.com" not in ctx.mcp_approved_hosts


@pytest.mark.asyncio
async def test_timeout_denies(monkeypatch):
    monkeypatch.setattr(approval_routes, "_APPROVAL_TIMEOUT_SECONDS", 0.05)
    ctx = _FakeCtx()
    async with _client(ctx) as client:
        resp = await client.post("/api/mcp/approval-request", json={
            "url": "https://newtarget.example.com/x", "method": "GET",
            "host": "newtarget.example.com",
        })
    body = resp.json()
    assert body["decision"] == "deny"
    assert body["reason"] == "timeout"


@pytest.mark.asyncio
async def test_invalid_decision_rejected():
    ctx = _FakeCtx()
    async with _client(ctx) as client:
        resp = await client.post("/api/mcp/approval-resume", json={"decision": "maybe"})
    assert resp.status_code == 400
