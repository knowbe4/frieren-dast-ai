"""Phase 1 — findings evidence grounding.

Covers: record_finding links to real history entries via evidence_entry_ids (not a
synthetic stub), warns when it cannot ground, and send_request returns the real
proxy-history entry_id of the request it issued.
"""

from __future__ import annotations

import asyncio

import httpx
import respx

from dast.proxy.session_store import SessionStore
from dast.tools import http_tools, record_finding_tools
from dast.tools.context import ToolContext


def _ctx(store: SessionStore, **kw) -> ToolContext:
    ctx = ToolContext(store=store, **kw)
    ctx.is_in_scope = lambda url: True  # type: ignore[method-assign]
    return ctx


# ── record_finding: evidence_entry_ids link to real entries ──────────────────

def test_record_finding_links_evidence_entry_ids():
    store = SessionStore()
    e1 = store.new_entry("POST", "https://example.com/g", {}, b'{"query":"mutation"}')
    e2 = store.new_entry("PUT", "https://example.com/u", {}, b"bytes")
    result = asyncio.run(record_finding_tools._record_finding(_ctx(store), {
        "title": "Consent not revalidated", "severity": "high",
        "url": "https://example.com/g", "evidence": "consent id 498 unchanged after swap",
        "evidence_entry_ids": [e1, e2],
    }))
    assert result["ok"] is True
    # Primary is the first real evidence id, not a fabricated synthetic entry.
    assert result["entry_id"] == e1
    assert not result["entry_id"].startswith("copilot-")
    assert result["evidence_entry_ids"] == [e1, e2]
    assert "warning" not in result
    finding = store.get_entry(e1).findings[0]
    assert finding["evidence_entry_ids"] == [e1, e2]
    assert not finding.get("evidence_synthetic")


def test_record_finding_warns_when_ungrounded():
    store = SessionStore()
    result = asyncio.run(record_finding_tools._record_finding(_ctx(store), {
        "title": "SSRF", "severity": "high",
        "url": "https://never-proxied.example.com/api", "evidence": "oob callback received",
    }))
    assert result["ok"] is True
    # No real traffic matched -> synthetic last resort, surfaced as a non-fatal warning.
    assert "warning" in result
    assert store.get_entry(result["entry_id"]).findings[0].get("evidence_synthetic") is True


def test_record_finding_fallback_prefers_real_post_over_empty_get():
    store = SessionStore()
    empty = store.new_entry("GET", "https://example.com/graphql", {}, None)
    real = store.new_entry("POST", "https://example.com/graphql", {}, b'{"query":"mutation"}')
    # Default GET method, no evidence ids -> must still ground on the real POST.
    result = asyncio.run(record_finding_tools._record_finding(_ctx(store), {
        "title": "GraphQL BOLA", "severity": "high",
        "url": "https://example.com/graphql", "evidence": "foreign object returned",
    }))
    assert result["ok"] is True
    assert result["entry_id"] == real
    assert result["entry_id"] != empty
    assert "warning" not in result


# ── send_request returns the real history entry_id ───────────────────────────

@respx.mock
def test_send_request_returns_entry_id():
    store = SessionStore()

    def _simulate_proxy_record(request):
        # The real proxy records the entry (request+response) before our client sees
        # the response; simulate that so resolve_sent_entry_id has a new entry to find.
        store.new_entry("POST", "https://api.example.com/graphql", {}, b'{"query":"query{me}"}')
        return httpx.Response(200, json={"data": {"me": {"id": 1}}})

    respx.route(method="POST", host="api.example.com", path="/graphql").mock(
        side_effect=_simulate_proxy_record)

    result = asyncio.run(http_tools._send_request(_ctx(store, source_label="copilot"), {
        "url": "https://api.example.com/graphql", "method": "POST",
        "body": '{"query":"query{me}"}',
    }))
    assert result["ok"] is True
    assert result.get("entry_id")
    assert store.get_entry(result["entry_id"]) is not None
