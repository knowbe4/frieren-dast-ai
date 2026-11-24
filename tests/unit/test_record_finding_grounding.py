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


# ── classification: same-tenant integrity flaw is NOT forced to idor ─────────

def test_same_tenant_integrity_finding_accepted_and_hinted():
    """A business-logic / consent / data-integrity finding on the OWN tenant's object is
    recorded as submitted (never refused, values unchanged) and, when mislabeled idor/BOLA,
    gets a non-fatal reclassification hint."""
    store = SessionStore()
    e1 = store.new_entry("PATCH", "https://example.com/g", {}, b'{"query":"mutation"}')
    result = asyncio.run(record_finding_tools._record_finding(_ctx(store), {
        "title": "IDOR: linked-field lock bypass",
        "severity": "medium",
        "url": "https://example.com/g",
        "evidence": "same-tenant object: the consent-locked field updated anyway after swap",
        "reasoning": "business-logic / data-integrity failure on my own account's object",
        "attack_type": "idor",
        "cwe": "CWE-639",
        "evidence_entry_ids": [e1],
    }))
    # Accepted, not refused, and stored exactly as submitted (hint never mutates values).
    assert result["ok"] is True
    finding = store.get_entry(e1).findings[0]
    assert finding["attack_type"] == "idor"
    assert finding["cwe"] == "CWE-639"
    assert finding["title"] == "IDOR: linked-field lock bypass"
    # Soft guard: nudge toward an honest reclassification (business-logic, not idor/BOLA).
    assert "warning" in result
    assert "business-logic" in result["warning"].lower()
    assert "cross-tenant object access" in result["warning"].lower()


def test_genuine_cross_tenant_idor_classifies_without_hint():
    """A real cross-tenant IDOR still classifies as idor with no spurious reclassification hint."""
    store = SessionStore()
    e1 = store.new_entry("GET", "https://example.com/api/orders/42", {}, b"{}")
    result = asyncio.run(record_finding_tools._record_finding(_ctx(store), {
        "title": "IDOR: cross-tenant order disclosure",
        "severity": "high",
        "url": "https://example.com/api/orders/42",
        "evidence": "200 reading ANOTHER tenant's order 42 — foreign object returned in full",
        "reasoning": "object-level access to a different account's resource",
        "attack_type": "idor",
        "cwe": "CWE-639",
        "evidence_entry_ids": [e1],
    }))
    assert result["ok"] is True
    finding = store.get_entry(e1).findings[0]
    assert finding["attack_type"] == "idor"
    assert finding["cwe"] == "CWE-639"
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


# ── 5-A write-back: confirmed findings mirror into session_intelligence ──────

def test_record_finding_mirrors_confirmed_vuln_into_intel():
    """A recorded finding with an attack_type lands in session_intelligence as a
    confirmed vuln — the coordinator's planner hint/router learns what the
    copilot PROVED, the same ground truth the deterministic agents feed."""
    store = SessionStore()
    assert store.session_intelligence.peek("shop.example.net") is None
    result = asyncio.run(record_finding_tools._record_finding(_ctx(store), {
        "title": "IDOR on user object", "severity": "high",
        "url": "https://shop.example.net/api/users/42", "evidence": "foreign object returned",
        "attack_type": "idor", "parameter": "user_id",
    }))
    assert result["ok"] is True
    intel = store.session_intelligence.peek("shop.example.net")
    assert intel is not None
    assert "idor" in intel.effective_attack_types
    assert intel.confirmed_vulns.get(("/api/users/42", "user_id")) == ["idor"]


def test_record_finding_without_attack_type_skips_intel_mirror():
    """No attack_type → nothing to classify → no intel entry created."""
    store = SessionStore()
    result = asyncio.run(record_finding_tools._record_finding(_ctx(store), {
        "title": "Business logic flaw", "severity": "medium",
        "url": "https://shop.example.net/checkout", "evidence": "consent bypassed",
    }))
    assert result["ok"] is True
    assert store.session_intelligence.peek("shop.example.net") is None
