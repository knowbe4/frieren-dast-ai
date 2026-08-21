"""
Unit tests for dast/hackerone/persistence.py — confirmed-triage persistence.

Locks in that a confirmed triage becomes a synthetic ``source="agent"`` entry plus
a ``"vulnerable"`` finding in the shape the dashboard / SARIF export read, with the
right CWE and severity, and that the H1 route's ``_persist_finding`` still delegates
to the shared helper.
"""

from __future__ import annotations

from types import SimpleNamespace

from dast.hackerone.persistence import H1_CWE_MAP, persist_confirmed_finding


class _FakeStore:
    def __init__(self, entry_id: str = "e1"):
        self._entry_id = entry_id
        self.entries: list = []
        self.findings: list = []

    def new_entry(self, **kwargs):
        self.entries.append(kwargs)
        return self._entry_id

    def add_finding(self, entry_id, finding, status):
        self.findings.append((entry_id, finding, status))


def test_persist_writes_entry_and_finding():
    store = _FakeStore()
    persist_confirmed_finding(
        store,
        method="post",
        url="https://target.example/v3/summary?crId=abc",
        request_headers={"Content-Type": "application/json"},
        request_body='{"a":1}',
        vuln_type="idor",
        severity="Medium",
        evidence="token not validated",
        reasoning="crId alone returns the record",
        payload="token=BOGUS",
        source="vuln-agent",
    )

    assert len(store.entries) == 1
    entry = store.entries[0]
    assert entry["method"] == "POST"                      # normalised upper
    assert entry["source"] == "agent"                     # synthetic entry origin
    assert entry["request_body"] == b'{"a":1}'

    assert len(store.findings) == 1
    entry_id, finding, status = store.findings[0]
    assert entry_id == "e1"
    assert status == "vulnerable"
    assert finding["attack_type"] == "idor"
    assert finding["cwe"] == H1_CWE_MAP["idor"] == "CWE-639"
    assert finding["severity"] == "medium"                # normalised lower
    assert finding["source"] == "vuln-agent"
    assert finding["payload"] == "token=BOGUS"


def test_persist_noops_without_store_or_url():
    # No store: nothing to do, must not raise.
    persist_confirmed_finding(None, method="GET", url="https://x", vuln_type="xss")
    store = _FakeStore()
    persist_confirmed_finding(store, method="GET", url="", vuln_type="xss")
    assert store.entries == []
    assert store.findings == []


def test_persist_swallows_store_errors():
    class _BoomStore:
        def new_entry(self, **kwargs):
            raise RuntimeError("db down")

    # Best-effort: a store failure must never propagate.
    persist_confirmed_finding(_BoomStore(), method="GET", url="https://x", vuln_type="xss")


def test_unknown_vuln_type_gets_empty_cwe():
    store = _FakeStore()
    persist_confirmed_finding(store, method="GET", url="https://x", vuln_type="mystery")
    _, finding, _ = store.findings[0]
    assert finding["cwe"] == ""


def test_h1_route_persist_finding_delegates():
    # The H1 route helper is now a thin delegator to persist_confirmed_finding.
    from dast.proxy.api import hackerone_routes

    store = _FakeStore()
    ctx = SimpleNamespace(store=store)
    report = SimpleNamespace(
        vuln_type="sqli", http_method="GET", request_headers={}, request_body="",
        payload="' OR 1=1",
    )
    result = SimpleNamespace(
        proof_url="https://target.example/item?id=1", severity="high",
        evidence="error-based", reasoning="db error reflected",
    )
    hackerone_routes._persist_finding(ctx, report, result)

    assert len(store.findings) == 1
    _, finding, status = store.findings[0]
    assert finding["attack_type"] == "sqli"
    assert finding["cwe"] == "CWE-89"
    assert finding["source"] == "h1-triage"
    assert status == "vulnerable"
