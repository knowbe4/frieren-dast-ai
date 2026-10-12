"""Unit tests for the WebSocket observer passive plugin.

Locks in: cross-origin 101 handshake is flagged (CSWSH), same-origin handshakes
are catalogued exactly once, non-101 upgrades and plain HTTP are ignored.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from dast.plugins import websocket_observer as ws


@pytest.fixture(autouse=True)
def _clear_dedup():
    ws._seen_endpoints.clear()
    yield
    ws._seen_endpoints.clear()


class _Store:
    def __init__(self) -> None:
        self.findings: list = []

    def add_finding(self, entry_id: str, finding: dict, status: str) -> None:
        self.findings.append(finding)


def _entry(origin: str, status: int = 101, host: str = "ws.app.example.com") -> SimpleNamespace:
    headers = {"Upgrade": "websocket", "Connection": "Upgrade"}
    if origin:
        headers["Origin"] = origin
    return SimpleNamespace(
        id="e1", method="GET", url=f"wss://{host}/socket", path="/socket",
        host=host, source="proxy", request_headers=headers,
        response_status=status, content_type="", response_body=None,
    )


def _run(entry: SimpleNamespace) -> _Store:
    store = _Store()
    asyncio.run(ws.WebsocketObserverPlugin().on_entry(entry, store))
    return store


def test_cross_origin_handshake_flagged():
    store = _run(_entry(origin="https://evil.example.com"))
    assert len(store.findings) == 1
    finding = store.findings[0]
    assert finding["severity"] == "medium"
    assert finding["cwe"] == "CWE-346"
    assert "Origin" in finding["title"]


def test_same_origin_handshake_catalogued_once():
    entry = _entry(origin="https://ws.app.example.com")
    first = _run(entry)
    assert len(first.findings) == 1
    assert first.findings[0]["severity"] == "informational"
    # Second handshake on the same endpoint must not re-fire.
    second = _run(entry)
    assert second.findings == []


def test_subdomain_origin_not_flagged():
    # app.example.com vs ws.app.example.com — same registrable side, not CSWSH.
    store = _run(_entry(origin="https://app.example.com"))
    assert [f["severity"] for f in store.findings] == ["informational"]


def test_failed_handshake_ignored():
    assert _run(_entry(origin="https://evil.example.com", status=403)).findings == []


def test_plain_http_ignored():
    entry = SimpleNamespace(
        id="e1", method="GET", url="https://app.example.com/page", path="/page",
        host="app.example.com", source="proxy",
        request_headers={"Origin": "https://evil.example.com"},
        response_status=200, content_type="text/html", response_body=None,
    )
    assert _run(entry).findings == []


def test_missing_origin_not_flagged_as_mismatch():
    # Non-browser clients omit Origin — that is not evidence of missing validation.
    store = _run(_entry(origin=""))
    assert [f["severity"] for f in store.findings] == ["informational"]
