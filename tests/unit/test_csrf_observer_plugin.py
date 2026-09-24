"""Unit tests for the passive CSRF observer plugin.

The regression these lock in: the plugin flags state-changing requests without a
CSRF token AND re-enqueues them for active confirmation. It must NOT do either
for the scanner's OWN synthetic traffic — the active agents (source "agent"),
param-mining, and probe-diff all send tokenless POSTs. Flagging those is a
self-inflicted false positive, and re-enqueuing them turns the scanner's probe
traffic into a self-amplifying scan-queue feedback loop that starves real
endpoints (the DVWA /exec/ contention this fixes). Genuine traffic is unaffected.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import List, Tuple

import pytest

import dast.plugins.csrf_observer as mod
from dast.plugins.csrf_observer import CsrfObserverPlugin, _SYNTHETIC_SOURCES


class _Store:
    def __init__(self) -> None:
        self.findings: List[Tuple[str, dict, str]] = []
        self.enqueued: List[str] = []

    def add_finding(self, entry_id: str, finding: dict, status: str) -> None:
        self.findings.append((entry_id, finding, status))

    def enqueue_for_scan(self, entry_id: str) -> None:
        self.enqueued.append(entry_id)


@pytest.fixture(autouse=True)
def _reset_flagged_endpoints():
    # The per-endpoint dedup set lives in a module global for process lifetime;
    # isolate each test.
    mod._flagged_endpoints.clear()
    yield
    mod._flagged_endpoints.clear()


def _entry(source: str = "proxy", entry_id: str = "e1", path: str = "/vulnerabilities/exec/") -> SimpleNamespace:
    # A tokenless, cookie-less state-changing request with a 200 response and a
    # simple content-type — the classic Check-1 trigger.
    return SimpleNamespace(
        id=entry_id,
        host="app.example.com",
        method="POST",
        path=path,
        source=source,
        response_status=200,
        request_headers={"content-type": "application/x-www-form-urlencoded"},
        request_body=b"ip=127.0.0.1&Submit=Submit",
        response_headers={},
        queued_for_scan=False,
        scan_result=None,
        ai_queued=False,
        import_hints=None,
    )


def _run(entry: SimpleNamespace) -> _Store:
    store = _Store()
    asyncio.run(CsrfObserverPlugin().on_entry(entry, store))
    return store


def test_flags_and_enqueues_genuine_tokenless_request():
    store = _run(_entry(source="proxy"))
    assert len(store.findings) == 1
    _, finding, _ = store.findings[0]
    assert finding["attack_type"] == "csrf"
    assert finding["title"] == "State-Changing Request Without CSRF Token"
    assert store.enqueued == ["e1"]


@pytest.mark.parametrize("source", sorted(_SYNTHETIC_SOURCES))
def test_synthetic_sources_are_neither_flagged_nor_enqueued(source):
    store = _run(_entry(source=source))
    assert store.findings == []
    assert store.enqueued == []


def test_repeated_requests_to_same_endpoint_flag_once():
    # The live noise against VAmPI: eight genuine POSTs each to /users/v1/login
    # and /users/v1/register produced 16 identical CSRF findings. The signal is
    # per-endpoint, so it must fire once per (host, method, path).
    store = _Store()
    plugin = CsrfObserverPlugin()
    for i in range(8):
        asyncio.run(plugin.on_entry(_entry(entry_id=f"e{i}", path="/users/v1/login"), store))
    assert len(store.findings) == 1
    assert store.enqueued == ["e0"]


def test_distinct_endpoints_flag_separately():
    store = _Store()
    plugin = CsrfObserverPlugin()
    asyncio.run(plugin.on_entry(_entry(entry_id="a", path="/users/v1/login"), store))
    asyncio.run(plugin.on_entry(_entry(entry_id="b", path="/users/v1/register"), store))
    assert len(store.findings) == 2
    assert store.enqueued == ["a", "b"]
