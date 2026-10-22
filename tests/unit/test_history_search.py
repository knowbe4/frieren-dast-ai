"""
Unit tests for the global HTTP history search (full headers + bodies).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import List, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient

from dast.proxy.api.proxy_routes import make_router
from dast.proxy.history_search import search_entries
from dast.proxy.session_store import ProxyEntry


def _entry(
    entry_id: str,
    path: str = "/",
    request_headers: Optional[dict] = None,
    request_body: Optional[bytes] = None,
    response_headers: Optional[dict] = None,
    response_body: Optional[bytes] = None,
    status: int = 200,
) -> ProxyEntry:
    return ProxyEntry(
        id=entry_id,
        method="GET",
        url=f"https://app.example.com{path}",
        host="app.example.com",
        path=path,
        request_headers=request_headers or {},
        request_body=request_body,
        response_status=status,
        response_headers=response_headers or {},
        response_body=response_body,
    )


def _history() -> List[ProxyEntry]:
    return [
        _entry("url", path="/api/users/42"),
        _entry("req-header", request_headers={"Authorization": "Bearer tok-REQ-123"}),
        _entry("resp-header", response_headers={"X-Trace-Id": "trace-RESP-456"}),
        _entry("req-body", request_body=b'{"email":"alice@example.com"}'),
        _entry("resp-body", response_body=b'{"next_page_cursor":"paginate-BODY-789"}'),
        _entry("multi-cookie", response_headers={"set-cookie": ["a=1", "session=SID-999"]}),
        _entry("status", status=418),
    ]


def test_matches_url():
    assert search_entries(_history(), "users/42") == ["url"]


def test_matches_request_and_response_headers():
    assert search_entries(_history(), "tok-req-123") == ["req-header"]
    assert search_entries(_history(), "x-trace-id") == ["resp-header"]


def test_matches_repeated_header_values():
    assert search_entries(_history(), "SID-999") == ["multi-cookie"]


def test_matches_request_and_response_bodies():
    assert search_entries(_history(), "alice@example") == ["req-body"]
    assert search_entries(_history(), "paginate-body-789") == ["resp-body"]


def test_matches_status_code():
    assert search_entries(_history(), "418") == ["status"]


def test_empty_query_matches_nothing():
    assert search_entries(_history(), "   ") == []


def test_route_returns_matching_ids():
    store = SimpleNamespace(all_entries=_history)
    ctx = SimpleNamespace(store=store, scan_queue=None, scan_queue_state=None)
    app = FastAPI()
    app.include_router(make_router(ctx))
    response = TestClient(app).get("/api/history/search", params={"q": "paginate-BODY"})
    assert response.status_code == 200
    assert response.json()["ids"] == ["resp-body"]
