"""
The dashboard UI must force revalidation: a fresh index.html paired with a
heuristically cached old js/*.js breaks the UI after an upgrade.
"""

from __future__ import annotations

import asyncio
from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from dast.proxy.dashboard_server import build_app
from dast.proxy.session_store import SessionStore


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = build_app(store=SessionStore(), scan_queue=asyncio.Queue())
    with TestClient(app, base_url="http://127.0.0.1") as test_client:
        yield test_client


@pytest.mark.parametrize("path", ["/", "/ui/js/10-state-core.js", "/ui/styles.css"])
def test_ui_assets_require_revalidation(client: TestClient, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-cache"


def test_not_modified_response_keeps_policy(client: TestClient) -> None:
    first = client.get("/ui/js/10-state-core.js")
    second = client.get("/ui/js/10-state-core.js", headers={"if-none-match": first.headers["etag"]})
    assert second.status_code == 304
    assert second.headers["cache-control"] == "no-cache"


def test_index_versions_asset_urls(client: TestClient) -> None:
    html = client.get("/").text
    assert 'src="/ui/js/10-state-core.js?v=' in html
    assert 'href="/ui/styles.css?v=' in html
    versioned = client.get("/ui/js/10-state-core.js?v=123")
    assert versioned.status_code == 200
