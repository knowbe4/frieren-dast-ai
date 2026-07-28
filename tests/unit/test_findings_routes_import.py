"""
Unit tests for /api/findings/import — the background job + polling flow.

Regression: importing a large report ran parse_findings() + storing synchronously
inside the POST handler. A long AI parse (or many findings to store) could run
past the browser's request timeout with zero visible progress, and closing the
modal (or the tab) looked like it "did nothing" even though the backend kept
working blind. The fix makes POST /api/findings/import return a job_id
immediately; the actual work runs as a background asyncio task, and the caller
polls GET /api/findings/import/{job_id} for status/progress until it's done.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from dast.ai import bedrock_client


@pytest.fixture
def app_and_store():
    from dast.proxy.dashboard_server import build_app
    from dast.proxy.session_store import SessionStore

    store = SessionStore()
    app = build_app(store=store, scan_queue=asyncio.Queue())
    return app, store


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


class TestImportFindingsJob:
    @pytest.mark.asyncio
    async def test_post_returns_job_id_immediately(self, app_and_store, monkeypatch):
        app, store = app_and_store
        monkeypatch.setattr(bedrock_client, "invoke_json", lambda *a, **k: {
            "findings": [{
                "title": "Reflected XSS", "severity": "high", "cwe": "CWE-79",
                "attack_type": "xss", "url": "https://example.com/search",
                "path": "", "method": "GET", "content_type": "",
                "request_body": "", "parameter": "q", "payload": "<script>",
                "evidence": "reflected", "host_hint": "example.com",
            }]
        })
        async with await _client(app) as client:
            resp = await client.post("/api/findings/import", json={"content": "some report"})
            assert resp.status_code == 200
            data = resp.json()
            assert "job_id" in data
            assert "parsed" not in data  # must not block for the result

    @pytest.mark.asyncio
    async def test_missing_content_returns_400_synchronously(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.post("/api/findings/import", json={"content": ""})
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_polling_reaches_done_with_parsed_findings(self, app_and_store, monkeypatch):
        app, store = app_and_store
        monkeypatch.setattr(bedrock_client, "invoke_json", lambda *a, **k: {
            "findings": [{
                "title": "Reflected XSS", "severity": "high", "cwe": "CWE-79",
                "attack_type": "xss", "url": "https://example.com/search",
                "path": "", "method": "GET", "content_type": "",
                "request_body": "", "parameter": "q", "payload": "<script>",
                "evidence": "reflected", "host_hint": "example.com",
            }]
        })
        async with await _client(app) as client:
            resp = await client.post("/api/findings/import", json={"content": "some report"})
            job_id = resp.json()["job_id"]

            data = None
            for _ in range(50):
                poll = await client.get(f"/api/findings/import/{job_id}")
                data = poll.json()
                if data.get("status") not in ("parsing", "storing"):
                    break
                await asyncio.sleep(0.05)

            assert data["parsed"] == 1
            assert data["ok"] is True

    @pytest.mark.asyncio
    async def test_polling_before_done_reports_status_not_result(self, app_and_store, monkeypatch):
        app, store = app_and_store
        started = asyncio.Event()
        release = asyncio.Event()

        def _slow_invoke_json(*a, **k):
            started.set()
            # parse_findings runs this in a thread executor — block synchronously
            # until the test releases it, simulating a slow LLM call.
            import time
            while not release.is_set():
                time.sleep(0.02)
            return {"findings": []}

        monkeypatch.setattr(bedrock_client, "invoke_json", _slow_invoke_json)

        async with await _client(app) as client:
            resp = await client.post("/api/findings/import", json={"content": "some report"})
            job_id = resp.json()["job_id"]

            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)

            poll = await client.get(f"/api/findings/import/{job_id}")
            data = poll.json()
            assert data["status"] == "parsing"
            assert "parsed" not in data

            release.set()

    @pytest.mark.asyncio
    async def test_unknown_job_id_returns_404(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.get("/api/findings/import/does-not-exist")
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_llm_failure_surfaces_as_zero_parsed_not_error(self, app_and_store, monkeypatch):
        # parse_findings() itself catches LLM exceptions and returns [] — this
        # is "no findings", not a job failure.
        def _raise(*a, **k):
            raise RuntimeError("bedrock down")
        monkeypatch.setattr(bedrock_client, "invoke_json", _raise)

        async with await _client(app_and_store[0]) as client:
            resp = await client.post("/api/findings/import", json={"content": "some report"})
            job_id = resp.json()["job_id"]

            data = None
            for _ in range(50):
                poll = await client.get(f"/api/findings/import/{job_id}")
                data = poll.json()
                if data.get("status") not in ("parsing", "storing"):
                    break
                await asyncio.sleep(0.05)

            assert data["parsed"] == 0
