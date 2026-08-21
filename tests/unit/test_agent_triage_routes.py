"""
Unit tests for dast/proxy/api/agent_triage_routes.py — the Vuln Validator routes.

The agentic loop itself is mocked (``run_triage_agent`` monkeypatched) so these
exercise the routes: job lifecycle, the pause/resume round-trip through the HTTP
API, the AgentToolContext scope relaxation, and error paths. Uses an ASGI
transport + AsyncClient so the background job task shares the test event loop.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi import FastAPI

from dast.proxy.api.agent_triage_routes import AgentToolContext, make_router


class _FakeStore:
    def __init__(self):
        self.findings = []

    def new_entry(self, **kwargs):
        return "e1"

    def add_finding(self, entry_id, finding, status):
        self.findings.append((entry_id, finding, status))


class _FakeCtx:
    def __init__(self, store=None):
        self.proxy_port = 8080
        self.dashboard_port = 8088
        self.store = store
        self.settings = None
        self.browse_queue = None
        self.agent_triage_ws_clients = set()
        self.events = []

    async def broadcast_agent(self, payload):
        self.events.append(payload)


def _app(ctx):
    app = FastAPI()
    app.include_router(make_router(ctx))
    return app


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                             base_url="http://test")


def _patch_parser(monkeypatch):
    from dast.hackerone import parser

    def fake_parse(text):
        return parser.H1Report(vuln_type="idor",
                               proof_url="https://target.example/x",
                               target_url="https://target.example/x",
                               raw_text=text)
    monkeypatch.setattr(parser, "parse_report", fake_parse)


async def _wait_for(client, job_id, predicate, tries=50):
    """Poll status until predicate(job) is true (giving the bg task loop time)."""
    for _ in range(tries):
        await asyncio.sleep(0.02)
        resp = await client.get(f"/api/vuln-validator/status/{job_id}")
        job = resp.json()
        if predicate(job):
            return job
    return job


# ── AgentToolContext scope ────────────────────────────────────────────────────

def test_agent_tool_context_honors_approved_hosts():
    ctx = AgentToolContext(proxy_port=1, dashboard_port=2, store=None, settings=None)
    # No settings → base scope is False; an approved host flips it to True.
    assert ctx.is_in_scope("https://out.example/x") is False
    ctx.approved_hosts.add("out.example")
    assert ctx.is_in_scope("https://out.example/x") is True
    assert ctx.is_in_scope("https://other.example/y") is False


# ── error paths ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_validate_requires_report_text():
    async with _client(_app(_FakeCtx())) as client:
        resp = await client.post("/api/vuln-validator/validate", json={"report_text": ""})
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_status_and_resume_404():
    async with _client(_app(_FakeCtx())) as client:
        assert (await client.get("/api/vuln-validator/status/nope")).status_code == 404
        assert (await client.post("/api/vuln-validator/resume/nope",
                                  json={"kind": "question", "value": {}})).status_code == 404


@pytest.mark.asyncio
async def test_bad_override_url_rejected():
    async with _client(_app(_FakeCtx())) as client:
        resp = await client.post("/api/vuln-validator/validate",
                                 json={"report_text": "x", "override_url": "http://127.0.0.1/x"})
        assert resp.status_code == 400


# ── pause/resume round-trip ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_question_pause_resume_then_confirmed_persists(monkeypatch):
    _patch_parser(monkeypatch)
    from dast.ai import triage_agent

    async def fake_agent(report, report_text, tool_ctx, *, on_event, wait_for_human):
        await on_event({"type": "step", "step": 1, "action": "ask_human"})
        answer = await wait_for_human("question", {"question": "which id?"})
        await on_event({"type": "observation", "step": 1,
                        "observation": f"got {answer.get('text')}"})
        return triage_agent.AgentVerdict(
            status="confirmed", severity="medium", evidence="ev", reasoning="rs",
            proof_url="https://target.example/x", method="GET",
        )

    monkeypatch.setattr(triage_agent, "run_triage_agent", fake_agent)

    store = _FakeStore()
    async with _client(_app(_FakeCtx(store=store))) as client:
        start = await client.post("/api/vuln-validator/validate",
                                  json={"report_text": "IDOR report"})
        job_id = start.json()["job_id"]

        # The loop should pause on the free-form question.
        job = await _wait_for(client, job_id, lambda j: j.get("pause") is not None)
        assert job["pause"]["kind"] == "question"

        # Answer it; the loop resumes and finishes confirmed.
        resume = await client.post(f"/api/vuln-validator/resume/{job_id}",
                                   json={"kind": "question", "value": {"text": "crId=42"}})
        assert resume.json()["ok"] is True

        job = await _wait_for(client, job_id, lambda j: j["status"] == "confirmed")
        assert job["status"] == "confirmed"
        assert job["verdict"]["severity"] == "medium"

    # Confirmed verdict persisted a finding (source=vuln-agent).
    assert len(store.findings) == 1
    assert store.findings[0][1]["source"] == "vuln-agent"


@pytest.mark.asyncio
async def test_resume_when_not_paused_is_rejected(monkeypatch):
    _patch_parser(monkeypatch)
    from dast.ai import triage_agent

    started = asyncio.Event()
    release = asyncio.Event()

    async def fake_agent(report, report_text, tool_ctx, *, on_event, wait_for_human):
        started.set()
        await release.wait()
        return triage_agent.AgentVerdict(status="not_confirmed")

    monkeypatch.setattr(triage_agent, "run_triage_agent", fake_agent)

    async with _client(_app(_FakeCtx())) as client:
        start = await client.post("/api/vuln-validator/validate",
                                  json={"report_text": "report"})
        job_id = start.json()["job_id"]
        await started.wait()
        # Running but not paused → resume must 400.
        resp = await client.post(f"/api/vuln-validator/resume/{job_id}",
                                 json={"kind": "question", "value": {"text": "x"}})
        assert resp.status_code == 400
        release.set()


@pytest.mark.asyncio
async def test_cancel_and_jobs_listing(monkeypatch):
    _patch_parser(monkeypatch)
    from dast.ai import triage_agent

    release = asyncio.Event()

    async def fake_agent(report, report_text, tool_ctx, *, on_event, wait_for_human):
        await release.wait()
        return triage_agent.AgentVerdict(status="not_confirmed")

    monkeypatch.setattr(triage_agent, "run_triage_agent", fake_agent)

    async with _client(_app(_FakeCtx())) as client:
        start = await client.post("/api/vuln-validator/validate",
                                  json={"report_text": "report"})
        job_id = start.json()["job_id"]

        jobs = (await client.get("/api/vuln-validator/jobs")).json()
        assert any(j["job_id"] == job_id for j in jobs)

        cancel = await client.post(f"/api/vuln-validator/cancel/{job_id}")
        assert cancel.json()["ok"] is True
        job = await _wait_for(client, job_id, lambda j: j["status"] == "cancelled")
        assert job["status"] == "cancelled"
        release.set()
