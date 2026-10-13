"""ThreatModelWorker — schema-forced call and newest-first merge."""

import asyncio

from dast.ai import bedrock_client
from dast.discovery.threat_model import ThreatModelWorker
from dast.proxy.session_store import ProxyEntry, SessionStore


def _entry(index: int) -> ProxyEntry:
    return ProxyEntry(
        id=f"e{index}", method="GET", url=f"https://app.test/api/items/{index}", host="app.test",
        path=f"/api/items/{index}", request_headers={"authorization": "Basic YWRtaW46c2VjcmV0"},
        request_body=None, response_status=200, response_headers={"content-type": "application/json"},
    )


def test_analyse_uses_schema_fences_traffic_and_hides_credentials(monkeypatch):
    seen = {}

    def _fake_invoke_json(**kwargs):
        seen.update(kwargs)
        return {"trust_boundaries": ["All /api routes require auth"], "high_risk_surfaces": [],
                "security_invariants": ["All responses are JSON"], "not_vulnerabilities": []}

    monkeypatch.setattr(bedrock_client, "invoke_json", _fake_invoke_json)
    worker = ThreatModelWorker(store=SessionStore(), engine=None)
    asyncio.run(worker._analyse("app.test", [_entry(i) for i in range(5)]))

    assert seen["schema"] is not None and seen["temperature"] == 0
    assert "<traffic_sample>" in seen["user"]
    assert "YWRtaW46c2VjcmV0" not in seen["user"]
    assert worker.get_model("app.test").security_invariants == ["All responses are JSON"]


def test_newer_analysis_items_take_priority():
    worker = ThreatModelWorker(store=SessionStore(), engine=None)
    empty = {"trust_boundaries": [], "high_risk_surfaces": [], "not_vulnerabilities": []}
    worker._apply_result("h", {**empty, "security_invariants": [f"old {i}" for i in range(8)]})
    worker._apply_result("h", {**empty, "security_invariants": ["new fact"]})
    invariants = worker.get_model("h").security_invariants
    assert invariants[0] == "new fact" and len(invariants) == 8
