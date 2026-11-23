"""Deserialization sink agent tests (4-B).

Pins the SAFETY contract: no captured body is ever re-sent, no executable
gadget is ever sent (the OOB body is the spliced URLDNS fixture — DNS only),
and the OOB fires only with an operator-provided fixture + a Collaborator hit.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import dast.agents  # noqa: F401 — populates the Coordinator registry
import pytest

from dast.ai.coordinator import Coordinator
from dast.scanners.active_checks import CheckTarget


def _target(body=b"\xac\xed\x00\x05some-serialized-state", method="POST"):
    return CheckTarget(
        method=method, url="https://app.example.com/api/import",
        headers={"content-type": "application/x-java-serialized-object"},
        body=body,
        params=[{"name": "session", "location": "body", "value": "x"}],
    )


def _r(status=200, body="ok", url="https://app.example.com/api/import"):
    return SimpleNamespace(
        status_code=status, text=body, headers={}, content=body.encode(),
        request=SimpleNamespace(method="POST", url=url, headers={}, content=b""),
    )


class _FakeCollaborator:
    host = "collab.example.test"
    port = 53

    def __init__(self, hit: bool):
        self._hit = hit
        self.tokens = []

    def issue_token(self) -> str:
        token = "dasttesttoken"
        self.tokens.append(token)
        return token

    def was_hit(self, token: str) -> bool:
        return self._hit


@pytest.fixture(autouse=True)
def _fresh_registry():
    from dast.ai import provider_health

    provider_health.reset()
    yield
    provider_health.reset()


def test_registered_and_dispatch_gated():
    assert "deserialization" in Coordinator._registry


@pytest.mark.asyncio
async def test_reflection_error_is_unconfirmed_sink_finding(monkeypatch):
    from dast.agents.deserialization_agent import DeserializationAgent, _PROBE_BODY

    sent_bodies: list = []

    async def fake_send(client, method, url, headers, body, **kw):
        sent_bodies.append(body)
        if body == _PROBE_BODY:
            return _r(500, "java.io.InvalidClassException: stream corrupted")
        return _r(200, "ok")

    monkeypatch.setattr(
        "dast.agents.deserialization_agent._send", fake_send)
    monkeypatch.setattr(
        "dast.agents.deserialization_agent._FIXTURE",
        __import__("pathlib").Path("/nonexistent/urldns.bin"))

    findings = await DeserializationAgent().run(_target(), MagicMock(),
                                                _FakeCollaborator(hit=False))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-502"
    assert findings[0].confirmed is False
    # SAFETY: the captured serialized body is never re-sent
    assert _target().body not in sent_bodies


@pytest.mark.asyncio
async def test_urldns_oob_confirms_with_fixture_and_hit(monkeypatch, tmp_path):
    from dast.agents.deserialization_agent import DeserializationAgent, _PLACEHOLDER_URL

    placeholder = _PLACEHOLDER_URL.encode()
    # minimal fixture: java magic + the placeholder URL (shape, not a real stream)
    fixture = b"\xac\xed\x00\x05" + b"\x74" + len(placeholder).to_bytes(2, "big") \
        + placeholder + b"\x74" + len(placeholder).to_bytes(2, "big") + placeholder
    fixture_path = tmp_path / "urldns.bin"
    fixture_path.write_bytes(fixture)
    monkeypatch.setattr("dast.agents.deserialization_agent._FIXTURE", fixture_path)

    sent_bodies: list = []

    async def fake_send(client, method, url, headers, body, **kw):
        sent_bodies.append(body)
        return _r(200, "accepted")

    monkeypatch.setattr("dast.agents.deserialization_agent._send", fake_send)
    collab = _FakeCollaborator(hit=True)

    findings = await DeserializationAgent().run(_target(), MagicMock(), collab)

    assert len(findings) == 1
    assert findings[0].confirmed is True
    assert findings[0].severity == "critical"
    oob_body = sent_bodies[-1]
    assert _PLACEHOLDER_URL.encode() not in oob_body          # spliced out
    assert b"collab.example.test" in oob_body                 # collaborator URL in
    assert collab.tokens == ["dasttesttoken"]
    # TC_STRING length prefixes patched to the new URL length
    collab_url = f"http://{collab.host}:{collab.port}/{collab.tokens[0]}"
    assert len(collab_url).to_bytes(2, "big") in oob_body


@pytest.mark.asyncio
async def test_urldns_no_hit_no_confirmed_finding(monkeypatch, tmp_path):
    from dast.agents.deserialization_agent import DeserializationAgent, _PLACEHOLDER_URL

    placeholder = _PLACEHOLDER_URL.encode()
    fixture = b"\xac\xed\x00\x05" + b"\x74" + len(placeholder).to_bytes(2, "big") + placeholder
    fixture_path = tmp_path / "urldns.bin"
    fixture_path.write_bytes(fixture)
    monkeypatch.setattr("dast.agents.deserialization_agent._FIXTURE", fixture_path)

    async def fake_send(client, method, url, headers, body, **kw):
        return _r(200, "accepted")

    monkeypatch.setattr("dast.agents.deserialization_agent._send", fake_send)
    findings = await DeserializationAgent().run(_target(), MagicMock(),
                                                _FakeCollaborator(hit=False))
    assert all(f.confirmed is False for f in findings)


@pytest.mark.asyncio
async def test_get_target_is_skipped():
    from dast.agents.deserialization_agent import DeserializationAgent

    findings = await DeserializationAgent().run(_target(method="GET"), MagicMock(),
                                                _FakeCollaborator(hit=True))
    assert findings == []
