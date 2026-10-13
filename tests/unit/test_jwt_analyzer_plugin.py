"""JWT analyzer plugin — tokens the client sent, deduped, alg:none only critical when accepted."""

from __future__ import annotations

import asyncio
import base64
import json
from types import SimpleNamespace
from typing import List, Tuple

from dast.plugins.jwt_analyzer import JwtAnalyzerPlugin


def _segment(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _token(alg: str = "HS256", claims: dict | None = None, signature: str = "c2lnbmF0dXJlX3ZhbHVl") -> str:
    claims = claims if claims is not None else {"sub": "1234567890", "exp": 9999999999}
    return f"{_segment({'alg': alg, 'typ': 'JWT'})}.{_segment(claims)}.{signature}"


class _Store:
    def __init__(self) -> None:
        self.findings: List[Tuple[str, dict, str]] = []

    def add_finding(self, entry_id: str, finding: dict, status: str) -> None:
        self.findings.append((entry_id, finding, status))


def _entry(token: str = "", status: int = 200, source: str = "proxy", body: bytes = b"", entry_id: str = "e1"):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return SimpleNamespace(id=entry_id, host="api.test", source=source, request_headers=headers,
                           response_status=status, response_body=body)


def _run(plugin: JwtAnalyzerPlugin, entry) -> _Store:
    store = _Store()
    asyncio.run(plugin.on_entry(entry, store))
    return store


def test_alg_none_accepted_by_server_is_critical_confirmed():
    store = _run(JwtAnalyzerPlugin(), _entry(_token(alg="none", signature=""), status=200))
    finding = store.findings[0][1]
    assert finding["severity"] == "critical" and finding["confirmed"] is True


def test_alg_none_rejected_is_only_a_lead():
    store = _run(JwtAnalyzerPlugin(), _entry(_token(alg="none", signature=""), status=401))
    finding = store.findings[0][1]
    assert finding["severity"] == "medium"
    assert finding["confirmed"] is False and finding["needs_review"] is True


def test_scanner_probes_with_forged_tokens_are_ignored():
    store = _run(JwtAnalyzerPlugin(), _entry(_token(alg="none", signature=""), source="agent"))
    assert store.findings == []


def test_tokens_in_response_bodies_are_not_analysed():
    body = json.dumps({"example": _token(alg="none", signature="")}).encode()
    assert _run(JwtAnalyzerPlugin(), _entry(body=body)).findings == []


def test_same_token_reported_once_across_requests():
    plugin = JwtAnalyzerPlugin()
    token = _token(claims={"sub": "1234567890"})  # no exp -> one finding
    first = _run(plugin, _entry(token, entry_id="e1"))
    second = _run(plugin, _entry(token, entry_id="e2"))
    assert len(first.findings) == 1
    assert second.findings == []
