"""Unit tests for the OAuth/OIDC flow analyzer passive plugin.

Locks in: the four deterministic flow weaknesses (implicit grant, missing state,
missing PKCE, credentials in a token request's query string), secret redaction
in evidence, and per-(host, client, check) dedup.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import List, Tuple

import pytest

from dast.plugins import oauth_flow_analyzer as ofa


@pytest.fixture(autouse=True)
def _clear_dedup():
    ofa._seen_checks.clear()
    yield
    ofa._seen_checks.clear()


class _Store:
    def __init__(self) -> None:
        self.findings: List[Tuple[str, dict, str]] = []

    def add_finding(self, entry_id: str, finding: dict, status: str) -> None:
        self.findings.append((entry_id, finding, status))


def _entry(url: str, method: str = "GET") -> SimpleNamespace:
    return SimpleNamespace(
        id="e1", method=method, url=url, path=url.split("app.example.com", 1)[-1].split("?")[0],
        host="app.example.com", source="proxy", request_headers={},
        content_type="text/html", response_body=None, response_status=200,
    )


def _run(url: str, method: str = "GET") -> _Store:
    store = _Store()
    asyncio.run(ofa.OauthFlowAnalyzerPlugin().on_entry(_entry(url, method=method), store))
    return store


def _titles(store: _Store) -> List[str]:
    return [f["title"] for _, f, _ in store.findings]


def test_implicit_flow_flagged():
    store = _run(
        "https://app.example.com/oauth/authorize?response_type=token&client_id=client-implicit"
        "&redirect_uri=https://app.example.com/cb&state=xyz"
    )
    titles = _titles(store)
    assert "OAuth Implicit Grant Flow In Use" in titles
    # state was present -> no missing-state finding
    assert "OAuth Authorization Request Without state Parameter" not in titles


def test_missing_state_flagged():
    store = _run(
        "https://app.example.com/oauth/authorize?response_type=code&client_id=client-missstate"
        "&redirect_uri=https://app.example.com/cb&code_challenge=S0meCHALLENGE"
    )
    assert "OAuth Authorization Request Without state Parameter" in _titles(store)
    # PKCE present -> no missing-PKCE finding
    assert "OAuth Authorization Code Flow Without PKCE" not in _titles(store)


def test_code_flow_without_pkce_flagged_low():
    store = _run(
        "https://app.example.com/oauth/authorize?response_type=code&client_id=client-pkce"
        "&redirect_uri=https://app.example.com/cb&state=xyz"
    )
    finding = next(f for _, f, _ in store.findings if "PKCE" in f["title"])
    assert finding["severity"] == "low"


def test_token_request_credentials_in_query_flagged_and_redacted():
    store = _run(
        "https://app.example.com/oauth/token?grant_type=authorization_code"
        "&client_id=client-tokenq&client_secret=supersecretvalue123&code=abc123",
        method="POST",
    )
    finding = next(f for _, f, _ in store.findings if "Token Request" in f["title"])
    assert finding["cwe"] == "CWE-598"
    # The secret value must never appear verbatim in the evidence.
    assert "supersecretvalue123" not in finding["evidence"]
    assert "<redacted:" in finding["evidence"]


def test_external_redirect_uri_flagged():
    store = _run(
        "https://app.example.com/oauth/authorize?response_type=code&client_id=client-exturi"
        "&redirect_uri=https://evil.example.com/cb&state=xyz&code_challenge=x"
    )
    assert any("redirect_uri" in t for t in _titles(store))


def test_healthy_flow_produces_no_findings():
    store = _run(
        "https://app.example.com/oauth/authorize?response_type=code&client_id=client-healthy"
        "&redirect_uri=https://app.example.com/cb&state=xyz&code_challenge=S0me"
    )
    assert store.findings == []


def test_non_oauth_params_ignored():
    assert _run("https://app.example.com/api/items?page=2&sort=price").findings == []


def test_dedup_same_client_and_check():
    url = (
        "https://app.example.com/oauth/authorize?response_type=token&client_id=client-dedup1"
        "&redirect_uri=https://app.example.com/cb"
    )
    first = _run(url)
    assert len(first.findings) >= 1
    second = _run(url)
    assert second.findings == []


def test_scanner_source_skipped():
    store = _Store()
    entry = _entry(
        "https://app.example.com/oauth/authorize?response_type=token&client_id=webapp"
    )
    entry.source = "scanner"
    asyncio.run(ofa.OauthFlowAnalyzerPlugin().on_entry(entry, store))
    assert store.findings == []
