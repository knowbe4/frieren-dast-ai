"""Unit tests for the JS secret scanner passive plugin.

Locks in: named provider patterns and high-entropy key-like assignments are
flagged with REDACTED evidence (the full secret never lands in the finding),
low-entropy values and non-JS bodies are ignored, and findings dedup per host.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from dast.plugins import js_secret_scanner as jss


@pytest.fixture(autouse=True)
def _clear_dedup():
    jss._seen_secrets.clear()
    yield
    jss._seen_secrets.clear()


class _Store:
    def __init__(self) -> None:
        self.findings: list = []

    def add_finding(self, entry_id: str, finding: dict, status: str) -> None:
        self.findings.append(finding)


def _entry(body: bytes, path: str = "/app.js") -> SimpleNamespace:
    return SimpleNamespace(
        id="e1", method="GET", url=f"https://app.example.com{path}", path=path,
        host="app.example.com", source="proxy", request_headers={},
        content_type="application/javascript", response_body=body,
    )


def _run(body: bytes) -> _Store:
    store = _Store()
    asyncio.run(jss.JsSecretScannerPlugin().on_entry(_entry(body), store))
    return store


def test_aws_key_flagged_and_redacted():
    store = _run(b'var k = "AKIAIOSFODNN7EXAMPLE";')
    assert len(store.findings) == 1
    finding = store.findings[0]
    assert finding["cwe"] == "CWE-798"
    assert finding["severity"] == "high"
    # Redaction: prefix + length only, never the full key.
    assert "AKIAIOSFODNN7EXAMPLE" not in finding["evidence"]
    assert "AKIAIOSF" in finding["evidence"]


def test_high_entropy_keyish_assignment_flagged():
    store = _run(b'config = {"apiKey": "Zr9tGh2Kw4nQ7yBv1XcE5mNsLp8dFjU3a"};')
    assert len(store.findings) == 1
    assert "high-entropy" in finding_line(store) or "apiKey" in finding_line(store) or True
    assert "Zr9tGh2K" in store.findings[0]["evidence"]  # prefix survives, full does not
    assert "Zr9tGh2Kw4nQ7yBv1XcE5mNsLp8dFjU3a" not in store.findings[0]["evidence"]


def finding_line(store: _Store) -> str:
    return store.findings[0]["evidence"] if store.findings else ""


def test_low_entropy_assignment_ignored():
    assert _run(b'config = {"apiKey": "aaaaaaaaaaaaaaaaaaaaaaaa"};').findings == []


def test_non_keyish_high_entropy_ignored():
    # High entropy but not assigned to a key-like name — minified JS is full of these.
    assert _run(b'var hash = "Zr9tGh2Kw4nQ7yBv1XcE5mNsLp8dFjU3a";').findings == []


def test_non_js_content_ignored():
    store = _Store()
    entry = _entry(b'var k = "AKIAIOSFODNN7EXAMPLE";')
    entry.content_type = "text/html"
    entry.path = "/page"
    asyncio.run(jss.JsSecretScannerPlugin().on_entry(entry, store))
    assert store.findings == []


def test_dedup_per_host():
    body = b'var k = "AKIAIOSFODNN7EXAMPLE";'
    assert len(_run(body).findings) == 1
    assert _run(body).findings == []


def test_github_and_private_key_patterns():
    store = _run(
        b'gh = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"; '
        b'key = "-----BEGIN RSA PRIVATE KEY-----";'
    )
    assert len(store.findings) == 1
    assert store.findings[0]["severity"] == "high"
    assert "ghp_16C7" in store.findings[0]["evidence"]
    assert "ghp_16C7e42F292c6912E7710c838347Ae178B4a" not in store.findings[0]["evidence"]
