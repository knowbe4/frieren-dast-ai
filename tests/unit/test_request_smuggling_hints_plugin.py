"""Request smuggling hints — malformed Content-Length is recorded, not raised."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from dast.plugins.request_smuggling_hints import RequestSmugglingHintsPlugin


class _Store:
    def __init__(self) -> None:
        self.findings = []

    def add_finding(self, entry_id: str, finding: dict, status: str) -> None:
        self.findings.append(finding)


def _run(headers: dict, status: int = 200, body: bytes = b"a=1") -> _Store:
    store = _Store()
    entry = SimpleNamespace(id="e1", request_headers=headers, response_status=status, request_body=body)
    asyncio.run(RequestSmugglingHintsPlugin().on_entry(entry, store))
    return store


def test_duplicated_content_length_is_a_hint_not_an_exception():
    store = _run({"content-length": "3, 3"}, status=400)
    assert [f["title"] for f in store.findings] == ["Potential Request Smuggling: Malformed Content-Length"]
    assert store.findings[0]["confirmed"] is False


def test_mismatched_length_with_400_still_flagged():
    store = _run({"content-length": "10"}, status=400, body=b"a=1")
    assert store.findings[0]["title"].endswith("Content-Length Mismatch and 400 Response")


def test_normal_request_is_not_flagged():
    assert _run({"content-length": "3"}).findings == []
