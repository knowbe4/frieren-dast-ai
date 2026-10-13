"""DOM XSS sources plugin — bounded source->sink matching, no noise on bundles."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import List, Tuple

from dast.plugins.dom_xss_sources import DomXssSourcesPlugin


class _Store:
    def __init__(self) -> None:
        self.findings: List[Tuple[str, dict, str]] = []
        self.enqueued: List[str] = []

    def add_finding(self, entry_id: str, finding: dict, status: str) -> None:
        self.findings.append((entry_id, finding, status))

    def enqueue_for_scan(self, entry_id: str) -> None:
        self.enqueued.append(entry_id)


def _entry(body: str, content_type: str = "text/html", path: str = "/page", source: str = "proxy"):
    return SimpleNamespace(
        id="e1", url=f"https://app.test{path}", path=path, source=source,
        content_type=content_type, response_body=body.encode(),
        queued_for_scan=False, scan_result=None, ai_queued=False, import_hints=None,
    )


def _run(entry) -> _Store:
    store = _Store()
    asyncio.run(DomXssSourcesPlugin().on_entry(entry, store))
    return store


def test_minified_bundle_with_unrelated_sink_and_words_is_not_flagged():
    # One-line bundle: a sink and the words data/input/hash far apart, in other
    # statements. The old `.*` rules flagged this as high.
    bundle = "var a=1;el.innerHTML=t.title;" + "x" * 500 + ";var data=input;r=location.hash;"
    assert _run(_entry(bundle, "application/javascript", "/app.js")).findings == []


def test_lone_location_hash_is_not_a_finding():
    assert _run(_entry("<script>var h = location.hash;</script>")).findings == []


def test_source_feeding_sink_in_same_statement_is_flagged_low():
    store = _run(_entry("<script>el.innerHTML = decodeURIComponent(location.hash.slice(1));</script>"))
    assert len(store.findings) == 1
    finding = store.findings[0][1]
    assert finding["severity"] == "low"
    assert finding["confirmed"] is False
    assert store.enqueued == ["e1"]


def test_js_asset_is_flagged_but_not_enqueued():
    store = _run(_entry("document.write(location.search);", "application/javascript", "/app.js"))
    assert len(store.findings) == 1
    assert store.enqueued == []


def test_scanner_probe_responses_are_ignored():
    store = _run(_entry("<script>el.innerHTML = location.hash;</script>", source="agent"))
    assert store.findings == [] and store.enqueued == []
