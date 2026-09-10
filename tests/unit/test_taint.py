"""
Unit tests for the taint marker correlation engine and the passive correlator
plugin. Pure in-memory — no network, no LLM.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from dast.plugins.taint_correlator import TaintCorrelatorPlugin
from dast.scanners.taint import MARKER_PREFIX, TaintStore


# ── core engine ──────────────────────────────────────────────────────────────

class TestMint:
    def test_marker_format_and_uniqueness(self):
        store = TaintStore()
        tokens = {store.mint("https://a/x", "q", "query") for _ in range(50)}
        assert len(tokens) == 50  # all unique
        for token in tokens:
            assert token.startswith(MARKER_PREFIX)
            assert token[len(MARKER_PREFIX):].isalnum()

    def test_get_returns_source_metadata(self):
        store = TaintStore()
        token = store.mint("https://a/login", "user", "body", "POST")
        marker = store.get(token)
        assert marker is not None
        assert marker.source_url == "https://a/login"
        assert marker.source_param == "user"
        assert marker.source_location == "body"
        assert marker.source_method == "POST"

    def test_eviction_bounds_registry(self):
        store = TaintStore(max_markers=10)
        first = store.mint("https://a/x", "q", "query")
        for _ in range(15):
            store.mint("https://a/x", "q", "query")
        # oldest evicted once over the ceiling
        assert store.get(first) is None


class TestFindHits:
    def test_empty_body_no_hits(self):
        store = TaintStore()
        store.mint("https://a/x", "q", "query")
        assert store.find_hits("https://a/x", "") == []

    def test_unknown_marker_shaped_token_ignored(self):
        store = TaintStore()
        # a token matching the shape but never minted must not produce a hit
        fake = MARKER_PREFIX + "0123456789ab"
        assert store.find_hits("https://a/x", f"noise {fake} noise") == []

    def test_same_endpoint_reflection_not_cross_location(self):
        store = TaintStore()
        token = store.mint("https://a/echo?x=1", "x", "query")
        hits = store.find_hits("https://a/echo?x=2", f"<p>{token}</p>")
        assert len(hits) == 1
        assert hits[0].is_cross_location is False  # same host+path, query ignored

    def test_cross_endpoint_surfacing_flagged(self):
        store = TaintStore()
        token = store.mint("https://a/comment", "body", "body", "POST")
        hits = store.find_hits("https://a/feed", f"<li>{token}</li>")
        assert len(hits) == 1
        assert hits[0].is_cross_location is True
        assert hits[0].marker.token == token

    def test_multiple_markers_one_pass(self):
        store = TaintStore()
        t1 = store.mint("https://a/1", "p1", "query")
        t2 = store.mint("https://a/2", "p2", "body")
        hits = store.find_hits("https://a/dashboard", f"{t1} ... {t2}")
        assert {h.marker.token for h in hits} == {t1, t2}


class TestCorrelations:
    def test_record_dedups_by_marker_and_sink(self):
        store = TaintStore()
        token = store.mint("https://a/in", "q", "query")
        (hit,) = store.find_hits("https://a/out", token)
        assert store.record_correlation(hit) is True
        # same marker, same sink endpoint (query differs) → not recorded again
        (hit2,) = store.find_hits("https://a/out?z=9", token)
        assert store.record_correlation(hit2) is False
        assert len(store.correlations()) == 1

    def test_correlations_for_source_filters(self):
        store = TaintStore()
        t1 = store.mint("https://a/in1", "q1", "query")
        t2 = store.mint("https://a/in2", "q2", "query")
        for token in (t1, t2):
            (hit,) = store.find_hits("https://a/out", token)
            store.record_correlation(hit)
        by_source = store.correlations_for_source(source_url="https://a/in1")
        assert len(by_source) == 1
        assert by_source[0].marker.source_param == "q1"


# ── passive correlator plugin ────────────────────────────────────────────────

@dataclass
class _FakeEntry:
    id: str
    url: str
    method: str
    response_body: Optional[bytes]


@dataclass
class _FakeStore:
    taint_store: TaintStore
    findings: List[Tuple[str, dict, str]] = field(default_factory=list)

    def add_finding(self, entry_id: str, finding: dict, scan_result: str) -> None:
        self.findings.append((entry_id, finding, scan_result))


class TestCorrelatorPlugin:
    async def test_cross_endpoint_hit_emits_finding_once(self):
        store = _FakeStore(taint_store=TaintStore())
        token = store.taint_store.mint("https://a/comment", "text", "body", "POST")
        entry = _FakeEntry(id="e1", url="https://a/feed", method="GET",
                           response_body=f"<div>{token}</div>".encode())
        plugin = TaintCorrelatorPlugin()

        await plugin.on_entry(entry, store)
        await plugin.on_entry(entry, store)  # second pass must not duplicate

        assert len(store.findings) == 1
        entry_id, finding, scan_result = store.findings[0]
        assert entry_id == "e1"
        assert scan_result == "vulnerable"
        assert finding["attack_type"] == "taint"
        assert finding["parameter"] == "text"
        assert "comment" in finding["evidence"] and "feed" in finding["evidence"]

    async def test_same_endpoint_reflection_no_finding(self):
        store = _FakeStore(taint_store=TaintStore())
        token = store.taint_store.mint("https://a/echo", "q", "query")
        entry = _FakeEntry(id="e1", url="https://a/echo", method="GET",
                           response_body=f"{token}".encode())
        await TaintCorrelatorPlugin().on_entry(entry, store)
        assert store.findings == []

    async def test_no_body_no_crash(self):
        store = _FakeStore(taint_store=TaintStore())
        entry = _FakeEntry(id="e1", url="https://a/x", method="GET", response_body=None)
        await TaintCorrelatorPlugin().on_entry(entry, store)
        assert store.findings == []
