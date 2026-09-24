"""Unit tests for the API-version-detector passive plugin.

The plugin flags when two or more versions of the same base endpoint appear in
traffic (an older version may lack controls added later). The regression these
tests lock in: it must emit that finding ONCE per (host, base, version-pair),
not on every subsequent request to a versioned path. Before the fix a single
run produced dozens of identical medium findings (the CLAUDE.md FP bar: a false
positive that wastes a developer's time is a failure).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import List, Tuple

import pytest

import dast.plugins.api_version_detector as mod
from dast.plugins.api_version_detector import ApiVersionDetectorPlugin


class _Store:
    """Captures add_finding calls."""

    def __init__(self) -> None:
        self.findings: List[Tuple[str, dict, str]] = []

    def add_finding(self, entry_id: str, finding: dict, status: str) -> None:
        self.findings.append((entry_id, finding, status))


def _entry(
    path: str,
    host: str = "api.example.com",
    entry_id: str = "e1",
    source: str = "proxy",
    response_status: int = 200,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=entry_id,
        host=host,
        path=path,
        source=source,
        response_status=response_status,
    )


@pytest.fixture(autouse=True)
def _reset_module_state():
    # The plugin tracks seen/flagged state in module globals for process lifetime;
    # isolate each test.
    mod._seen.clear()
    mod._flagged.clear()
    yield
    mod._seen.clear()
    mod._flagged.clear()


def _feed(store: _Store, plugin: ApiVersionDetectorPlugin, *entries: SimpleNamespace) -> None:
    for entry in entries:
        asyncio.run(plugin.on_entry(entry, store))


def test_single_version_does_not_flag():
    store = _Store()
    _feed(store, ApiVersionDetectorPlugin(), _entry("/users/v1/list"))
    assert store.findings == []


def test_two_versions_flag_once():
    store = _Store()
    _feed(store, ApiVersionDetectorPlugin(),
          _entry("/users/v1/list"), _entry("/users/v2/list"))
    assert len(store.findings) == 1
    _, finding, _status = store.findings[0]
    assert finding["title"] == "Multiple API Versions Active: v1 and v2"
    assert finding["severity"] == "medium"
    assert finding["attack_type"] == "api-version"


def test_repeated_requests_do_not_re_emit():
    # The exact bug seen live against VAmPI: the same two versions hit many times
    # produced one identical medium finding per request.
    store = _Store()
    plugin = ApiVersionDetectorPlugin()
    entries: List[SimpleNamespace] = []
    for _ in range(20):
        entries.append(_entry("/users/v1/list"))
        entries.append(_entry("/users/v2/list"))
    _feed(store, plugin, *entries)
    assert len(store.findings) == 1  # not 40


def test_new_version_emits_new_pair_once():
    store = _Store()
    _feed(store, ApiVersionDetectorPlugin(),
          _entry("/users/v1/list"),
          _entry("/users/v2/list"),   # -> v1 and v2
          _entry("/users/v3/list"),   # -> v1 and v3
          _entry("/users/v3/list"))   # repeat, no new finding
    titles = [f["title"] for _, f, _ in store.findings]
    assert titles == [
        "Multiple API Versions Active: v1 and v2",
        "Multiple API Versions Active: v1 and v3",
    ]


def test_distinct_hosts_flag_separately():
    store = _Store()
    _feed(store, ApiVersionDetectorPlugin(),
          _entry("/users/v1/x", host="a.example.com"),
          _entry("/users/v2/x", host="a.example.com"),
          _entry("/users/v1/x", host="b.example.com"),
          _entry("/users/v2/x", host="b.example.com"))
    assert len(store.findings) == 2


def test_synthetic_source_is_ignored():
    # The live FP against VAmPI: content-discovery fuzzed /v1/graphiql, /v2/altair,
    # etc., so distinct probe paths looked like many concurrent API versions.
    # Scanner-synthesized traffic must not count as evidence of a live version.
    store = _Store()
    _feed(store, ApiVersionDetectorPlugin(),
          _entry("/v1/graphiql", source="content-discovery"),
          _entry("/v2/graphiql", source="content-discovery"))
    assert store.findings == []


def test_not_found_paths_are_ignored():
    # A 404 does not prove a version exists — a wordlist hit on /v1/x and /v2/x
    # that both 404 must not be reported as multiple active versions.
    store = _Store()
    _feed(store, ApiVersionDetectorPlugin(),
          _entry("/users/v1/x", response_status=404),
          _entry("/users/v2/x", response_status=404))
    assert store.findings == []


def test_genuine_traffic_still_flags_after_guards():
    # Guardrails must not suppress real traffic: genuine 200s on two versions
    # still emit exactly one finding.
    store = _Store()
    _feed(store, ApiVersionDetectorPlugin(),
          _entry("/users/v1/list", source="browse", response_status=200),
          _entry("/users/v2/list", source="crawler", response_status=200))
    assert len(store.findings) == 1
