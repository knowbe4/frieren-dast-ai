"""
Unit tests for dast.proxy.auth_headers.extract_auth_headers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

from dast.proxy.auth_headers import extract_auth_headers


@dataclass
class _FakeEntry:
    host: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    source: str = "proxy"


def test_no_host_scans_globally():
    entries = [
        _FakeEntry(host="a.example.com", request_headers={"Authorization": "Bearer a"}),
        _FakeEntry(host="b.example.com", request_headers={}),
    ]
    # Reverse-chronological: caller controls order; most-recent-first here is entries[0].
    result = extract_auth_headers(entries, host=None)
    assert result == {"Authorization": "Bearer a"}


def test_exact_host_match():
    entries = [
        _FakeEntry(host="other.com", request_headers={"Cookie": "session=xyz"}),
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer b"}),
    ]
    result = extract_auth_headers(entries, host="example.com")
    assert result == {"Authorization": "Bearer b"}


def test_subdomain_match_when_enabled():
    entries = [
        _FakeEntry(host="sub.example.com", request_headers={"Authorization": "Bearer sub"}),
    ]
    result = extract_auth_headers(entries, host="example.com", include_subdomains=True)
    assert result == {"Authorization": "Bearer sub"}


def test_subdomain_non_match_when_disabled():
    entries = [
        _FakeEntry(host="sub.example.com", request_headers={"Authorization": "Bearer sub"}),
    ]
    result = extract_auth_headers(entries, host="example.com", include_subdomains=False)
    assert result == {}


def test_unrelated_host_does_not_match():
    entries = [
        _FakeEntry(host="totally-different.net", request_headers={"Authorization": "Bearer x"}),
    ]
    result = extract_auth_headers(entries, host="example.com")
    assert result == {}


def test_source_exclusion_skips_synthetic_entries():
    entries = [
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer synthetic"}, source="agent"),
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer real"}, source="proxy"),
    ]
    result = extract_auth_headers(entries, host="example.com", exclude_sources=("agent", "imported"))
    assert result == {"Authorization": "Bearer real"}


def test_source_exclusion_disabled_allows_any_source():
    entries = [
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer synthetic"}, source="agent"),
    ]
    result = extract_auth_headers(entries, host="example.com", exclude_sources=())
    assert result == {"Authorization": "Bearer synthetic"}


def test_limit_truncates_scanned_entries():
    entries = [
        _FakeEntry(host="example.com", request_headers={}),
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer too-old"}),
    ]
    result = extract_auth_headers(entries, host="example.com", limit=1)
    assert result == {}


def test_no_matching_entries_returns_empty_dict():
    entries = [
        _FakeEntry(host="example.com", request_headers={"X-Custom": "not-auth-related"}),
    ]
    result = extract_auth_headers(entries, host="example.com")
    assert result == {}


def test_stops_at_first_matching_entry_with_headers():
    entries = [
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer newest"}),
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer older"}),
    ]
    result = extract_auth_headers(entries, host="example.com")
    assert result == {"Authorization": "Bearer newest"}
