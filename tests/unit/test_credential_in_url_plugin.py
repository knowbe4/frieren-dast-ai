"""Unit tests for the credential-in-URL passive plugin.

The plugin flags passwords/tokens/API keys in query strings — a real
misconfiguration when it happens in genuine traffic. The regression these tests
lock in: the scanner's own param-mining probes inject synthetic `token=`,
`password=`, `api_key=` parameters, and the plugin must NOT flag those
(self-inflicted false positive that wastes a developer's time — the CLAUDE.md
bar). The real request is still analysed; only scanner-synthesized entries skip.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import List, Tuple

import pytest

from dast.plugins.credential_in_url import CredentialInUrlPlugin, _SYNTHETIC_SOURCES


class _Store:
    """Captures add_finding calls."""

    def __init__(self) -> None:
        self.findings: List[Tuple[str, dict, str]] = []

    def add_finding(self, entry_id: str, finding: dict, status: str) -> None:
        self.findings.append((entry_id, finding, status))


def _entry(url: str, source: str = "proxy") -> SimpleNamespace:
    return SimpleNamespace(id="e1", url=url, source=source)


def _run(entry: SimpleNamespace) -> _Store:
    store = _Store()
    asyncio.run(CredentialInUrlPlugin().on_entry(entry, store))
    return store


# Inert low-entropy placeholder value (>= _MIN_VALUE_LEN) — a stand-in for a
# credential, not a real one, so secret scanners do not trip on the fixtures.
_PLACEHOLDER = "xxxxxxxxxxxx"


def test_flags_real_credential_in_query():
    store = _run(_entry(f"http://app.example.com/cb?token={_PLACEHOLDER}"))
    assert len(store.findings) == 1
    _, finding, status = store.findings[0]
    assert finding["attack_type"] == "credential-in-url"
    assert status == "vulnerable"
    assert f"token={_PLACEHOLDER}" in finding["evidence"]


def test_ignores_param_mining_probe():
    # The exact FP seen on DVWA: param-mining appended token=/password= canaries.
    url = (f"http://127.0.0.1:8081/vulnerabilities/fi/?page=include.php"
           f"&token={_PLACEHOLDER}&password={_PLACEHOLDER}")
    assert _run(_entry(url, source="param-mining")).findings == []


@pytest.mark.parametrize("source", sorted(_SYNTHETIC_SOURCES))
def test_all_synthetic_sources_are_skipped(source):
    url = f"http://app.example.com/x?access_token={_PLACEHOLDER}"
    assert _run(_entry(url, source=source)).findings == []


def test_non_sensitive_params_are_not_flagged():
    assert _run(_entry("http://app.example.com/x?page=include.php&id=42")).findings == []


def test_short_values_are_not_flagged():
    # Below _MIN_VALUE_LEN — placeholder/empty, not a real secret.
    assert _run(_entry("http://app.example.com/x?token=abc")).findings == []
