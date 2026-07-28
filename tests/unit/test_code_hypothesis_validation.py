"""
Unit tests for the code-hypothesis validation fixes:
  - Bug 3: resolved host is validated before a scan entry is created, so a
    placeholder like "<sentry-admin-platform-host>" is rejected instead of
    queueing a scan that can only fail with DNS errors.
  - Bug 1: hypothesis validation entries set skip_dedup so each hypothesis
    actually runs (two hypotheses on the same endpoint must both be tested).
"""

from __future__ import annotations

import pytest

from dast.proxy.api.code_routes import _is_valid_host


class TestIsValidHost:
    @pytest.mark.parametrize("host", [
        "example.com",
        "api-od-console-keycloak.staging.acme-corp.dev",
        "localhost:8080",
        "sub.domain.co.uk:443",
        "192.168.1.1",
        "single-label",
    ])
    def test_valid_hosts(self, host):
        assert _is_valid_host(host) is True

    @pytest.mark.parametrize("host", [
        "<sentry-admin-platform-host>",   # the exact placeholder from the bug report
        "{domain}",
        "has space.com",
        "",
        "host\twith\ttab",
        "<host>",
        "a<b",
    ])
    def test_invalid_hosts(self, host):
        assert _is_valid_host(host) is False


class TestHypothesisEntriesSkipDedup:
    """Bug 1: synthetic entries created for hypothesis validation must bypass the
    scan-worker dedup so distinct hypotheses on the same endpoint all run."""

    def test_proxy_entry_supports_skip_dedup(self):
        # The fix relies on ProxyEntry carrying a skip_dedup flag the scan worker
        # honours; guard that the field exists and defaults to False.
        from dast.proxy.session_store import ProxyEntry
        e = ProxyEntry(
            id="syn-x", method="GET", url="https://h/p", host="h", path="/p",
            request_headers={}, request_body=None, source="imported",
        )
        assert e.skip_dedup is False
        e.skip_dedup = True
        assert e.skip_dedup is True
