"""Unit tests for operator-driven browser-open target validation.

The "Open Browser" auth-pause action must permit local DAST targets (DVWA on
127.0.0.1, private-network apps) — the operator is opening the target they are
already scanning, not making a server-side request. Only non-http(s) schemes and
host-less URLs are rejected. Regression for the reported bug where "Open Browser"
returned "No valid public URL to open" for 127.0.0.1.
"""

from __future__ import annotations

import pytest

from dast.proxy.api.browse_targets import is_openable_target_url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8081/login.php",  # DVWA local lab — the reported case
        "http://localhost:3000/",
        "http://192.168.1.10/app",
        "https://example.com/login",
        "https://app.example.com:8443/x?y=1",
    ],
)
def test_openable_targets(url):
    assert is_openable_target_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "",  # empty
        "file:///etc/passwd",  # non-http scheme
        "javascript:alert(1)",  # non-http scheme
        "data:text/html,<h1>x</h1>",  # non-http scheme
        "ftp://example.com/f",  # non-http scheme
        "http://",  # no host
        "https:///path-only",  # no host
    ],
)
def test_rejected_targets(url):
    assert is_openable_target_url(url) is False
