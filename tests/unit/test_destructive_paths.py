"""Unit tests for the shared session-destructive path matcher.

Locks in: the last path segment is matched with or without a file extension
(classic apps expose /logout.php), and the CLI crawler and proxy scan adapter
both refuse such paths.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from dast.proxy.check_target_adapter import _entry_to_check_target
from dast.scanners.crawler import CrawlerWorker
from dast.utils.destructive_paths import destructive_segment


@pytest.mark.parametrize("url, expected", [
    ("http://127.0.0.1:8081/logout.php", "logout"),
    ("https://app.example.com/auth/logout", "logout"),
    ("https://app.example.com/api/v1/sign-out/", "sign-out"),
    ("https://app.example.com/Account/SignOut.aspx?returnUrl=/", "signout"),
    ("/users/delete-account", "delete-account"),
    ("/logout?next=/home", "logout"),
])
def test_destructive_paths_are_detected(url: str, expected: str) -> None:
    assert destructive_segment(url) == expected


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8081/login.php",
    "http://127.0.0.1:8081/vulnerabilities/fi/?page=include.php",
    "https://app.example.com/logout-help/faq",
    "https://app.example.com/docs/logout.html.en/intro",
])
def test_regular_paths_are_not_destructive(url: str) -> None:
    assert destructive_segment(url) is None


def _crawler() -> CrawlerWorker:
    # _clean_url only needs the origin; skip the browser-bound constructor.
    crawler = CrawlerWorker.__new__(CrawlerWorker)
    crawler._origin = "127.0.0.1:8081"
    return crawler


def test_crawler_does_not_follow_logout_links() -> None:
    crawler = _crawler()

    assert crawler._clean_url("http://127.0.0.1:8081/logout.php") is None
    assert crawler._clean_url("http://127.0.0.1:8081/vulnerabilities/sqli/") == (
        "http://127.0.0.1:8081/vulnerabilities/sqli/"
    )


def test_crawler_skips_download_links() -> None:
    crawler = _crawler()

    assert crawler._clean_url("http://127.0.0.1:8081/docs/DVWA_v1.3.pdf") is None


def test_scan_adapter_skips_logout_with_extension() -> None:
    entry = SimpleNamespace(
        id="e1", method="GET", url="http://127.0.0.1:8081/logout.php?x=1", path="/logout.php",
        host="127.0.0.1:8081", request_headers={}, request_body=None, response_status=200,
        response_headers={}, response_body=b"", content_type="text/html", source="proxy",
    )

    assert _entry_to_check_target(entry) is None
