"""Unit tests for the Header OOB Scanner plugin — no network, fake OOB session."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from dast.plugins import header_oob_scanner as plugin_module
from dast.plugins.header_oob_scanner import HeaderOobScannerPlugin, build_finding, load_header_specs
from dast.scanners.oob_correlator import OobHit, OobInjection, looks_like_static_cdn_origin

_CORR = "abcdefghijklmnopqrst0123456789abc"


def _injection(reflected: bool = False, cdn_static_origin: bool = False) -> OobInjection:
    return OobInjection(
        marker="frmarker000001", entry_id="e1", url="https://t.test/a", method="GET",
        location="header", name="Referer", value=f"http://frmarker000001.{_CORR}.oast.test/",
        sent_at=0.0, reflected=reflected, cdn_static_origin=cdn_static_origin,
    )


def test_header_list_is_loaded_and_never_touches_host():
    specs = load_header_specs()
    names = {name.lower() for name, _ in specs}
    assert len(specs) >= 10
    assert "host" not in names
    assert all("{{OOB_HOST}}" in template for _, template in specs)


def test_http_callback_is_confirmed_blind_ssrf_high():
    finding = build_finding(OobHit(_injection(), "http", {"remote-address": "198.51.100.4"}))
    assert finding["severity"] == "high"
    assert finding["confirmed"] is True
    assert finding["parameter"] == "Referer"
    assert finding["validated_by"] == ["oob_callback"]


def test_dns_only_callback_is_confirmed_medium():
    finding = build_finding(OobHit(_injection(), "dns", {"remote-address": "8.8.8.8"}))
    assert finding["severity"] == "medium"
    assert finding["confirmed"] is True


def test_reflected_value_is_held_for_review():
    finding = build_finding(OobHit(_injection(reflected=True), "http", {}))
    assert finding["confirmed"] is False
    assert finding["needs_review"] is True


def test_cdn_static_origin_http_callback_is_held_for_review():
    # CDN/edge static origin + HTTP callback + not reflected -> NOT a confirmed SSRF.
    finding = build_finding(
        OobHit(_injection(cdn_static_origin=True), "http", {"remote-address": "198.51.100.4"})
    )
    assert finding["severity"] == "info"
    assert finding["confirmed"] is False
    assert finding["needs_review"] is True
    assert finding["confidence"] == 0.3
    assert "CDN" in finding["title"] or "edge" in str(finding.get("reasoning", ""))


def test_dynamic_origin_http_callback_stays_confirmed_high():
    # No CDN signal on the probe response -> genuine confirmed blind SSRF.
    finding = build_finding(
        OobHit(_injection(cdn_static_origin=False), "http", {"remote-address": "198.51.100.4"})
    )
    assert finding["severity"] == "high"
    assert finding["confirmed"] is True
    assert finding["needs_review"] is False


def test_cdn_static_origin_does_not_downgrade_dns_callback():
    # The CDN guard only applies to HTTP/HTTPS callbacks; DNS keeps its own rules.
    finding = build_finding(
        OobHit(_injection(cdn_static_origin=True), "dns", {"remote-address": "8.8.8.8"})
    )
    assert finding["severity"] == "medium"
    assert finding["confirmed"] is True


def test_reflected_takes_precedence_over_cdn_downgrade():
    # Reflected path is left intact even when the CDN signal is also present.
    finding = build_finding(
        OobHit(_injection(reflected=True, cdn_static_origin=True), "http", {})
    )
    assert finding["confirmed"] is False
    assert finding["confidence"] == 0.5


@pytest.mark.parametrize(
    "headers, expected",
    [
        ({"Server": "AmazonS3"}, True),
        ({"Server": "cloudflare"}, True),
        ({"server": "Google Frontend"}, True),
        ({"Via": "1.1 abc.cloudfront.net (CloudFront)"}, True),
        ({"X-Amz-Cf-Id": "abc", "X-Cache": "Hit from cloudfront"}, True),
        ({"Server": "nginx", "Content-Type": "text/html"}, False),
        ({"Server": "gunicorn/20.1.0"}, False),
        ({}, False),
        (None, False),
    ],
)
def test_looks_like_static_cdn_origin(headers, expected):
    assert looks_like_static_cdn_origin(headers) is expected


class _FakeSession:
    url = f"http://{_CORR}.oast.test"

    def __init__(self) -> None:
        self.batches: List[List[Dict[str, Any]]] = []

    async def register(self) -> bool:
        return True

    def marker_host(self, marker: str) -> str:
        return f"{marker}.{_CORR}.oast.test"

    async def fetch_interactions(self) -> List[Dict[str, Any]]:
        return self.batches.pop(0) if self.batches else []

    async def deregister(self) -> None:
        return None


class _FakeClient:
    def __init__(self, body: str = "ok") -> None:
        self.requests: List[Dict[str, Any]] = []
        self._body = body

    async def request(self, method: str, url: str, headers: Dict[str, str], content: Any = None):
        self.requests.append({"method": method, "url": url, "headers": dict(headers)})
        return SimpleNamespace(status_code=200, text=self._body)


class _FakeStore:
    def __init__(self) -> None:
        self.findings: List[tuple] = []

    def add_finding(self, entry_id: str, finding: dict, scan_result: str) -> None:
        self.findings.append((entry_id, finding, scan_result))


def _entry() -> SimpleNamespace:
    return SimpleNamespace(
        id="e1", method="GET", url="https://t.test/a?q=1", host="t.test",
        request_headers={"Host": "t.test", "Cookie": "s=1", "Referer": "https://t.test/"},
        request_body=None,
    )


def _plugin(session: _FakeSession) -> HeaderOobScannerPlugin:
    plugin = HeaderOobScannerPlugin()
    plugin._correlator._session_factory = lambda: session
    plugin._correlator._register_display = lambda url: None
    plugin._correlator._linger_seconds = 0  # no background poll loop in tests
    return plugin


@pytest.mark.asyncio
async def test_probe_injects_a_distinct_marker_per_header_and_attributes_the_hit():
    session, client, store = _FakeSession(), _FakeClient(), _FakeStore()
    plugin = _plugin(session)

    await plugin.on_active_probe(_entry(), store, client)

    assert len(client.requests) == 1
    sent = client.requests[0]["headers"]
    assert sent["Cookie"] == "s=1"                 # original context replayed
    assert "Host" not in sent                      # routing header never replayed/injected
    assert sent["x-dast-source"] == "agent"     # skipped by auto-scan / observers
    injected = [sent[name] for name, _ in load_header_specs()]
    markers = [value.split(_CORR)[0] for value in injected]
    assert len(set(markers)) == len(markers)       # one unique marker per header

    referer_marker = sent["Referer"].split("//")[1].split(".")[0]
    session.batches.append([{"protocol": "dns", "full-id": f"{referer_marker}.{_CORR}",
                             "remote-address": "203.0.113.9"}])
    assert await plugin._correlator.poll_once() == 1

    entry_id, finding, scan_result = store.findings[0]
    assert entry_id == "e1"
    assert finding["parameter"] == "Referer"
    assert finding["confirmed"] is True
    assert scan_result == "vulnerable"


@pytest.mark.asyncio
async def test_same_endpoint_is_probed_once():
    session, client, store = _FakeSession(), _FakeClient(), _FakeStore()
    plugin = _plugin(session)
    await plugin.on_active_probe(_entry(), store, client)
    await plugin.on_active_probe(_entry(), store, client)
    assert len(client.requests) == 1


@pytest.mark.asyncio
async def test_reflected_marker_marks_injection_for_review():
    session, store = _FakeSession(), _FakeStore()
    plugin = _plugin(session)
    echo = _FakeClient()

    async def _echo_request(method, url, headers, content=None):
        echo.requests.append({"headers": dict(headers)})
        return SimpleNamespace(status_code=200, text=f"<a href=\"{headers['Referer']}\">back</a>")

    echo.request = _echo_request
    await plugin.on_active_probe(_entry(), store, echo)

    referer_marker = echo.requests[0]["headers"]["Referer"].split("//")[1].split(".")[0]
    session.batches.append([{"protocol": "http", "full-id": f"{referer_marker}.{_CORR}"}])
    await plugin._correlator.poll_once()

    assert store.findings[0][1]["needs_review"] is True


@pytest.mark.asyncio
async def test_cdn_static_origin_probe_holds_callback_for_review():
    # A probe response served by a CDN/static origin + an HTTP callback must be
    # held for review, not reported as a confirmed high blind SSRF.
    session, store = _FakeSession(), _FakeStore()
    plugin = _plugin(session)
    cdn = _FakeClient()

    async def _cdn_request(method, url, headers, content=None):
        cdn.requests.append({"headers": dict(headers)})
        return SimpleNamespace(
            status_code=200,
            text="static content",
            headers={"Server": "AmazonS3", "x-amz-cf-id": "edge", "Via": "1.1 cloudfront"},
        )

    cdn.request = _cdn_request
    await plugin.on_active_probe(_entry(), store, cdn)

    referer_marker = cdn.requests[0]["headers"]["Referer"].split("//")[1].split(".")[0]
    session.batches.append([{"protocol": "http", "full-id": f"{referer_marker}.{_CORR}",
                             "remote-address": "198.51.100.4"}])
    await plugin._correlator.poll_once()

    finding = store.findings[0][1]
    assert finding["confirmed"] is False
    assert finding["needs_review"] is True
    assert finding["severity"] == "info"


@pytest.mark.asyncio
async def test_no_probe_when_oob_server_unreachable(monkeypatch):
    class _Down(_FakeSession):
        async def register(self) -> bool:
            return False

    client, store = _FakeClient(), _FakeStore()
    plugin = _plugin(_Down())
    await plugin.on_active_probe(_entry(), store, client)
    assert client.requests == []
    assert plugin_module._PLUGIN_NAME == "Header OOB Scanner"
