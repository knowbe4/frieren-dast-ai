"""Cache deception agent tests (4-A): the three-step dance with a scripted
authed/anon transport. Confirmed iff victim markers survive the anonymous
re-read of a cacheable, path-mapped variant."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import dast.agents  # noqa: F401 — populates the Coordinator registry
import pytest

from dast.scanners.active_checks import CheckTarget

_AUTHED = {"cookie": "sid=victim-session"}
_MARK = "AKIAIOSFODNN7EXAMPLEKEY"


def _target(url="https://app.example.com/my-account"):
    return CheckTarget(method="GET", url=url, headers=_AUTHED, body=None, params=[])


def _r(status=200, body="ok", url="https://app.example.com/my-account"):
    return SimpleNamespace(
        status_code=status, text=body, headers={}, content=body.encode(),
        request=SimpleNamespace(method="GET", url=url, headers={}, content=b""),
    )


@pytest.fixture(autouse=True)
def _fresh_registry():
    from dast.ai import provider_health

    provider_health.reset()
    yield
    provider_health.reset()


def _install(monkeypatch, script):
    """script(url, headers) -> (status, body). The ANON re-read is scripted
    separately (monkeypatches httpx.AsyncClient used by _anon_fetch)."""
    import dast.agents.cache_deception_agent as mod

    async def fake_send(client, method, url, headers, body, **kw):
        status, text = script(url, dict(headers))
        return _r(status, text, url=url)

    monkeypatch.setattr(mod, "_send", fake_send)


def _install_anon(monkeypatch, anon_body_by_url):

    class _FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, url, headers=None, content=None):
            body = anon_body_by_url.get(url) or (
                f"cached: {_MARK}" if "wcd" in url else "public page")
            return SimpleNamespace(status_code=200, text=body, headers={},
                                   content=body.encode())

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)


def test_unauthed_target_is_skipped():
    from dast.agents.cache_deception_agent import CacheDeceptionAgent

    t = CheckTarget(method="GET", url="https://app.example.com/", headers={}, body=None,
                    params=[])
    findings = asyncio_run(CacheDeceptionAgent().run(t, MagicMock(), None))
    assert findings == []


def test_confirmed_when_markers_survive_anonymous(monkeypatch):
    from dast.agents.cache_deception_agent import CacheDeceptionAgent

    # markers auto-derive from the authed-vs-anon diff of the BASE url
    def script(url, headers):
        cookie = headers.get("cookie")
        if "wcd" in url:
            return 200, f"account page with {_MARK} and more"
        if cookie:
            return 200, f"victim page: {_MARK}"
        return 200, "public page"

    _install(monkeypatch, script)
    _install_anon(monkeypatch, {
        # baseline anon: no marker (so the diff derives one)
        "https://app.example.com/my-account": "public page",
        # the SECOND variant (first static-ext .js) is cacheable and leaks
    })
    # make the cacheable signal fire: second authed fetch shows HIT
    real_script = script

    def script2(url, headers):
        status, text = real_script(url, headers)
        if "wcd" in url:
            return 200, f"account page with {_MARK} (x-cache hit)"
        return status, text

    # simpler: monkeypatch _cacheable_signal to report cacheable
    import dast.agents.cache_deception_agent as mod
    monkeypatch.setattr(mod, "_cacheable_signal",
                        lambda c1, c2: (True, "X-Cache HIT (forced by test)"))

    findings = asyncio_run(CacheDeceptionAgent().run(_target(), MagicMock(), None))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-525"
    assert findings[0].severity == "critical"
    assert findings[0].confirmed is True
    assert "redacted" in findings[0].evidence  # the leaked key is never stored raw


def test_not_path_mapped_never_confirms(monkeypatch):
    from dast.agents.cache_deception_agent import CacheDeceptionAgent

    def script(url, headers):
        # origin does NOT path-map: variants return the public page
        if "wcd" in url:
            return 404, "public page"
        return 200, f"victim page: {_MARK}"

    _install(monkeypatch, script)
    findings = asyncio_run(CacheDeceptionAgent().run(_target(), MagicMock(), None))
    assert findings == []


def asyncio_run(coro):
    import asyncio
    return asyncio.run(coro)
