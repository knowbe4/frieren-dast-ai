"""Unit tests for the deterministic ``web_cache_deception_probe`` tool.

A fake origin+cache models web cache deception: the origin path-maps a crafted static-looking URL
(e.g. /my-account/wcd.js) back to the authenticated handler and returns the victim's private body
with ``Cache-Control: public``; the cache stores that body and serves it to a later ANONYMOUS
request for the same URL. The probe must confirm the leak and record a finding with the secret
redacted. Negatives: a ``no-store`` variant and a variant whose anonymous response lacks the victim
markers must NOT confirm (and must not record). Marker auto-derivation is covered too.
"""

from __future__ import annotations

import pytest

from dast.tools import web_cache_deception_tools as wcd


# ── Shared fakes ─────────────────────────────────────────────────────────────

class _FakeResp:
    def __init__(self, text: str, status: int = 200, headers=None):
        self.text = text
        self.status_code = status
        # Lowercased keys; the probe only reads via .get(lower).
        self.headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}


class _FakeStore:
    def __init__(self):
        self.recorded = []

    def get_cookies_for_host(self, host):
        return [{"name": "session", "value": "sess-val"}]

    def record_manual_finding(self, finding, url, method="GET"):
        self.recorded.append((finding, url, method))
        return "entry-wcd-1"


class _FakeCtx:
    def __init__(self, store):
        self.store = store
        self.source_label = "copilot"
        self.proxy_port = 8080

    @property
    def proxy_url(self):
        return "http://127.0.0.1:8080"

    def is_in_scope(self, url):
        return True


SECRET = "testapikeytestapikeytest1"  # 25 alnum (low-entropy synthetic fixture) -> matches the API-key regex
AUTHED_BODY = f"<html>Log out | My account. Your API Key: {SECRET}</html>"
ANON_BODY = "<html>Please log in to continue.</html>"


def _is_authed(headers) -> bool:
    """A request is authenticated iff it still carries the Cookie the authed pass attaches."""
    return any(k.lower() == "cookie" for k in (headers or {}))


# ── variant generation ───────────────────────────────────────────────────────

def test_wcd_variants_emits_expected_set():
    variants = wcd._wcd_variants("https://host.example.com/my-account")
    urls = [v["url"] for v in variants]
    techs = [v["technique"] for v in variants]

    # 6 static-ext + 6 delimiters + trailing-slash + encoded-dot-segment = 14
    assert len(variants) == 14
    for ext in wcd._WCD_STATIC_EXTS:
        assert f"https://host.example.com/my-account/wcd{ext}" in urls
        assert f"static-ext:{ext}" in techs
    for delim in wcd._WCD_DELIMS:
        assert f"https://host.example.com/my-account{delim}wcd.css" in urls
        assert f"path-delimiter:{delim}" in techs
    assert "https://host.example.com/my-account/" in urls
    assert "trailing-slash" in techs
    assert "https://host.example.com/my-account/%2e%2e%2fwcd.js" in urls
    assert "encoded-dot-segment" in techs
    # Scheme/host/query preserved; delimiters kept verbatim (not re-encoded).
    q = [v["url"] for v in wcd._wcd_variants("https://h/acct?x=1") if v["technique"] == "static-ext:.js"][0]
    assert q == "https://h/acct/wcd.js?x=1"


# ── confirmation ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_confirms_and_records_with_secret_redacted(monkeypatch):
    import httpx

    # The one vulnerable, cacheable variant.
    target = "https://host.example.com/my-account/wcd.js"

    class _OriginCache:
        """Origin path-maps /my-account/wcd.js -> authed handler (public cache-control); the cache
        stores the authed body the first time and replays it to an anonymous request."""
        def __init__(self, *a, **k):
            self.store = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            if url.rstrip("/").endswith("/my-account") or url == "https://host.example.com/my-account":
                return _FakeResp(AUTHED_BODY if _is_authed(headers) else ANON_BODY, 200,
                                 {"cache-control": "private"})
            if url == target:
                if _is_authed(headers):
                    # Origin serves the private body; cache stores it under the crafted key.
                    xc = "HIT" if url in self.store else "MISS"
                    self.store[url] = AUTHED_BODY
                    return _FakeResp(AUTHED_BODY, 200,
                                     {"cache-control": "public, max-age=60", "x-cache": xc})
                # Anonymous request -> cache replays the stored private body.
                if url in self.store:
                    return _FakeResp(self.store[url], 200, {"cache-control": "public", "x-cache": "HIT"})
                return _FakeResp(ANON_BODY, 200, {"cache-control": "public"})
            # Any other crafted variant: origin does NOT path-map back -> anonymous-looking body.
            return _FakeResp(ANON_BODY, 404, {"cache-control": "public"})

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _OriginCache())

    store = _FakeStore()
    result = await wcd._web_cache_deception_probe(_FakeCtx(store), {
        "url": "https://host.example.com/my-account",
    })

    assert result["ok"] is True
    assert result["confirmed"] is True
    assert result["variant"] == target
    assert result["technique"] == "static-ext:.js"
    # Finding recorded, CWE-525, HIGH, via the store API, attached to the WINNING variant url.
    assert store.recorded
    finding, rec_url, _ = store.recorded[0]
    assert rec_url == target
    assert finding["cwe"] == "CWE-525"
    assert finding["severity"] == "high"
    assert finding["attack_type"] == "web_cache_deception"
    assert finding["validated_by"] == ["web_cache_deception_probe"]
    assert finding["source"] == "copilot"
    # The actual secret is REDACTED everywhere in the recorded evidence.
    blob = repr(finding)
    assert SECRET not in blob
    assert "<redacted:len=25>" in blob


# ── negative: no-store variant is not cacheable ────────────────────────────────

@pytest.mark.asyncio
async def test_no_store_variant_not_confirmed(monkeypatch):
    import httpx

    class _NoStoreOrigin:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            # Origin always path-maps back to the authed body when authenticated, but every
            # response is Cache-Control: no-store, so NOTHING is cacheable and nothing confirms.
            body = AUTHED_BODY if _is_authed(headers) else ANON_BODY
            return _FakeResp(body, 200, {"cache-control": "no-store"})

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _NoStoreOrigin())

    store = _FakeStore()
    result = await wcd._web_cache_deception_probe(_FakeCtx(store), {
        "url": "https://host.example.com/my-account",
    })
    assert result["ok"] is True
    assert result["confirmed"] is False
    assert result["variant"] is None
    assert not store.recorded
    # Every marker-bearing variant was evaluated and rejected on the cache signal.
    assert any(s.get("cacheable") is False for s in result["steps"])


# ── negative: unauth response lacks the victim markers ─────────────────────────

@pytest.mark.asyncio
async def test_unauth_without_markers_not_confirmed(monkeypatch):
    import httpx

    target = "https://host.example.com/my-account/wcd.js"

    class _NoCacheReplay:
        """Cacheable + path-maps back for the AUTHED fetch, but the cache does NOT actually serve
        the private body anonymously (anon gets the public login page) -> must NOT confirm."""
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            if url == target:
                if _is_authed(headers):
                    return _FakeResp(AUTHED_BODY, 200, {"cache-control": "public", "x-cache": "HIT"})
                return _FakeResp(ANON_BODY, 200, {"cache-control": "public", "x-cache": "MISS"})
            body = AUTHED_BODY if _is_authed(headers) else ANON_BODY
            return _FakeResp(body, 200, {"cache-control": "private"})

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _NoCacheReplay())

    store = _FakeStore()
    result = await wcd._web_cache_deception_probe(_FakeCtx(store), {
        "url": "https://host.example.com/my-account",
    })
    assert result["ok"] is True
    assert result["confirmed"] is False
    assert not store.recorded
    # The variant reached the UNAUTH pass (candidate) but the markers did not leak.
    leak_steps = [s for s in result["steps"] if s.get("variant") == target]
    assert leak_steps and leak_steps[0].get("cacheable") is True
    assert leak_steps[0].get("confirmed") is False


# ── marker auto-derivation ─────────────────────────────────────────────────────

def test_marker_auto_derivation():
    markers = wcd._derive_markers(AUTHED_BODY, ANON_BODY)
    # The high-entropy secret present only in the authed body is derived.
    assert SECRET in markers
    # Account/session keywords unique to the authed body are derived.
    assert any("api key" == m or "log out" == m or "my account" == m for m in markers)
    # A token present in BOTH bodies is not a marker.
    assert SECRET not in wcd._derive_markers(f"x {SECRET}", f"y {SECRET}")


def test_redact_hides_secret():
    red = wcd._redact(f"key={SECRET} end")
    assert SECRET not in red
    assert "<redacted:len=25>" in red
