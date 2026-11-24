"""HAR import tests (4-C): dast/proxy/har_import.py + POST /api/history/import/har.

Contract (ARTEX-adapted): 1.2-only, ≤2000 entries, per-entry errors never
fatal (≤50 details), cookies arrays synthesize wire headers, postData.params
rebuild urlencoded bodies, deterministic har-<sha256> keys, userinfo redacted,
imported entries never carry match&replace (they are plain history rows).
"""

from __future__ import annotations

import base64
import json

import pytest

from dast.proxy.har_import import har_key, import_har, import_har_incremental


def _har(entries, version="1.2"):
    return {"log": {"version": version, "creator": {"name": "t", "version": "1"},
                    "entries": entries}}


def _entry(url="https://app.example.com/api/x", status=200, method="GET",
           req_body=None, resp_text="hi", resp_headers=None):
    entry = {
        "startedDateTime": "2026-11-23T12:00:00Z",
        "request": {"method": method, "url": url,
                    "headers": [{"name": "content-type", "value": "application/json"}],
                    "cookies": [], "queryString": []},
        "response": {"status": status,
                     "headers": resp_headers or [{"name": "content-type",
                                                 "value": "text/html"}],
                     "cookies": [],
                     "content": {"size": len(resp_text), "mimeType": "text/html",
                                 "text": resp_text}},
    }
    if req_body is not None:
        entry["request"]["postData"] = {"mimeType": "application/json", "text": req_body}
    return entry


# ── parsing ──────────────────────────────────────────────────────────────────

def test_basic_import_and_shape():
    payloads, stats = import_har(_har([_entry()]))
    assert stats["imported"] == 1 and stats["failed"] == 0
    (p,) = payloads
    assert p["method"] == "GET" and p["url"] == "https://app.example.com/api/x"
    assert p["response_status"] == 200
    assert p["response_body"] == b"hi"
    assert p["request_headers"]["content-type"] == "application/json"
    assert p["har_key"].startswith("har-")


def test_non_har_and_bad_version_raise():
    with pytest.raises(ValueError):
        import_har({"log": {"version": "1.1", "entries": []}})
    with pytest.raises(ValueError):
        import_har({"nope": True})


def test_large_file_paginates_instead_of_erroring():
    # 4-C: >2000 entries no longer 400s — the first call imports the first
    # page and reports next_offset for the follow-up call.
    entries = [_entry(f"https://a.com/{i}") for i in range(2500)]
    doc = _har(entries)
    payloads, stats = import_har(doc)
    assert len(payloads) == 2000
    assert stats["next_offset"] == 2000
    payloads2, stats2 = import_har(doc, offset=stats["next_offset"])
    assert len(payloads2) == 500
    assert stats2["next_offset"] is None
    # no overlap between pages
    assert {p["har_key"] for p in payloads}.isdisjoint({p["har_key"] for p in payloads2})


def test_per_entry_errors_never_abort():
    ok = _entry("https://a.com/good")
    bad = _entry("not-a-url")   # missing scheme → per-entry failure
    payloads, stats = import_har(_har([bad, ok, bad]))
    assert stats["imported"] == 1 and stats["failed"] == 2
    assert stats["errors"] and len(stats["errors"]) <= 50


def test_cookies_arrays_synthesize_wire_headers():
    e = _entry(resp_headers=[])
    e["request"]["cookies"] = [{"name": "sid", "value": "1"}]
    e["response"]["cookies"] = [{"name": "c1", "value": "v1"}]
    payloads, _ = import_har(_har([e]))
    (p,) = payloads
    assert p["request_headers"]["cookie"] == "sid=1"
    assert p["response_headers"]["set-cookie"] == ["c1=v1"]


def test_postdata_params_rebuild_urlencoded_body():
    e = _entry(method="POST")
    e["request"]["postData"] = {"mimeType": "application/x-www-form-urlencoded",
                                "params": [{"name": "a", "value": "1"},
                                           {"name": "b", "value": "x y"}],
                                "text": ""}
    payloads, _ = import_har(_har([e]))
    (p,) = payloads
    assert p["request_body"] == b"a=1&b=x%20y"


def test_base64_content_decoded():
    e = _entry(resp_text=base64.b64encode(b"\x00\x01bin").decode())
    e["response"]["content"]["encoding"] = "base64"
    payloads, _ = import_har(_har([e]))
    (p,) = payloads
    assert p["response_body"] == b"\x00\x01bin"


def test_userinfo_redacted():
    e = _entry(url="https://user:pw@app.example.com/x")
    payloads, _ = import_har(_har([e]))
    (p,) = payloads
    assert "pw" not in p["url"]


def test_deterministic_keys_and_stable_roundtrip():
    e = _entry()
    k1 = har_key("GET", "https://a.com/x", 200, b"", b"hi", "t")
    k2 = har_key("GET", "https://a.com/x", 200, b"", b"hi", "t")
    assert k1 == k2
    payloads1, _ = import_har(_har([e]))
    payloads2, _ = import_har(_har([e]))
    assert payloads1[0]["har_key"] == payloads2[0]["har_key"]


# ── streaming import ──────────────────────────────────────────────────────────

def test_incremental_import_streams_all_entries_in_order():
    # Guards the O(n^2)->O(n) raw_decode(text, idx) change: many entries must
    # still import completely, in order, across page boundaries.
    entries = [_entry(f"https://a.com/{i}") for i in range(1500)]
    raw = json.dumps(_har(entries)).encode("utf-8")

    urls = []
    last_stats = None
    for payloads, stats in import_har_incremental(raw, page=400):
        urls.extend(p["url"] for p in payloads)
        last_stats = stats

    assert len(urls) == 1500
    assert urls == [f"https://a.com/{i}" for i in range(1500)]
    assert last_stats["done"] is True  # final (partial) page carries done
    assert last_stats["truncated"] is False
    assert last_stats["total_entries"] == 1500


# ── route ────────────────────────────────────────────────────────────────────

class TestHarImportRoute:
    def test_route_imports_into_history(self):
        import asyncio

        from fastapi.testclient import TestClient

        from dast.proxy.dashboard_server import build_app
        from dast.proxy.session_store import SessionStore

        store = SessionStore()
        app = build_app(store=store, scan_queue=asyncio.Queue())
        with TestClient(app, base_url="http://127.0.0.1") as c:
            resp = c.post("/api/history/import/har",
                          content=json.dumps(_har([_entry()])),
                          headers={"content-type": "application/json"})
        assert resp.status_code == 200
        assert resp.json()["imported"] == 1
        entries = store.all_entries()
        assert len(entries) == 1
        assert entries[0].source == "imported"

    def test_route_bad_version_returns_400(self):
        import asyncio

        from fastapi.testclient import TestClient

        from dast.proxy.dashboard_server import build_app
        from dast.proxy.session_store import SessionStore

        app = build_app(store=SessionStore(), scan_queue=asyncio.Queue())
        with TestClient(app, base_url="http://127.0.0.1") as c:
            resp = c.post("/api/history/import/har",
                          content=json.dumps(_har([], version="1.1")))
        assert resp.status_code == 400

    def test_route_invalid_json_returns_400(self):
        import asyncio

        from fastapi.testclient import TestClient

        from dast.proxy.dashboard_server import build_app
        from dast.proxy.session_store import SessionStore

        app = build_app(store=SessionStore(), scan_queue=asyncio.Queue())
        with TestClient(app, base_url="http://127.0.0.1") as c:
            resp = c.post("/api/history/import/har", content=b"{oops")
        assert resp.status_code == 400


def test_route_offset_paginates_imports():
    """?offset skips the first N entries of the doc — the >=2k file imports in
    repeated calls (the 2500-entry page math is covered by the pure test)."""
    import asyncio

    from fastapi.testclient import TestClient

    from dast.proxy.dashboard_server import build_app
    from dast.proxy.session_store import SessionStore

    doc = _har([_entry(f"https://a.com/{i}") for i in range(30)])
    store = SessionStore()
    app = build_app(store=store, scan_queue=asyncio.Queue())
    with TestClient(app, base_url="http://127.0.0.1") as c:
        r1 = c.post("/api/history/import/har?offset=20",
                    content=json.dumps(doc), headers={"content-type": "application/json"})
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["imported"] == 10
        assert d1["next_offset"] is None
        assert d1["total_entries"] == 30

        entries = store.all_entries()
        assert len(entries) == 10
        assert len({e.import_key for e in entries if e.import_key}) == 10
