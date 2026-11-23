"""HAR 1.2 export tests (3-I): dast/proxy/har_export.py + the download route.

Pure-generator tests cover the ARTEX contract: stable (ts, id) ordering,
explicit placeholders (timings -1 / time 0 / empty cookies+cache), multi
Set-Cookie pairs, base64 for non-UTF-8 bodies, mimeType propagation, userinfo
redaction, hard caps with never-silent truncation reporting.
"""

from __future__ import annotations

import asyncio
import base64
import json
from types import SimpleNamespace

from dast.proxy.har_export import entries_to_har, truncation_headers


def _entry(eid="e1", ts=1000.0, method="GET", url="https://app.example.com/x?a=1",
           req_headers=None, req_body=None, status=200, resp_headers=None,
           resp_body=b"hello", host="app.example.com", path="/x"):
    return SimpleNamespace(
        id=eid, ts=ts, method=method, url=url, host=host, path=path,
        request_headers=req_headers or {}, request_body=req_body,
        response_status=status, response_headers=resp_headers or {},
        response_body=resp_body, content_type="application/json",
        duration_ms=1.0,
    )


def _log(entries, **kw):
    log, trunc = entries_to_har(entries, **kw)
    return log["log"], trunc


# ── shape ────────────────────────────────────────────────────────────────────

def test_log_shape_and_stable_order():
    e2 = _entry("e2", ts=1001.0, url="https://a.com/2", path="/2")
    e1 = _entry("e1", ts=1000.0)
    e0 = _entry("e0", ts=1000.0)  # same ts → id breaks the tie deterministically
    inner, trunc = _log([e2, e1, e0])
    assert inner["version"] == "1.2"
    assert inner["creator"]["name"]
    assert [e["_dastEntryId"] for e in inner["entries"]] == ["e0", "e1", "e2"]
    assert trunc == {"entries": False, "bytes": False}


def test_explicit_placeholders_nothing_invented():
    inner, _ = _log([_entry()])
    (entry,) = inner["entries"]
    assert entry["time"] == 0
    assert entry["cache"] == {}
    assert entry["timings"] == {"send": -1, "wait": -1, "receive": -1}
    assert entry["request"]["cookies"] == []
    assert entry["response"]["cookies"] == []
    assert entry["request"]["headersSize"] == -1
    assert entry["response"]["redirectURL"] == ""


def test_started_datetime_is_rfc3339_utc():
    inner, _ = _log([_entry(ts=1000.0)])
    (entry,) = inner["entries"]
    assert entry["startedDateTime"].startswith("1970-01-01T00:16:40")
    assert entry["startedDateTime"].endswith("Z")


def test_querystring_and_multi_set_cookie():
    e = _entry(req_headers={"content-type": "application/json"},
               resp_headers={"set-cookie": ["a=1", "b=2"], "x-one": "1"})
    doc, _ = entries_to_har([e])
    inner = doc["log"]
    entry = inner["entries"][0]
    assert entry["request"]["queryString"] == [{"name": "a", "value": "1"}]
    resp_cookies = [h for h in entry["response"]["headers"]
                    if h["name"] == "set-cookie"]
    assert [c["value"] for c in resp_cookies] == ["a=1", "b=2"]


def test_post_data_mime_and_text():
    e = _entry(method="POST", url="https://a.com/x",
               req_headers={"content-type": "application/json"},
               req_body=b'{"k": "v"}')
    inner, _ = _log([e])
    (entry,) = inner["entries"]
    pd = entry["request"]["postData"]
    assert pd["mimeType"] == "application/json"
    assert pd["text"] == '{"k": "v"}'


def test_binary_body_is_base64_with_encoding():
    e = _entry(resp_body=b"\x00\xff\xfe", resp_headers={"content-type": "application/octet-stream"})
    doc, _ = entries_to_har([e])
    inner = doc["log"]
    content = inner["entries"][0]["response"]["content"]
    assert content["encoding"] == "base64"
    assert base64.b64decode(content["text"]) == b"\x00\xff\xfe"


def test_userinfo_is_redacted_from_url():
    e = _entry(url="https://user:secret@app.example.com/x")
    doc, _ = entries_to_har([e])
    inner = doc["log"]
    assert "secret" not in json.dumps(inner)
    assert "app.example.com/x" in inner["entries"][0]["request"]["url"]


def test_incomplete_entries_are_skipped():
    pending = _entry("pending", status=None)
    done = _entry("done", status=200)
    doc, _ = entries_to_har([pending, done])
    inner = doc["log"]
    assert [e["_dastEntryId"] for e in inner["entries"]] == ["done"]


# ── caps with never-silent truncation ────────────────────────────────────────

def test_entries_cap_truncates_loudly(monkeypatch):
    import dast.proxy.har_export as hx
    monkeypatch.setattr(hx, "_MAX_ENTRIES", 2)
    entries = [_entry(f"e{i}", ts=1000.0 + i) for i in range(5)]
    doc, trunc = entries_to_har(entries)
    inner = doc["log"]
    assert len(inner["entries"]) == 2
    assert trunc["entries"] is True
    assert inner["_truncated"] is True
    assert inner["_truncatedReason"] == "max_entries"
    assert inner["_totalMatched"] == 5


def test_bytes_cap_truncates_loudly():
    big = _entry("big", ts=1000.0, resp_body=b"x" * (700 * 1024))
    small1 = _entry("s1", ts=1001.0, resp_body=b"a" * (700 * 1024))
    small2 = _entry("s2", ts=1002.0, resp_body=b"b" * 10)
    doc, trunc = entries_to_har([big, small1, small2], max_raw_bytes=1024 * 1024)
    inner = doc["log"]
    ids = [e["_dastEntryId"] for e in inner["entries"]]
    assert ids[0] == "big"  # stable order kept
    assert len(ids) < 3 and trunc["bytes"] is True
    assert inner["_truncatedReason"] == "max_bytes"
    assert inner["_totalMatched"] == 3


def test_truncation_headers_only_when_truncated():
    clean = truncation_headers({"entries": False, "bytes": False}, 3, 3)
    assert "X-DAST-HAR-Truncated" not in clean
    assert clean["X-DAST-HAR-Exported"] == "3"
    cut = truncation_headers({"entries": True, "bytes": True}, 2, 9)
    assert cut["X-DAST-HAR-Truncated"] == "true"
    assert cut["X-DAST-HAR-Truncated-Reason"] == "max_entries"
    assert cut["X-DAST-HAR-Matched"] == "9"


# ── download route ───────────────────────────────────────────────────────────

class TestHarRoute:
    def test_route_downloads_har(self):
        from fastapi.testclient import TestClient

        from dast.proxy.dashboard_server import build_app
        from dast.proxy.session_store import SessionStore

        store = SessionStore()
        eid = store.new_entry("GET", "https://example.com/page?q=1",
                              {"content-type": "text/html"}, None)
        store.complete_entry(eid, status=200, response_headers={"content-type": "text/html"},
                             response_body=b"hi", duration_ms=1.0)
        app = build_app(store=store, scan_queue=asyncio.Queue())
        with TestClient(app, base_url="http://127.0.0.1") as c:
            resp = c.get("/api/history/export/har")

        assert resp.status_code == 200
        assert "attachment" in resp.headers["content-disposition"]
        assert resp.headers["X-DAST-HAR-Exported"] == "1"
        log = json.loads(resp.content)
        assert log["log"]["version"] == "1.2"
        (entry,) = log["log"]["entries"]
        assert entry["request"]["url"] == "https://example.com/page?q=1"

    def test_route_empty_history_is_valid_har(self):
        from fastapi.testclient import TestClient

        from dast.proxy.dashboard_server import build_app
        from dast.proxy.session_store import SessionStore

        app = build_app(store=SessionStore(), scan_queue=asyncio.Queue())
        with TestClient(app, base_url="http://127.0.0.1") as c:
            resp = c.get("/api/history/export/har")
        log = json.loads(resp.content)
        assert log["log"]["entries"] == []
        assert "X-DAST-HAR-Truncated" not in resp.headers
