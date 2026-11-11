"""Unit tests for dast.tools.extract_tools.extract_response — the server-side response extractor
that lets the copilot read fields/arrays out of a FULL captured body (which the turn observation
only previews). Generic placeholder data only."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from dast.tools.extract_tools import _extract_response


def _entry(eid: str, url: str, body):
    raw = body if isinstance(body, bytes) else str(body).encode("utf-8")
    return SimpleNamespace(id=eid, url=url, host="app.example.com", path="/p", response_body=raw)


class _Store:
    def __init__(self, entries):
        self._e = list(entries)

    def get_entry(self, eid):
        return next((e for e in self._e if e.id == eid), None)

    def entries_newest_first(self):
        return list(reversed(self._e))

    def all_entries(self):
        return list(self._e)


def _ctx(store, in_scope: bool = True):
    return SimpleNamespace(store=store, is_in_scope=lambda u: in_scope,
                           dashboard_base_url="http://127.0.0.1:8088")


_URL = "https://app.example.com/api/items"


@pytest.mark.asyncio
async def test_path_array_map_enumerates_all():
    body = json.dumps({"store_items": [{"uuid": "a"}, {"uuid": "b"}, {"uuid": "c"}]})
    ctx = _ctx(_Store([_entry("e1", _URL, body)]))
    r = await _extract_response(ctx, {"url": _URL, "path": "store_items[].uuid"})
    assert r["ok"] and r["total"] == 3 and r["values"] == ["a", "b", "c"] and r["truncated"] is False


@pytest.mark.asyncio
async def test_path_nested_scalar():
    body = json.dumps({"user": {"attributes": {"svcJwt": "TOKEN-VALUE"}}})
    ctx = _ctx(_Store([_entry("e1", _URL, body)]))
    r = await _extract_response(ctx, {"url": _URL, "path": "user.attributes.svcJwt"})
    assert r["ok"] and r["total"] == 1 and r["values"] == ["TOKEN-VALUE"]


@pytest.mark.asyncio
async def test_pagination_offset_limit():
    body = json.dumps({"items": [{"x": i} for i in range(5)]})
    ctx = _ctx(_Store([_entry("e1", _URL, body)]))
    r = await _extract_response(ctx, {"url": _URL, "path": "items[].x", "offset": 1, "limit": 2})
    assert r["total"] == 5 and r["count"] == 2 and r["offset"] == 1 and r["truncated"] is True
    assert r["values"] == ["1", "2"]


@pytest.mark.asyncio
async def test_huge_array_is_capped():
    body = json.dumps({"items": [{"x": i} for i in range(500)]})
    ctx = _ctx(_Store([_entry("e1", _URL, body)]))
    r = await _extract_response(ctx, {"url": _URL, "path": "items[].x"})  # default limit 100
    assert r["total"] == 500 and r["count"] == 100 and r["truncated"] is True


@pytest.mark.asyncio
async def test_regex_on_non_json():
    ctx = _ctx(_Store([_entry("e1", _URL, "a=1&b=2&c=33")]))
    r = await _extract_response(ctx, {"url": _URL, "regex": r"(\w+)=\d+"})
    assert r["ok"] and r["values"] == ["a", "b", "c"]


@pytest.mark.asyncio
async def test_summary_when_no_path_or_regex():
    body = json.dumps([{"uuid": "a", "name": "x"}, {"uuid": "b", "name": "y"}])
    ctx = _ctx(_Store([_entry("e1", _URL, body)]))
    r = await _extract_response(ctx, {"url": _URL})
    assert r["ok"] and r["kind"] == "array" and r["length"] == 2
    assert r["element_keys"] == ["name", "uuid"]


@pytest.mark.asyncio
async def test_resolve_by_entry_id():
    body = json.dumps({"k": [1, 2]})
    ctx = _ctx(_Store([_entry("ex", _URL, body)]))
    r = await _extract_response(ctx, {"entry_id": "ex", "path": "k[]"})
    assert r["ok"] and r["values"] == ["1", "2"]


@pytest.mark.asyncio
async def test_latest_matching_url_wins():
    old = _entry("old", _URL, json.dumps({"k": ["old"]}))
    new = _entry("new", _URL, json.dumps({"k": ["new"]}))
    ctx = _ctx(_Store([old, new]))  # newest_first reverses -> new first
    r = await _extract_response(ctx, {"url": _URL, "path": "k[]"})
    assert r["values"] == ["new"]


@pytest.mark.asyncio
async def test_out_of_scope_refused():
    ctx = _ctx(_Store([_entry("e1", _URL, "{}")]), in_scope=False)
    r = await _extract_response(ctx, {"url": _URL, "path": "a"})
    assert r["ok"] is False and "out of scope" in r["error"]


@pytest.mark.asyncio
async def test_missing_entry():
    ctx = _ctx(_Store([]))
    r = await _extract_response(ctx, {"url": _URL, "path": "a"})
    assert r["ok"] is False and "no captured response" in r["error"]


@pytest.mark.asyncio
async def test_path_on_non_json_body_errors():
    ctx = _ctx(_Store([_entry("e1", _URL, "not json at all")]))
    r = await _extract_response(ctx, {"url": _URL, "path": "a.b"})
    assert r["ok"] is False and "not JSON" in r["error"]


@pytest.mark.asyncio
async def test_requires_url_or_entry_id():
    ctx = _ctx(_Store([_entry("e1", _URL, "{}")]))
    r = await _extract_response(ctx, {"path": "a"})
    assert r["ok"] is False and "url or entry_id" in r["error"]
