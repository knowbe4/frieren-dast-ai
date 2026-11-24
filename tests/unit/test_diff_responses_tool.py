"""Unit tests for the diff_responses tool (5-A-4).

The system prompt asks the copilot to 'compare the two bodies' — this tool makes
that comparison deterministic: status, key headers, body length and capped
line-level added/removed between two real proxy-history entries.
"""

from __future__ import annotations

import asyncio

from dast.proxy.session_store import SessionStore
from dast.tools import http_tools
from dast.tools.context import ToolContext


def _ctx(store: SessionStore) -> ToolContext:
    ctx = ToolContext(store=store)
    ctx.is_in_scope = lambda url: True  # type: ignore[method-assign]
    return ctx


def _capture(store: SessionStore, url: str, status: int, headers: dict,
             body: bytes, method: str = "GET"):
    entry_id = store.new_entry(method, url, {}, None)
    entry = store.get_entry(entry_id)
    entry.response_status = status
    entry.response_headers = headers
    entry.response_body = body
    return entry_id


def test_diff_reports_status_header_and_line_changes():
    store = SessionStore()
    id_a = _capture(store, "https://shop.test/api/users/42", 200,
                    {"content-type": "application/json"},
                    b'{"user": "me", "email": "me@shop.test"}\n')
    id_b = _capture(store, "https://shop.test/api/users/43", 403,
                    {"content-type": "application/json"},
                    b'{"error": "forbidden"}\n')
    out = asyncio.run(http_tools._diff_responses(_ctx(store), {
        "entry_id_a": id_a, "entry_id_b": id_b}))

    assert out["ok"] is True
    assert out["status_changed"] == [200, 403]
    assert out["body_length"] != out["body_length"][1:]  # lengths differ
    assert out["body_lines_removed_count"] >= 1          # the user line went away
    assert any("email" in ln for ln in out["body_lines_removed"])
    assert any("forbidden" in ln for ln in out["body_lines_added"])


def test_diff_reports_key_header_change_and_identical_verdict():
    store = SessionStore()
    id_a = _capture(store, "https://shop.test/a", 200,
                    {"content-type": "text/html", "www-authenticate": ""}, b"hello\n")
    id_b = _capture(store, "https://shop.test/b", 200,
                    {"content-type": "text/html", "www-authenticate": "Bearer"}, b"hello\n")
    out = asyncio.run(http_tools._diff_responses(_ctx(store), {
        "entry_id_a": id_a, "entry_id_b": id_b}))
    assert out["ok"] is True
    assert out["status_changed"] is None
    assert out["headers_changed"]["www-authenticate"] == ["", "Bearer"]

    # Identical responses → the explicit verdict, no noise fields.
    id_c = _capture(store, "https://shop.test/c", 200,
                    {"content-type": "text/html"}, b"hello\n")
    id_d = _capture(store, "https://shop.test/d", 200,
                    {"content-type": "text/html"}, b"hello\n")
    same = asyncio.run(http_tools._diff_responses(_ctx(store), {
        "entry_id_a": id_c, "entry_id_b": id_d}))
    assert "structurally identical" in same["verdict"]
    assert "headers_changed" not in same


def test_diff_rejects_unknown_and_missing_store():
    store = SessionStore()
    out = asyncio.run(http_tools._diff_responses(_ctx(store), {
        "entry_id_a": "nope", "entry_id_b": "nada"}))
    assert out["ok"] is False
    assert "entry not found" in out["error"]

    bare = ToolContext(store=None)
    out = asyncio.run(http_tools._diff_responses(bare, {
        "entry_id_a": "a", "entry_id_b": "b"}))
    assert out["ok"] is False
    assert "in-process store" in out["error"]


def test_diff_line_caps_keep_the_result_bounded():
    store = SessionStore()
    body_a = "\n".join(f"line-{i}" for i in range(60)).encode()
    body_b = "\n".join(f"renamed-{i}" for i in range(60)).encode()
    id_a = _capture(store, "https://shop.test/list", 200, {}, body_a)
    id_b = _capture(store, "https://shop.test/list", 200, {}, body_b)
    out = asyncio.run(http_tools._diff_responses(_ctx(store), {
        "entry_id_a": id_a, "entry_id_b": id_b}))
    assert out["ok"] is True
    assert out["body_lines_added_count"] == 60      # true scale reported
    assert len(out["body_lines_added"]) == 8        # but only the first 8 lines
    assert all(len(ln) <= 200 for ln in out["body_lines_added"])
