"""
Unit tests for ``upload_to_presigned_url`` (dast/tools/upload_tools.py) and its
narrow session-scope exemption (CopilotSession._scope_gate).

The tool PUTs raw bytes to a presigned storage URL. Three things must hold:
  (a) SSRF guard — the PUT is allowed ONLY when the URL's exact host+path was
      observed in an IN-SCOPE response body; a fabricated/unobserved host is denied
      and nothing is sent.
  (b) binary round-trip — the base64 body decodes to the EXACT bytes handed to the
      proxy-routed httpx client, with no UTF-8 corruption.
  (c) no session auth — the PUT carries no Cookie/CSRF/Bearer/Authorization header
      (presigned URLs are SigV4-signed; any extra header breaks the signature and
      leaks app auth cross-origin).

A fake httpx.AsyncClient captures exactly what the tool sends (and the client's
construction kwargs, so we can assert it routes through ctx.proxy_url).
"""

from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional

import pytest

from dast.tools import upload_tools as ut


# ── Fakes ──────────────────────────────────────────────────────────────────────

class _FakeEntry:
    """Minimal ProxyEntry stand-in — only id + response_body + source are read."""

    def __init__(self, response_body: Optional[bytes], source: str = "proxy",
                 id: str = "e1") -> None:
        self.id = id
        self.response_body = response_body
        self.source = source


class _FakeStore:
    def __init__(self, entries: List[_FakeEntry]) -> None:
        self._entries = entries

    def in_scope_entries(self) -> List[_FakeEntry]:
        # Mirror the real store: out-of-scope entries are excluded.
        return [e for e in self._entries if e.source != "out-of-scope"]

    def get_entry(self, entry_id: str) -> Optional[_FakeEntry]:
        # Mirror the real store: get_entry returns the entry regardless of scope
        # (scope is enforced separately by the tool).
        for e in self._entries:
            if e.id == entry_id:
                return e
        return None


class _FakeCtx:
    def __init__(self, store: Any, read_only: bool = False) -> None:
        self.store = store
        self.source_label = "copilot"
        self.proxy_port = 8080
        self.read_only = read_only

    @property
    def proxy_url(self) -> str:
        return "http://127.0.0.1:8080"


class _FakeResp:
    def __init__(self, text: str, status: int, headers: Dict[str, str]) -> None:
        self.text = text
        self.status_code = status
        self.headers = {str(k): str(v) for k, v in headers.items()}
        self.url = "https://storage.example.com/key"


def _capture_client(holder: Dict[str, Any]):
    """An httpx.AsyncClient replacement that records its construction kwargs and the
    single request it is asked to send, then returns a canned 200."""

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            holder["init_kwargs"] = kwargs

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

        async def request(self, method: str, url: str, headers=None, content=None):
            holder["method"] = method
            holder["url"] = url
            holder["headers"] = dict(headers) if headers else {}
            holder["content"] = content
            return _FakeResp("", 200, {"ETag": '"deadbeef"'})

    return _Client


# The upload URL and the two forms a response body can carry it in.
_UPLOAD_URL = ("https://persona-assets-xyz.s3.amazonaws.com/uploads/abc123"
               "?X-Amz-Signature=sig&X-Amz-Expires=900")
_BODY_WITH_URL = (
    '{"data":{"createPersonaAsset":{"uploadUrl":'
    '"https://persona-assets-xyz.s3.amazonaws.com/uploads/abc123'
    '?X-Amz-Signature=sig&X-Amz-Expires=900"}}}'
)
# Same URL but JSON-escaped forward slashes, as some encoders emit.
_BODY_WITH_URL_ESCAPED = (
    '{"uploadUrl":"https:\\/\\/persona-assets-xyz.s3.amazonaws.com\\/uploads\\/abc123'
    '?X-Amz-Signature=sig"}'
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# ── (a) SSRF guard ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_allows_when_host_path_observed_in_scope(monkeypatch):
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"))])
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"url": _UPLOAD_URL, "body_base64": _b64(b"hello")})

    assert result["ok"] is True
    assert result["status"] == 200
    assert holder["method"] == "PUT"          # the PUT actually went out
    assert holder["url"] == _UPLOAD_URL


@pytest.mark.asyncio
async def test_allows_when_observed_with_escaped_slashes(monkeypatch):
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    store = _FakeStore([_FakeEntry(_BODY_WITH_URL_ESCAPED.encode("utf-8"))])
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"url": _UPLOAD_URL, "body_base64": _b64(b"x")})

    assert result["ok"] is True
    assert holder.get("method") == "PUT"


@pytest.mark.asyncio
async def test_denies_when_host_path_not_observed(monkeypatch):
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    # A different (fabricated) host+path than anything in the store.
    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"))])
    evil = "https://attacker-controlled.s3.amazonaws.com/uploads/abc123?X-Amz-Signature=sig"
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"url": evil, "body_base64": _b64(b"hello")})

    assert result["ok"] is False
    assert "not observed" in result["error"]
    assert holder == {}  # nothing was sent


@pytest.mark.asyncio
async def test_denies_same_host_but_different_path(monkeypatch):
    # The SSRF boundary is host+PATH, not host alone: the attacker cannot borrow a
    # legitimately-observed bucket host to PUT to an arbitrary key.
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"))])
    other_key = ("https://persona-assets-xyz.s3.amazonaws.com/uploads/victim-key"
                 "?X-Amz-Signature=sig")
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"url": other_key, "body_base64": _b64(b"hello")})

    assert result["ok"] is False
    assert holder == {}


@pytest.mark.asyncio
async def test_denies_when_only_out_of_scope_entry_has_url(monkeypatch):
    # An out-of-scope entry must NOT satisfy the guard (in_scope_entries excludes it).
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"), source="out-of-scope")])
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"url": _UPLOAD_URL, "body_base64": _b64(b"hello")})

    assert result["ok"] is False
    assert holder == {}


@pytest.mark.asyncio
async def test_denies_when_no_store(monkeypatch):
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    result = await ut._upload_to_presigned_url(
        _FakeCtx(store=None), {"url": _UPLOAD_URL, "body_base64": _b64(b"hello")})

    assert result["ok"] is False
    assert holder == {}


# ── (b) binary round-trip ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_binary_body_round_trips_exact_bytes(monkeypatch):
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    # Bytes that are NOT valid UTF-8 (0x80, 0xFF, a PNG header, NULs) — exactly the
    # content a naive text path would corrupt.
    blob = bytes([0x89, 0x50, 0x4E, 0x47, 0x00, 0x80, 0xFF, 0xFE, 0x01, 0x02, 0x00, 0xC3])
    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"))])

    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"url": _UPLOAD_URL, "body_base64": _b64(blob)})

    assert result["ok"] is True
    assert result["bytes_sent"] == len(blob)
    # The bytes handed to httpx (which then streams them through the proxy) are exactly
    # the decoded blob — raw bytes, not a lossy str.
    assert holder["content"] == blob
    assert isinstance(holder["content"], (bytes, bytearray))
    # Routed through the proxy so it lands in history.
    assert holder["init_kwargs"].get("proxy") == "http://127.0.0.1:8080"


@pytest.mark.asyncio
async def test_rejects_invalid_base64(monkeypatch):
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"))])
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"url": _UPLOAD_URL, "body_base64": "!!!not base64!!!"})

    assert result["ok"] is False
    assert "base64" in result["error"]
    assert holder == {}


# ── (c) no session auth ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_session_auth_attached(monkeypatch):
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"))])
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"url": _UPLOAD_URL, "body_base64": _b64(b"hello"),
                          "content_type": "image/png"})

    assert result["ok"] is True
    sent = {k.lower() for k in holder["headers"]}
    for forbidden in ("cookie", "authorization", "x-csrf-token", "x-xsrf-token",
                      "x-auth-token", "x-api-key"):
        assert forbidden not in sent, f"{forbidden} must never be attached to a presigned PUT"
    # Only the signed Content-Type and the history source tag are present.
    assert holder["headers"].get("Content-Type") == "image/png"
    assert holder["headers"].get("x-dast-source") == "copilot"


@pytest.mark.asyncio
async def test_no_content_type_when_not_supplied(monkeypatch):
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"))])
    await ut._upload_to_presigned_url(
        _FakeCtx(store), {"url": _UPLOAD_URL, "body_base64": _b64(b"hello")})

    assert "Content-Type" not in holder["headers"]


@pytest.mark.asyncio
async def test_read_only_blocks_put(monkeypatch):
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"))])
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store, read_only=True),
        {"url": _UPLOAD_URL, "body_base64": _b64(b"hello")})

    assert result["ok"] is False
    assert result.get("read_only") is True
    assert holder == {}


# ── (d) by-reference resolution (source_entry_id) ────────────────────────────────

@pytest.mark.asyncio
async def test_by_reference_happy_path(monkeypatch):
    # The model passes the entry id of the in-scope createPersonaAsset response; the
    # tool reads that stored body, extracts uploadUrl at the default json_path, and PUTs.
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"), id="E42")])
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"source_entry_id": "E42", "body_base64": _b64(b"hello")})

    assert result["ok"] is True
    assert result["status"] == 200
    assert holder["method"] == "PUT"
    # The tool resolved the FULL url from the stored response — the model never passed it.
    assert holder["url"] == _UPLOAD_URL


@pytest.mark.asyncio
async def test_by_reference_entry_not_found(monkeypatch):
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"), id="E42")])
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"source_entry_id": "does-not-exist", "body_base64": _b64(b"hi")})

    assert result["ok"] is False
    assert "not found" in result["error"]
    assert holder == {}  # nothing was sent


@pytest.mark.asyncio
async def test_by_reference_entry_out_of_scope(monkeypatch):
    # The source entry itself must be in scope — an out-of-scope entry is refused.
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"),
                                   source="out-of-scope", id="E42")])
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"source_entry_id": "E42", "body_base64": _b64(b"hi")})

    assert result["ok"] is False
    assert "out of scope" in result["error"]
    assert holder == {}


@pytest.mark.asyncio
async def test_by_reference_json_path_missing(monkeypatch):
    # A json_path that points at nothing in the stored body gives a clear error.
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"), id="E42")])
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"source_entry_id": "E42",
                          "url_json_path": "data.nope.missing",
                          "body_base64": _b64(b"hi")})

    assert result["ok"] is False
    assert "data.nope.missing" in result["error"]
    assert holder == {}


@pytest.mark.asyncio
async def test_by_reference_value_not_a_url(monkeypatch):
    # The value at the json_path exists but is not an absolute http(s) URL.
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    body = '{"data":{"createPersonaAsset":{"uploadUrl":"/relative/not/absolute"}}}'
    store = _FakeStore([_FakeEntry(body.encode("utf-8"), id="E42")])
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"source_entry_id": "E42", "body_base64": _b64(b"hi")})

    assert result["ok"] is False
    assert "absolute http(s) URL" in result["error"]
    assert holder == {}


@pytest.mark.asyncio
async def test_by_reference_value_not_a_string(monkeypatch):
    # The value at the json_path is present but not a string (e.g. a dict).
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    body = '{"data":{"createPersonaAsset":{"uploadUrl":{"nested":"x"}}}}'
    store = _FakeStore([_FakeEntry(body.encode("utf-8"), id="E42")])
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"source_entry_id": "E42", "body_base64": _b64(b"hi")})

    assert result["ok"] is False
    assert "not a string URL" in result["error"]
    assert holder == {}


@pytest.mark.asyncio
async def test_by_reference_custom_json_path(monkeypatch):
    # A caller-supplied url_json_path is honored.
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    body = ('{"data":{"makeUpload":{"put":'
            '"https://persona-assets-xyz.s3.amazonaws.com/uploads/abc123?X-Amz-Signature=sig"}}}')
    store = _FakeStore([_FakeEntry(body.encode("utf-8"), id="E7")])
    result = await ut._upload_to_presigned_url(
        _FakeCtx(store), {"source_entry_id": "E7",
                          "url_json_path": "data.makeUpload.put",
                          "body_base64": _b64(b"hi")})

    assert result["ok"] is True
    assert holder["method"] == "PUT"


@pytest.mark.asyncio
async def test_requires_exactly_one_of_url_or_source_entry_id(monkeypatch):
    import httpx
    holder: Dict[str, Any] = {}
    monkeypatch.setattr(httpx, "AsyncClient", _capture_client(holder))

    store = _FakeStore([_FakeEntry(_BODY_WITH_URL.encode("utf-8"), id="E42")])
    # Neither supplied.
    r1 = await ut._upload_to_presigned_url(_FakeCtx(store), {"body_base64": _b64(b"hi")})
    assert r1["ok"] is False and "required" in r1["error"]
    # Both supplied.
    r2 = await ut._upload_to_presigned_url(
        _FakeCtx(store),
        {"url": _UPLOAD_URL, "source_entry_id": "E42", "body_base64": _b64(b"hi")})
    assert r2["ok"] is False and "not both" in r2["error"]
    assert holder == {}  # nothing was sent in either case


# ── scope-gate exemption (and non-regression of the generic deny) ─────────────────

class _ScopeCtx:
    """Minimal tool_ctx for a direct _scope_gate call."""

    def __init__(self, in_scope: bool) -> None:
        self._in_scope = in_scope
        self.approved_hosts: set = set()

    def is_in_scope(self, url: str) -> bool:
        return self._in_scope


async def _deny_human(kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {"decision": "deny"}


@pytest.mark.asyncio
async def test_scope_gate_exempts_upload_tool():
    from dast.ai.copilot.session import CopilotSession

    session = CopilotSession("s-upload")
    ctx = _ScopeCtx(in_scope=False)  # storage host is intentionally out of scope

    async def _observe(entry, obs):  # pragma: no cover - not reached on allow
        return None

    denial = await session._scope_gate(
        "upload_to_presigned_url",
        {"url": "https://persona-assets-xyz.s3.amazonaws.com/uploads/abc?X-Amz-Signature=s"},
        ctx, set(), {}, _deny_human, _observe,
    )
    assert denial is None  # exempt: the tool's own observed-URL check is the authority


@pytest.mark.asyncio
async def test_scope_gate_still_denies_other_tools():
    # The exemption must NOT weaken the generic out-of-scope deny for other tools.
    from dast.ai.copilot.session import CopilotSession

    session = CopilotSession("s-send")
    ctx = _ScopeCtx(in_scope=False)

    async def _observe(entry, obs):  # pragma: no cover
        return None

    denial = await session._scope_gate(
        "send_request", {"url": "https://evil.example.com/x"},
        ctx, set(), {}, _deny_human, _observe,
    )
    assert denial is not None
    assert "Denied" in denial
