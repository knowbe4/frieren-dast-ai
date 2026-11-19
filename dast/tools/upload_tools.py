"""
upload_to_presigned_url — PUT raw bytes to a presigned upload URL.

A presigned upload URL (e.g. the ``uploadUrl`` an in-scope ``createPersonaAsset``
mutation returns, pointing at ``*.s3.amazonaws.com``) is SigV4 signature-authed:
the signature covers a FIXED set of headers, so ANY extra header we inject (a
session Cookie, a CSRF token, a Bearer) both breaks the signature
(``SignatureDoesNotMatch``) AND leaks the app's auth to a cross-origin storage
host. ``send_request`` / ``browser_fetch`` force-attach that session auth and are
string-body only, so they are the wrong transport here. This tool keeps the
clean, no-auth, binary path isolated:

  * NO ``attach()`` — no Cookie / CSRF / Bearer / Authorization is ever added.
  * Body is passed as raw bytes (base64-decoded from ``body_base64``), not text,
    so a binary blob round-trips uncorrupted.
  * Only the caller's ``content_type`` (when the presigned URL signed one) is sent.
  * The single PUT is routed through the Frieren proxy so it lands in history.

Two ways to point the tool at the URL:

  * **By reference (preferred)** — pass ``source_entry_id`` (a proxy-history entry
    id, e.g. the ``createPersonaAsset`` response) and optionally ``url_json_path``
    (default ``data.createPersonaAsset.uploadUrl``). The tool reads THAT entry's
    stored response body from ``ctx.store`` and extracts the full URL server-side.
    The model never copies the ~1500-char presigned URL, so it can neither truncate
    it nor be blocked by the observation display's length cap. This is also the
    tighter SSRF boundary: the URL is whatever a specific IN-SCOPE stored response
    actually captured — the source entry must itself be in scope or the PUT is
    refused.
  * **Explicit url (back-compat)** — pass ``url`` with the presigned URL verbatim.
    The SSRF guard here is host+path: the URL's host+path must have been observed
    as a value in some in-scope response body, else the PUT is refused. The target
    host is intentionally out of scope (a storage host, not the app); the
    session-level scope gate exempts ONLY this tool (see
    ``CopilotSession._scope_gate``) precisely because these checks are the real
    authority.

Exactly one of ``url`` / ``source_entry_id`` must be supplied.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Uploads can be large; give the PUT much longer than send_request's 15s.
_UPLOAD_TIMEOUT_SECONDS = 180.0

_DEFAULT_URL_JSON_PATH = "data.createPersonaAsset.uploadUrl"


def _entry_body_text(entry: Any) -> Optional[str]:
    """Decode a ProxyEntry.response_body (bytes or str) to text, or None if empty."""
    body = getattr(entry, "response_body", None)
    if not body:
        return None
    if isinstance(body, (bytes, bytearray)):
        return bytes(body).decode("utf-8", errors="replace")
    return str(body)


def _extract_json_path(text: str, dotted_path: str) -> Any:
    """Parse ``text`` as JSON and descend the dot-separated ``dotted_path``.

    Returns the value at the path, or raises KeyError/TypeError/ValueError with a
    message the caller turns into a clean tool error. Intermediate values must be
    dicts; a missing key or a non-dict mid-path is an error.
    """
    doc = json.loads(text)  # ValueError on non-JSON body
    cur: Any = doc
    for key in [p for p in dotted_path.split(".") if p]:
        if not isinstance(cur, dict):
            raise TypeError(f"value before '{key}' is not an object")
        if key not in cur:
            raise KeyError(key)
        cur = cur[key]
    return cur


def _observed_host_path(ctx: ToolContext, url: str) -> bool:
    """True when the URL's host+path (NOT the query — the SigV4 X-Amz-* params are
    volatile) was seen as a value in some IN-SCOPE response body.

    This is the SSRF boundary for the explicit-``url`` path: a presigned upload URL
    is only trustworthy because an in-scope response returned it. We match host+path
    (not the full URL) because the query string carries a per-request
    signature/expiry that changes every call. JSON bodies may escape the forward
    slashes (``https:\\/\\/host\\/key``), so the body is de-escaped before the
    substring check.
    """
    store = getattr(ctx, "store", None)
    if store is None:
        return False
    parsed = urlparse(url)
    netloc = parsed.netloc
    path = parsed.path or ""
    # A presigned upload URL always carries a real object-key path; a bare host (or
    # "/") is never a legitimate upload target and must not satisfy the guard.
    if not netloc or len(path) <= 1:
        return False
    needle = netloc + path
    try:
        entries = store.in_scope_entries()
    except Exception as exc:  # noqa: BLE001 — a store hiccup must not open the gate
        logger.warning("upload_to_presigned_url: in_scope_entries lookup failed",
                       error=str(exc))
        return False
    for entry in entries:
        text = _entry_body_text(entry)
        if not text:
            continue
        if needle in text or needle in text.replace("\\/", "/"):
            return True
    return False


def _resolve_url_from_entry(
    ctx: ToolContext, source_entry_id: str, url_json_path: str
) -> Dict[str, Any]:
    """Resolve the presigned URL from a stored in-scope response by reference.

    Returns ``{"url": <str>}`` on success or ``{"error": <str>}`` on any failure
    (entry not found, entry out of scope, path missing / not a string / not an
    absolute http(s) URL). The model never sees or copies the URL.
    """
    store = getattr(ctx, "store", None)
    if store is None:
        return {"error": "no proxy store available to resolve source_entry_id"}

    try:
        entry = store.get_entry(source_entry_id)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"could not read source_entry_id: {str(exc)[:120]}"}
    if entry is None:
        return {"error": (
            f"source_entry_id '{source_entry_id}' not found in proxy history — pass the "
            "entry id of the in-scope response that returned the upload URL (e.g. the "
            "createPersonaAsset POST, from get_history).")}

    # The source entry MUST itself be in scope: an out-of-scope entry could carry a
    # URL the app never legitimately handed us. Reuse the store's own in-scope view.
    try:
        in_scope_ids = {getattr(e, "id", None) for e in store.in_scope_entries()}
    except Exception as exc:  # noqa: BLE001 — a store hiccup must not open the gate
        return {"error": f"could not verify source entry scope: {str(exc)[:120]}"}
    if getattr(entry, "id", source_entry_id) not in in_scope_ids:
        return {"error": (
            f"source_entry_id '{source_entry_id}' is out of scope — the upload URL must "
            "come from an in-scope response.")}

    text = _entry_body_text(entry)
    if not text:
        return {"error": (
            f"source_entry_id '{source_entry_id}' has no response body to read the URL from.")}

    try:
        value = _extract_json_path(text, url_json_path)
    except ValueError:
        return {"error": (
            f"source entry response body is not valid JSON; cannot read '{url_json_path}'.")}
    except (KeyError, TypeError) as exc:
        return {"error": (
            f"json path '{url_json_path}' not found in the source entry response: {str(exc)[:120]}")}

    if not isinstance(value, str):
        return {"error": (
            f"value at '{url_json_path}' is not a string URL (got {type(value).__name__}).")}
    url = value.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {"error": (
            f"value at '{url_json_path}' is not an absolute http(s) URL: {url[:120]!r}")}
    return {"url": url}


_UPLOAD_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "source_entry_id": {
            "type": "string",
            "description": (
                "PREFERRED. The proxy-history entry id of the in-scope response that minted "
                "the upload URL (e.g. the createPersonaAsset POST — find it with get_history). "
                "The tool reads that stored response and extracts the full upload URL itself, so "
                "you never copy the long presigned URL. The source entry must be in scope."
            ),
        },
        "url_json_path": {
            "type": "string",
            "description": (
                "Optional dot-path to the upload URL inside the source entry's JSON response "
                "body. Defaults to 'data.createPersonaAsset.uploadUrl'. Only used with "
                "source_entry_id."
            ),
        },
        "url": {
            "type": "string",
            "description": (
                "Back-compat alternative to source_entry_id: the presigned PUT upload URL "
                "EXACTLY as an in-scope response returned it. Prefer source_entry_id — a long "
                "presigned URL is easy to truncate. Do not edit or invent it; its host+path "
                "must have been observed in an in-scope response body or the upload is refused."
            ),
        },
        "body_base64": {
            "type": "string",
            "description": (
                "The bytes to upload, base64-encoded. Decoded to raw bytes and PUT verbatim, so "
                "binary content (images, audio, archives) round-trips uncorrupted."
            ),
        },
        "content_type": {
            "type": "string",
            "description": (
                "Optional Content-Type. Send this ONLY when the presigned URL signed a "
                "Content-Type (e.g. the createPersonaAsset call specified one); it must match "
                "exactly or S3 returns SignatureDoesNotMatch. Send nothing else — no auth headers."
            ),
        },
    },
    "required": ["body_base64"],
}


async def _upload_to_presigned_url(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    source_entry_id = str(args.get("source_entry_id", "")).strip()

    # Exactly one of url / source_entry_id. The by-reference path is preferred; the
    # explicit url stays for non-persona cases.
    if url and source_entry_id:
        return {"ok": False, "error": (
            "pass exactly one of source_entry_id or url, not both")}
    if not url and not source_entry_id:
        return {"ok": False, "error": (
            "one of source_entry_id (preferred) or url is required")}

    # Resolve the URL. Two SSRF boundaries, one per path:
    #   - source_entry_id: the URL is read server-side from a specific IN-SCOPE stored
    #     response (strictly tighter than host+path matching).
    #   - explicit url: must be an absolute http(s) URL AND its host+path must have been
    #     observed in some in-scope response body.
    if source_entry_id:
        url_json_path = args.get("url_json_path")
        if url_json_path is None or not str(url_json_path).strip():
            url_json_path = _DEFAULT_URL_JSON_PATH
        else:
            url_json_path = str(url_json_path).strip()
        resolved = _resolve_url_from_entry(ctx, source_entry_id, url_json_path)
        if "error" in resolved:
            return {"ok": False, "error": resolved["error"]}
        url = resolved["url"]
    else:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return {"ok": False, "error": "url must be an absolute http(s) URL"}

    body_b64 = args.get("body_base64")
    if not isinstance(body_b64, str) or not body_b64.strip():
        return {"ok": False, "error": "body_base64 is required (base64-encoded bytes to PUT)"}
    try:
        raw = base64.b64decode(body_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        return {"ok": False, "error": f"body_base64 is not valid base64: {str(exc)[:120]}"}
    if not raw:
        return {"ok": False, "error": "body_base64 decoded to zero bytes — nothing to upload"}

    # Read-only mode: a PUT changes remote state, so it is blocked like every other write.
    if getattr(ctx, "read_only", False):
        return {"ok": False, "read_only": True,
                "error": "read-only mode: upload (PUT) is blocked"}

    # SSRF guard for the explicit-url path: only PUT to a host+path an in-scope response
    # actually handed us. (The source_entry_id path already resolved the URL from a
    # specific in-scope stored response, which is a tighter boundary — no host+path
    # substring match needed.)
    if not source_entry_id and not _observed_host_path(ctx, url):
        parsed = urlparse(url)
        logger.warning("upload_to_presigned_url refused unobserved URL",
                       host=parsed.hostname, path=parsed.path)
        return {"ok": False, "error": (
            "refused: this upload URL's host+path was not observed in any in-scope response "
            "body. A presigned upload URL must come from a prior in-scope response (e.g. "
            "createPersonaAsset.uploadUrl) — do not edit or invent an upload host. Prefer "
            "passing source_entry_id so the tool reads the URL from the stored response "
            "itself.")}

    # Build ONLY the headers the presigned signature expects. No attach(): the raw-bytes
    # body and the (optional) signed Content-Type are all that goes to the storage host.
    # Any session auth that _apply_session_auth may have written into tool_args["headers"]
    # is deliberately IGNORED here — attaching it would break SigV4 and leak app auth.
    headers: Dict[str, str] = {}
    content_type = args.get("content_type")
    if content_type:
        headers["Content-Type"] = str(content_type)

    # Tag the proxy-history entry so the operator can tell this traffic apart. The proxy
    # reads x-dast-source to label the entry and strips it before forwarding upstream, so
    # it never reaches (or breaks) the SigV4-signed request.
    source_label = getattr(ctx, "source_label", None)
    if source_label:
        headers["x-dast-source"] = str(source_label)

    try:
        import httpx

        timeout = httpx.Timeout(connect=10.0, read=_UPLOAD_TIMEOUT_SECONDS,
                                write=_UPLOAD_TIMEOUT_SECONDS, pool=10.0)
        async with httpx.AsyncClient(
            proxy=getattr(ctx, "proxy_url", None), verify=False,
            follow_redirects=False, timeout=timeout,
        ) as client:
            resp = await client.request("PUT", url, headers=headers or None, content=raw)
        full_text = resp.text
        return {
            "ok": 200 <= resp.status_code < 300,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": full_text[:4000],
            "bytes_sent": len(raw),
            "final_url": str(resp.url),
        }
    except Exception as exc:  # noqa: BLE001 — a handler never raises; return structured error
        return {"ok": False, "error": f"upload failed: {str(exc)[:200]}", "bytes_sent": len(raw)}


register(Tool(
    name="upload_to_presigned_url",
    description=(
        "PUT raw bytes to a presigned upload URL (e.g. an S3 uploadUrl returned by an "
        "in-scope createPersonaAsset mutation). Middle step of the asset chain: "
        "createPersonaAsset -> upload_to_presigned_url -> completePersonaAssetUpload. "
        "PREFERRED: pass source_entry_id (the get_history entry id of the createPersonaAsset "
        "response) so the tool reads the full upload URL from that stored in-scope response "
        "itself — you never copy the long presigned URL (optionally url_json_path, default "
        "'data.createPersonaAsset.uploadUrl'). Back-compat: pass url verbatim instead. Always "
        "pass body_base64 (base64 of the bytes) and, only if the presigned URL signed one, "
        "content_type. The PUT carries NO session auth (presigned URLs are SigV4-signed; a "
        "Cookie/CSRF/Bearer both breaks the signature and leaks app auth to the storage host), "
        "sends the body as raw bytes so binary content is not corrupted, and is recorded in "
        "proxy history. The upload URL must come from an in-scope response (SSRF guard). "
        "Presigned URLs expire (~1h) so run create -> PUT -> complete promptly. Do not use "
        "this for normal app API calls (use send_request)."
    ),
    input_schema=_UPLOAD_SCHEMA,
    handler=_upload_to_presigned_url,
    tags=["http", "active"],
))
