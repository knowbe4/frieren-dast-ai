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

SSRF guard (the crux): the target host is deliberately OUT OF SCOPE (a storage
host, not the app). We only allow the PUT when the URL's host+path was actually
observed as a value in an IN-SCOPE response body — i.e. the app itself handed us
this upload URL. A host the model fabricated is refused. The session-level scope
gate exempts ONLY this tool (see ``CopilotSession._scope_gate``) precisely because
this observed-URL check is the real authority.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any, Dict
from urllib.parse import urlparse

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Uploads can be large; give the PUT much longer than send_request's 15s.
_UPLOAD_TIMEOUT_SECONDS = 180.0


def _observed_host_path(ctx: ToolContext, url: str) -> bool:
    """True when the URL's host+path (NOT the query — the SigV4 X-Amz-* params are
    volatile) was seen as a value in some IN-SCOPE response body.

    This is the SSRF boundary: a presigned upload URL is only trustworthy because an
    in-scope response returned it. We match host+path (not the full URL) because the
    query string carries a per-request signature/expiry that changes every call. JSON
    bodies may escape the forward slashes (``https:\\/\\/host\\/key``), so the body is
    de-escaped before the substring check.
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
        body = getattr(entry, "response_body", None)
        if not body:
            continue
        if isinstance(body, (bytes, bytearray)):
            text = bytes(body).decode("utf-8", errors="replace")
        else:
            text = str(body)
        if needle in text or needle in text.replace("\\/", "/"):
            return True
    return False


_UPLOAD_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": (
                "The presigned PUT upload URL EXACTLY as an in-scope response returned it "
                "(e.g. createPersonaAsset.uploadUrl). Do not edit or invent it — its host+path "
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
    "required": ["url", "body_base64"],
}


async def _upload_to_presigned_url(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
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

    # SSRF guard: only PUT to a host+path an in-scope response actually handed us.
    if not _observed_host_path(ctx, url):
        logger.warning("upload_to_presigned_url refused unobserved URL",
                       host=parsed.hostname, path=parsed.path)
        return {"ok": False, "error": (
            "refused: this upload URL's host+path was not observed in any in-scope response "
            "body. A presigned upload URL must come from a prior in-scope response (e.g. "
            "createPersonaAsset.uploadUrl) — do not edit or invent an upload host. Re-run the "
            "mutation that mints the URL, then pass that exact URL here.")}

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
        "in-scope createPersonaAsset mutation). Use this as the middle step of the asset "
        "chain: createPersonaAsset -> upload_to_presigned_url(body_base64) -> "
        "completePersonaAssetUpload. Pass body_base64 (base64 of the bytes) and, only if the "
        "presigned URL signed one, content_type. The PUT carries NO session auth (presigned "
        "URLs are SigV4-signed; a Cookie/CSRF/Bearer both breaks the signature and leaks app "
        "auth to the storage host), sends the body as raw bytes so binary content is not "
        "corrupted, and is recorded in proxy history. The upload URL must be EXACTLY what an "
        "in-scope response returned — a host+path not observed in an in-scope response body is "
        "refused (SSRF guard). Do not use this for normal app API calls (use send_request)."
    ),
    input_schema=_UPLOAD_SCHEMA,
    handler=_upload_to_presigned_url,
    tags=["http", "active"],
))
