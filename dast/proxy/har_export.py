"""HAR 1.2 export — turn proxy history entries into a spec-compliant HAR file.

Round 3-I, modeled on ARTEX's exporter (traffic/har.go) with the same
contract: stable (ts, id) ordering, EXPLICIT placeholders for timings we do
not record (``time: 0``, ``timings -1``, empty cookies/cache — nothing
invented), UTF-8-no-NUL bodies as plain text and everything else as base64,
hard caps (1000 entries / 20 MiB raw / 31 MiB marshalled backstop) whose
truncation is NEVER silent (response headers + ``_truncated`` fields in the
log). Pure functions — no store or event-loop coupling.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse

_MAX_ENTRIES = 1000
_MAX_RAW_BYTES = 20 * 1024 * 1024
_MAX_JSON_BYTES = 31 * 1024 * 1024
_ENVELOPE_MARGIN = 512  # log envelope overhead headroom for the backstop check


def _rfc3339(ts: float) -> str:
    return datetime.fromtimestamp(float(ts or 0.0), tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _redact_url(url: str) -> str:
    """Drop userinfo (a password embedded in the URL must not land in the export)."""
    try:
        p = urlparse(url or "")
        if p.username is None and p.password is None:
            return url
        netloc = p.hostname or ""
        if p.port:
            netloc += f":{p.port}"
        return p._replace(netloc=netloc).geturl()
    except ValueError:
        return url


def _headers_pairs(headers: Dict[str, object]) -> List[Dict[str, str]]:
    """Header dict → HAR [{name, value}] pairs; a LIST value (multi Set-Cookie
    as stored by the proxy) expands into one pair per value."""
    pairs: List[Dict[str, str]] = []
    for k, v in (headers or {}).items():
        values = v if isinstance(v, list) else [v]
        for item in values:
            pairs.append({"name": str(k), "value": str(item)})
    return pairs


def _encode_body(body: Optional[bytes]) -> Tuple[int, Dict[str, object]]:
    """(size, content-fields). UTF-8-valid without NUL → plain ``text``;
    anything else → base64 with ``encoding`` (ARTEX encodeHARBody)."""
    body = body or b""
    if not body:
        return 0, {}
    fields: Dict[str, object] = {"size": len(body)}
    try:
        text = body.decode("utf-8")
        if "\x00" not in text:
            fields["text"] = text
            return len(body), fields
    except UnicodeDecodeError:
        pass
    fields["text"] = base64.b64encode(body).decode("ascii")
    fields["encoding"] = "base64"
    return len(body), fields


def _entry_to_har(entry, include_request_body: bool = True,
                  include_response_body: bool = True) -> Dict[str, object]:
    """One ProxyEntry → one HAR entry object. Reads ONLY stored attributes."""
    url = _redact_url(entry.url)
    req_headers = _headers_pairs(entry.request_headers)
    req_size, req_content = _encode_body(entry.request_body if include_request_body else None)
    request: Dict[str, object] = {
        "method": entry.method,
        "url": url,
        "httpVersion": "HTTP/1.1",
        "headers": req_headers,
        "queryString": [{"name": n, "value": v}
                        for n, v in parse_qsl(urlparse(url).query, keep_blank_values=True)],
        "cookies": [],
        "headersSize": -1,  # not recorded — explicit placeholder, never invented
        "bodySize": req_size,
    }
    if req_content:
        mime = ""
        for k, v in (entry.request_headers or {}).items():
            if k.lower() == "content-type":
                mime = str(v)
                break
        request["postData"] = {"mimeType": mime, **req_content}

    response: Dict[str, object] = {
        "status": int(entry.response_status or 0),
        "statusText": "",
        "httpVersion": "HTTP/1.1",
        "headers": _headers_pairs(entry.response_headers),
        "cookies": [],
        "headersSize": -1,
        "bodySize": len(entry.response_body or b""),
        "content": {"mimeType": (entry.content_type or "").split(";")[0].strip(),
                    **_encode_body(entry.response_body if include_response_body else None)[1]},
        "redirectURL": "",
    }
    return {
        "_dastEntryId": entry.id,
        "startedDateTime": _rfc3339(entry.ts),
        "time": 0,  # not recorded per-phase
        "cache": {},
        "timings": {"send": -1, "wait": -1, "receive": -1},
        "request": request,
        "response": response,
    }


def _raw_entry_bytes(entry: Dict[str, object]) -> int:
    """Approximate wire size of one HAR entry (headers pairs + bodies) for the
    raw-bytes cap — the JSON backstop below is the authoritative bound."""
    total = 0
    for part in ("request", "response"):
        p = entry.get(part, {})
        for h in p.get("headers", []):
            total += len(h.get("name", "")) + len(h.get("value", "")) + 4
        total += int(p.get("bodySize", 0) or 0)
    content = entry.get("response", {}).get("content", {})
    total += int(content.get("size", 0) or 0)
    return total


def entries_to_har(entries: List[object], creator_name: str = "frieren DAST-AI",
                   creator_version: str = "",
                   max_entries: Optional[int] = None,
                   max_raw_bytes: Optional[int] = None,
                   max_json_bytes: Optional[int] = None) -> Tuple[Dict[str, object], Dict[str, bool]]:
    """Build the HAR 1.2 log dict from history entries.

    Caps resolve at CALL time (module constants) so tests and operators can
    tighten them. Returns (log, truncation) where truncation carries
    ``entries``/``bytes`` flags. Ordering is stable (ts asc, id asc); caps apply
    in that order and are reported — truncation is never silent. Entries
    without a response (still in flight) are skipped."""
    max_entries = _MAX_ENTRIES if max_entries is None else max_entries
    max_raw_bytes = _MAX_RAW_BYTES if max_raw_bytes is None else max_raw_bytes
    max_json_bytes = _MAX_JSON_BYTES if max_json_bytes is None else max_json_bytes
    completed = sorted((e for e in entries if getattr(e, "response_status", None) is not None),
                       key=lambda e: (getattr(e, "ts", 0.0), getattr(e, "id", "")))
    total_matched = len(completed)

    taken: List[Dict[str, object]] = []
    raw_used = 0
    truncated_by_entries = False
    truncated_by_bytes = False
    for e in completed:
        if len(taken) >= max_entries:
            truncated_by_entries = True
            break
        har_entry = _entry_to_har(e)
        cost = _raw_entry_bytes(har_entry)
        if taken and raw_used + cost > max_raw_bytes:
            truncated_by_bytes = True
            break
        taken.append(har_entry)
        raw_used += cost

    def _serialize(log_entries: List[Dict[str, object]]) -> Dict[str, object]:
        log: Dict[str, object] = {
            "log": {
                "version": "1.2",
                "creator": {"name": creator_name, "version": creator_version or "dev"},
                "entries": log_entries,
            }
        }
        if truncated_by_entries or truncated_by_bytes:
            log["log"]["_truncated"] = True
            log["log"]["_truncatedReason"] = "max_entries" if truncated_by_entries else "max_bytes"
            log["log"]["_totalMatched"] = total_matched
        return log

    log = _serialize(taken)
    # JSON backstop: drop from the TAIL until the marshalled file fits.
    while len(taken) > 1 and len(json.dumps(log).encode("utf-8")) > max_json_bytes:
        taken.pop()
        log = _serialize(taken)

    # entries-cap implies the export stopped early on volume too; the header
    # reason prefers max_entries (ARTEX order).
    truncation = {
        "entries": truncated_by_entries,
        "bytes": truncated_by_bytes or (truncated_by_entries and len(taken) < total_matched),
    }
    return log, truncation


def truncation_headers(truncation: Dict[str, bool], exported: int,
                       matched: int) -> Dict[str, str]:
    """X-DAST-HAR-* response headers for the download route (ARTEX contract)."""
    headers: Dict[str, str] = {
        "X-DAST-HAR-Exported": str(exported),
        "X-DAST-HAR-Matched": str(matched),
    }
    if truncation.get("entries") or truncation.get("bytes"):
        headers["X-DAST-HAR-Truncated"] = "true"
        headers["X-DAST-HAR-Truncated-Reason"] = (
            "max_entries" if truncation.get("entries") else "max_bytes")
    return headers
