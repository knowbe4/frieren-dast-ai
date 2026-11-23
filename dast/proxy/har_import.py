"""HAR 1.2 import — parse a HAR document into history-entry payloads.

Round 4-C, the inverse of ``har_export`` (ARTEX contract adapted): accepts a
HAR 1.2 log (≤2000 entries), validates per-entry and never aborts on one bad
entry (errors are counted, up to 50 details), synthesizes ``Cookie`` /
``Set-Cookie`` headers from the cookies arrays when absent, rebuilds
urlencoded bodies from ``postData.params`` when ``text`` is empty, decodes
base64 content, and strips URL userinfo. Imported entries are plain history
rows (source ``imported``) — NO match&replace or rewrite rules ever apply to
them (ARTEX invariant: imported traffic was never rewritten).

Deterministic de-dup key (``har-<sha256>`` over the entry's stable fields) is
computed here so the caller can skip an identical previous import.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

_MAX_ENTRIES = 2000
_MAX_ERROR_DETAILS = 50
_DECODABLE = ("text/plain", "application/json", "xml", "html", "javascript",
              "urlencoded", "form", "css", "csv", "svg")


def har_key(method: str, url: str, status: int,
            req_body: bytes, resp_body: bytes, ts: str) -> str:
    payload = "\x00".join([
        str(ts), method.upper(), url, str(status),
        hashlib.sha256(req_body).hexdigest(), hashlib.sha256(resp_body).hexdigest(),
    ])
    return "har-" + hashlib.sha256(payload.encode()).hexdigest()[:32]


def _decode(text: Optional[str], encoding: Optional[str]) -> bytes:
    if not text:
        return b""
    if (encoding or "").lower() == "base64":
        try:
            return base64.b64decode(text)
        except Exception:
            return b""
    return text.encode("utf-8", errors="replace")


def _headers_from_pairs(pairs: List[Dict[str, str]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    set_cookies: List[str] = []
    for pair in pairs or []:
        name = str(pair.get("name", "")).strip()
        if not name:
            continue
        if name.lower() == "set-cookie":
            set_cookies.append(str(pair.get("value", "")))
        else:
            out[name.lower()] = str(pair.get("value", ""))
    if set_cookies:
        out["set-cookie"] = set_cookies
    return out


def _redact_url(url: str) -> str:
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


def urlencode_pairs(params: List[Dict[str, Any]]) -> str:
    from urllib.parse import quote
    parts = []
    for p in params or []:
        name = str(p.get("name", ""))
        value = str(p.get("value", ""))
        parts.append(f"{quote(name, safe='')}={quote(value, safe='')}")
    return "&".join(parts)



def import_har(doc: Any) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Parse a HAR document → (entry payloads, stats).

    Each payload is a dict ready for ``SessionStore.new_entry`` +
    ``complete_entry``: {har_key, method, url, request_headers, request_body,
    response_status, response_headers, response_body, duration_ms}.

    Raises ValueError on a document that is not HAR 1.2 or exceeds the entry
    cap (the route maps those to 400/413); per-ENTRY problems are counted,
    never fatal (≤50 details, ARTEX contract).
    """
    stats: Dict[str, Any] = {"imported": 0, "skipped": 0, "failed": 0, "errors": []}
    if not isinstance(doc, dict) or not isinstance(doc.get("log"), dict):
        raise ValueError("not a HAR document (missing log)")
    log = doc["log"]
    if str(log.get("version", "")) != "1.2":
        raise ValueError(f"unsupported HAR version: {log.get('version')!r} (1.2 required)")
    raw_entries = log.get("entries")
    if not isinstance(raw_entries, list):
        raise ValueError("log.entries missing")
    if len(raw_entries) > _MAX_ENTRIES:
        raise ValueError(f"too many entries: {len(raw_entries)} > {_MAX_ENTRIES}")

    payloads: List[Dict[str, Any]] = []
    for i, entry in enumerate(raw_entries):
        try:
            req = entry["request"]
            resp = entry.get("response") or {}
            method = str(req.get("method", "GET")).upper()
            url = _redact_url(str(req.get("url", "")))
            if not method or not url.startswith(("http://", "https://")):
                raise ValueError("request needs an http(s) URL")

            req_headers = _headers_from_pairs(req.get("headers"))
            # cookies arrays synthesize the wire headers when absent (ARTEX).
            req_cookies = entry.get("request", {}).get("cookies") or []
            if req_cookies and "cookie" not in req_headers:
                pairs = "; ".join(f"{c.get('name')}={c.get('value')}"
                                  for c in req_cookies if c.get("name"))
                if pairs:
                    req_headers["cookie"] = pairs

            post = req.get("postData") or {}
            req_body = b""
            if post.get("params") and not post.get("text"):
                # rebuild the urlencoded body from params (ARTEX contract).
                req_body = urlencode_pairs(post["params"]).encode("utf-8")
                req_headers.setdefault("content-type",
                                       "application/x-www-form-urlencoded")
            else:
                req_body = _decode(post.get("text"), post.get("encoding"))

            status = int(resp.get("status", 0) or 0)
            resp_headers = _headers_from_pairs(resp.get("headers"))
            resp_cookies = resp.get("cookies") or []
            if resp_cookies and "set-cookie" not in resp_headers:
                set_cookies = [f"{c.get('name')}={c.get('value')}"
                               for c in resp_cookies if c.get("name")]
                if set_cookies:
                    resp_headers["set-cookie"] = set_cookies
            content = resp.get("content") or {}
            resp_body = _decode(content.get("text"), content.get("encoding"))

            key = har_key(method, url, status, req_body, resp_body,
                          str(entry.get("startedDateTime", "")))
            payloads.append({
                "har_key": key,
                "method": method,
                "url": url,
                "request_headers": req_headers,
                "request_body": req_body,
                "response_status": status,
                "response_headers": resp_headers,
                "response_body": resp_body,
                "duration_ms": 0,
            })
            stats["imported"] += 1
        except Exception as exc:
            stats["failed"] += 1
            if len(stats["errors"]) < _MAX_ERROR_DETAILS:
                stats["errors"].append(f"entry[{i}]: {str(exc)[:160]}")
    return payloads, stats


