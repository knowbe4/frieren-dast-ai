"""
Raw HTTP text formatting for evidence.

Single home for turning a `ProxyEntry` into raw HTTP request/response text
(the format shown as finding evidence). Kept dependency-free so any module can
import it without risking a circular import with `session_store`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry


def _format_raw_request(entry: "ProxyEntry") -> str:
    """Format a ProxyEntry's request as raw HTTP text (reusable by any caller)."""
    parsed = urlparse(entry.url)
    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    lines = [f"{entry.method} {path} HTTP/1.1", f"Host: {entry.host}"]
    for k, v in (entry.request_headers or {}).items():
        if k.lower() != "host":
            lines.append(f"{k}: {v}")
    lines.append("")
    if entry.request_body:
        lines.append(entry.request_body.decode("utf-8", errors="replace"))
    return "\r\n".join(lines)


def _format_raw_response(entry: "ProxyEntry") -> str:
    """Format a ProxyEntry's response as raw HTTP text (reusable by any caller)."""
    status = entry.response_status or 0
    lines = [f"HTTP/1.1 {status}"]
    for k, v in (entry.response_headers or {}).items():
        if k.lower() == "set-cookie" and isinstance(v, list):
            for cookie in v:
                lines.append(f"set-cookie: {cookie}")
        else:
            lines.append(f"{k}: {v}")
    lines.append("")
    if entry.response_body:
        lines.append(entry.response_body.decode("utf-8", errors="replace")[:4000])
    return "\r\n".join(lines)
