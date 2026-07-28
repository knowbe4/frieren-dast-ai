"""
Request Smuggling Hints plugin — passively flags HTTP/1.1 requests and
responses that exhibit header patterns associated with request smuggling
(CL.TE, TE.CL, and TE.TE variants) and response desync indicators.

This is a hint/signal plugin — it does not confirm exploitability.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dast.proxy.plugin_base import ProxyPlugin

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

_CHUNKED_RE = re.compile(r'\bchunked\b', re.IGNORECASE)


def _has_header(headers: dict, name: str) -> bool:
    return name.lower() in {k.lower() for k in headers}


def _header_value(headers: dict, name: str) -> str:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return ""


class RequestSmugglingHintsPlugin(ProxyPlugin):
    name        = "request-smuggling-hints"
    description = "Flags HTTP request/response patterns associated with request smuggling"
    version     = "1.0.0"
    author      = "Frieren DAST-AI"
    enabled     = True

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        req_headers = entry.request_headers
        resp_headers = entry.response_headers

        has_cl  = _has_header(req_headers, "content-length")
        has_te  = _has_header(req_headers, "transfer-encoding")
        te_val  = _header_value(req_headers, "transfer-encoding")

        # CL.TE or TE.CL: both headers present in the same request
        if has_cl and has_te:
            store.add_finding(
                entry.id,
                {
                    "title": "Potential Request Smuggling: Both Content-Length and Transfer-Encoding Present",
                    "severity": "medium",
                    "cwe": "CWE-444",
                    "attack_type": "request-smuggling",
                    "evidence": (
                        f"Request contains both Content-Length and Transfer-Encoding: {te_val!r}. "
                        f"Ambiguous message framing can enable CL.TE or TE.CL request smuggling "
                        f"when front-end and back-end servers disagree on precedence."
                    ),
                    "confirmed": False,
                    "validated_by": ["pattern"],
                },
                "safe",
            )
            return

        # TE.TE: Transfer-Encoding present but obfuscated (not plain "chunked")
        if has_te and _CHUNKED_RE.search(te_val) and te_val.strip().lower() != "chunked":
            store.add_finding(
                entry.id,
                {
                    "title": "Potential Request Smuggling: Obfuscated Transfer-Encoding Header",
                    "severity": "medium",
                    "cwe": "CWE-444",
                    "attack_type": "request-smuggling",
                    "evidence": (
                        f"Transfer-Encoding header value is {te_val!r} (not plain 'chunked'). "
                        f"Some servers normalise this differently, enabling TE.TE desync attacks."
                    ),
                    "confirmed": False,
                    "validated_by": ["pattern"],
                },
                "safe",
            )
            return

        # Response desync hint: 400 on a normal-looking request (server rejected framing)
        if entry.response_status == 400 and has_cl and not has_te:
            cl_val = _header_value(req_headers, "content-length")
            if entry.request_body and len(entry.request_body) != int(cl_val or 0):
                store.add_finding(
                    entry.id,
                    {
                        "title": "Potential Request Smuggling: Content-Length Mismatch and 400 Response",
                        "severity": "low",
                        "cwe": "CWE-444",
                        "attack_type": "request-smuggling",
                        "evidence": (
                            f"Content-Length header declares {cl_val} bytes but actual body is "
                            f"{len(entry.request_body)} bytes. Server returned 400 — "
                            f"may indicate framing ambiguity."
                        ),
                        "confirmed": False,
                        "validated_by": ["pattern"],
                    },
                    "safe",
                )
