"""
Encoding utility tools — url/base64/html encode + decode.

Pure string transforms (no ToolContext, no network, no scope gate). They exist so
an MCP client or agent can build and inspect payloads without shelling out. Each
tool takes ``text`` and returns ``{"ok": True, "result": ...}``.
"""

from __future__ import annotations

import base64
import html
import urllib.parse
from typing import Any, Callable, Dict

from dast.tools.base import Tool, register

_TEXT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {"text": {"type": "string", "description": "The text to transform."}},
    "required": ["text"],
}


def _url_encode(text: str) -> str:
    return urllib.parse.quote(text, safe="")


def _url_decode(text: str) -> str:
    return urllib.parse.unquote(text)


def _base64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _base64_decode(text: str) -> str:
    # validate=False tolerates whitespace/newlines the way operators paste tokens.
    return base64.b64decode(text.encode("ascii"), validate=False).decode("utf-8", errors="replace")


def _html_encode(text: str) -> str:
    return html.escape(text, quote=True)


def _html_decode(text: str) -> str:
    return html.unescape(text)


def _make_handler(transform: Callable[[str], str]):
    async def _handler(ctx: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        text = args.get("text")
        if text is None:
            return {"ok": False, "error": "text is required"}
        try:
            return {"ok": True, "result": transform(str(text))}
        except Exception as exc:
            return {"ok": False, "error": f"transform failed: {str(exc)[:200]}"}
    return _handler


# Each description states the transform plus when to reach for it, so the LLM
# picks the right encoding step instead of guessing or hand-encoding inline.
_ENCODERS = {
    "url_encode": (
        "Percent-encode text for use in a URL (encodes all reserved characters). Use when "
        "placing a payload into a query/path so it survives transport. Not for decoding.",
        _url_encode),
    "url_decode": (
        "Decode percent-encoded (URL-encoded) text. Use to read a captured URL-encoded "
        "value. Not for encoding a payload to send.",
        _url_decode),
    "base64_encode": (
        "Base64-encode UTF-8 text. Use to build a base64 payload (e.g. a JWT segment or a "
        "data: value). Not for URL escaping (use url_encode).",
        _base64_encode),
    "base64_decode": (
        "Base64-decode text back to UTF-8 (invalid bytes are replaced). Use to inspect a "
        "base64 token or response. Not for URL-encoded text (use url_decode).",
        _base64_decode),
    "html_encode": (
        "HTML-escape text (&, <, >, quotes). Use to test whether a reflection point escapes "
        "output. Not for URL contexts (use url_encode).",
        _html_encode),
    "html_decode": (
        "Decode HTML entities back to plain text. Use to read an HTML-escaped response value. "
        "Not for encoding.",
        _html_decode),
}

for _name, (_description, _transform) in _ENCODERS.items():
    register(Tool(
        name=_name,
        description=_description,
        input_schema=_TEXT_SCHEMA,
        handler=_make_handler(_transform),
        tags=["util"],
    ))
