"""
SignalR / Blazor (blazorpack) wire primitives and human-readable decoding.

Single home for the framing pieces that were previously copy-pasted across
`session_store`, `blazor_agent`, and `blazor_detector`: the record separator,
the msgpack varint length prefix (read + write), and the binary-protocol sniff.

It also owns the human-readable decoding used by the HTTP history view
(`decode_body` / `body_preview`): text-protocol (JSON + 0x1e) and
binary-protocol (MessagePack) frames are rendered as one line per message.
The active agent and the passive detector keep their own structured decoders
because their output shapes differ (frame building / structured dicts).
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional, Tuple

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# SignalR text-protocol record separator (0x1e), between JSON messages.
SIGNALR_SEPARATOR = "\x1e"

# DOS/PE "MZ" magic — used to spot a leaked native image in Blazor responses.
MZ_HEADER = b"\x4d\x5a"

# Text-protocol message type labels for types without a dedicated renderer.
_TEXT_TYPE_LABELS = {
    1: "invoke", 2: "stream", 3: "result", 4: "stream-item",
    5: "cancel", 6: "ping", 7: "close",
}

# Blazor circuit-infrastructure invocations whose args are noise — only the count is shown.
_KNOWN_BLAZOR_INFRA_TARGETS = {
    "JsInitialized", "AttachWebRendererInterop", "SetHasLocationChangingHandlers",
    "OnAfterRenderComplete", "AcknowledgeRenderer",
}

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_LEADING_BINARY_PREFIX_RE = re.compile(r"^[\x00-\x08\x0b-\x1f\x7f�]+")
_NON_PRINTABLE_RE = re.compile(r"[^\x20-\x7e]")


def read_varint(data: bytes, pos: int) -> Tuple[int, int]:
    """Read a 7-bit little-endian varint at `pos`; return (value, new_pos)."""
    result, shift = 0, 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7
    return result, pos


def encode_varint(length: int) -> bytes:
    """Encode a length as a 7-bit little-endian varint (inverse of read_varint)."""
    varint = b""
    while True:
        byte = length & 0x7F
        length >>= 7
        varint += bytes([byte | (0x80 if length else 0)])
        if not length:
            break
    return varint


def is_signalr_binary(raw: bytes) -> bool:
    """
    Return True if `raw` looks like SignalR binary (MessagePack/blazorpack).

    Binary frames are <varint-length><msgpack-fixarray>...; the varint can be
    1-5 bytes (continuation bit 0x80 set on all but the last). Skip the varint
    bytes, then check the next byte is a msgpack fixarray (0x90-0x9f).
    """
    if len(raw) < 2:
        return False
    pos = 0
    for _ in range(5):
        if pos >= len(raw):
            return False
        byte = raw[pos]
        pos += 1
        if not (byte & 0x80):  # last varint byte
            break
    return pos < len(raw) and 0x90 <= raw[pos] <= 0x9F


def _to_json_text(value: Any) -> str:
    """Serialise any decoded value to compact JSON text for display."""
    return json.dumps(value, ensure_ascii=False, default=str)


def annotate_blazor_args(target: str, args: Any) -> str:
    """
    Return a human-readable annotation for known Blazor circuit management calls.
    Raw args are often opaque tokens — we label them so the reader knows what they are.
    """
    # ConnectCircuit args[0] is an ASP.NET Core Data Protection token (CfDJ8... prefix).
    # It is AES-256-CBC + HMAC-SHA256 encrypted with the server's key ring —
    # cannot be decrypted without the server private key. It authenticates the circuit.
    if target == "ConnectCircuit":
        if isinstance(args, (list, tuple)) and args:
            token = str(args[0])
            is_data_protection = token.startswith("CfDJ8")
            label = (
                "ASP.NET DataProtection token (encrypted, not decodable)"
                if is_data_protection else "circuit token"
            )
            rest = _to_json_text(list(args[1:])) if len(args) > 1 else ""
            return f'"{token[:24]}…" [{label}]{(", " + rest) if rest else ""}'
        return _to_json_text(args)

    # UpdateRootComponents: args contain component descriptors
    if target == "UpdateRootComponents":
        if isinstance(args, (list, tuple)) and args:
            try:
                operations = json.loads(args[0]) if isinstance(args[0], str) else args[0]
                if isinstance(operations, list):
                    summary = [
                        f"{op.get('type','?')}:{op.get('marker','?')}" for op in operations[:3]
                    ]
                    ellipsis = "…" if len(operations) > 3 else ""
                    return f"[{', '.join(summary)}{ellipsis}] ({len(operations)} ops)"
            except Exception as exc:
                logger.debug(
                    "Blazor UpdateRootComponents args could not be summarised",
                    error=str(exc),
                )

    # OnNavigate: URL the user navigated to
    if target == "OnNavigate":
        if isinstance(args, (list, tuple)) and args:
            return f'"{args[0]}"'

    # JsInitialized, AttachWebRendererInterop etc — just show arg count
    if target in _KNOWN_BLAZOR_INFRA_TARGETS:
        if isinstance(args, (list, tuple)):
            return f"({len(args)} args)"
        return _to_json_text(args)

    return _to_json_text(args)


def _render_msgpack_invocation(message: Any) -> Optional[str]:
    """Render a MessagePack Invocation frame ``[1, headers, invId, target, args, ...]``."""
    if len(message) < 5:
        return None
    invocation_id = message[2]
    target = message[3] or ""
    args = message[4]
    id_part = f" [{invocation_id}]" if invocation_id else ""

    if target == "BeginInvokeDotNetFromJS" and isinstance(args, (list, tuple)) and len(args) >= 5:
        # args = [callId, assembly, method, dotNetObjectId, argsJson]
        assembly = args[1] or ""
        method = args[2] or "?"
        args_json_text = args[4]
        try:
            inner = json.loads(args_json_text) if isinstance(args_json_text, str) else args_json_text
            inner_text = _to_json_text(inner)
        except Exception as exc:
            logger.debug("BeginInvokeDotNetFromJS args are not JSON", error=str(exc))
            inner_text = str(args_json_text)[:300]
        namespace = f"{assembly}::" if assembly else ""
        return f"[dotnet-invoke]{id_part} {namespace}{method}({inner_text})"

    if target == "EndInvokeJSFromDotNet" and isinstance(args, (list, tuple)) and len(args) >= 2:
        call_id = args[0]
        outcome = "ok" if args[1] else "error"
        result = args[2] if len(args) > 2 else None
        try:
            if isinstance(result, str) and result.startswith(("[", "{")):
                result = json.loads(result)
        except Exception as exc:
            logger.debug("EndInvokeJSFromDotNet result is not JSON", error=str(exc))
        return f"[js-result] [{call_id}] {outcome} {_to_json_text(result)}"

    if target in ("OnRenderCompleted", "OnAfterRenderAsync"):
        batch = args[0] if isinstance(args, (list, tuple)) and args else args
        return f"[render] {target} batch={batch}"

    # Annotate well-known Blazor Server circuit management calls
    return f"[invoke]{id_part} {target}({annotate_blazor_args(target, args)})"


def _render_msgpack_completion(message: Any) -> str:
    """Render a MessagePack Completion frame ``[3, headers, invId, resultKind, payload?]``."""
    if len(message) < 4:
        return "[result:void]"
    result_kind = message[3]
    if result_kind == 1 and len(message) > 4:
        return f"[result:error] {message[4]}"
    if result_kind == 2 and len(message) > 4:
        return f"[result] {_to_json_text(message[4])[:300]}"
    return "[result:void]"


def decode_msgpack_signalr(raw: bytes) -> str:
    """
    Decode SignalR binary (MessagePack / blazorpack) protocol frames using msgpack lib.

    Each frame: <varint-length><msgpack-payload>
    SignalR msgpack array layout by type:
      1 = Invocation:  [1, headers, invId|null, target, args, streamIds?]
      3 = Completion:  [3, headers, invId, resultKind, payload?]
      6 = Ping:        [6]
      7 = Close:       [7, error?]
    """
    try:
        import msgpack
    except ImportError as exc:
        logger.debug("msgpack not installed — cannot decode SignalR binary frames", error=str(exc))
        return ""

    lines = []
    pos = 0
    while pos < len(raw):
        frame_len, pos = read_varint(raw, pos)
        if frame_len == 0 or pos + frame_len > len(raw):
            break
        frame = raw[pos:pos + frame_len]
        pos += frame_len
        if not frame:
            continue
        try:
            message = msgpack.unpackb(frame, raw=False, strict_map_key=False)
        except Exception as exc:
            logger.debug("SignalR msgpack frame could not be unpacked", error=str(exc))
            continue
        if not isinstance(message, (list, tuple)) or not message:
            continue

        message_type = message[0]
        if message_type == 1:
            rendered = _render_msgpack_invocation(message)
            if rendered is not None:
                lines.append(rendered)
        elif message_type == 3:
            lines.append(_render_msgpack_completion(message))
        elif message_type == 6:
            lines.append("[ping]")
        elif message_type == 7:
            error_text = message[1] if len(message) > 1 else ""
            lines.append(f"[close] {error_text}" if error_text else "[close]")
        else:
            lines.append(f"[type{message_type}]")

    return "\n".join(lines) if lines else ""


def _render_text_segment(segment: str) -> Optional[str]:
    """Render one 0x1e-delimited text-protocol segment, or None if it has no content."""
    json_start = next((i for i, ch in enumerate(segment) if ch in ("{", "[")), -1)
    if json_start == -1:
        readable = _NON_PRINTABLE_RE.sub("", segment)
        return f"[binary] {readable[:120]}" if readable.strip() else None
    try:
        message = json.loads(segment[json_start:])
    except (json.JSONDecodeError, ValueError) as exc:
        logger.debug("SignalR text segment is not valid JSON", error=str(exc))
        readable = _NON_PRINTABLE_RE.sub("", segment)
        return readable[:120] if readable.strip() else None

    message_type = message.get("type", "?")
    if message_type == 1:
        target = message.get("target", "?")
        args = json.dumps(message.get("arguments", []), ensure_ascii=False)
        invocation_id = message.get("invocationId", "")
        id_part = f" [{invocation_id}]" if invocation_id else ""
        return f"[invoke]{id_part} {target}({args})"
    if message_type == 3:
        error_text = message.get("error")
        if error_text:
            return f"[result:error] {error_text[:200]}"
        result = json.dumps(message.get("result", ""), ensure_ascii=False)
        return f"[result] {result[:300]}"
    if message_type == 6:
        return "[ping]"
    if message_type == 7:
        return f"[close] {message.get('error','')}" if message.get("error") else "[close]"
    label = _TEXT_TYPE_LABELS.get(message_type, f"type{message_type}")
    return f"[{label}] {segment[json_start:][:200]}"


def decode_signalr_body(raw: bytes) -> str:
    """
    Decode a SignalR body — auto-detects text (JSON+0x1e) vs binary (MessagePack) protocol.

    Text protocol: JSON objects separated by 0x1e record separator.
    Binary protocol (blazorpack): varint-length-prefixed MessagePack frames.
    """
    # --- Binary protocol (blazorpack / MessagePack) — check BEFORE text ---
    # Must come first because varint length bytes can coincidentally equal 0x1e
    if is_signalr_binary(raw):
        decoded = decode_msgpack_signalr(raw)
        if decoded:
            return decoded

    # --- Text protocol (0x1e record separator) ---
    if SIGNALR_SEPARATOR.encode() in raw:
        text = raw.decode("utf-8", errors="replace")
        lines = []
        for segment in text.split(SIGNALR_SEPARATOR):
            segment = segment.strip()
            if not segment:
                continue
            rendered = _render_text_segment(segment)
            if rendered is not None:
                lines.append(rendered)
        return "\n".join(lines) if lines else ""

    return ""


def is_signalr_body(raw: bytes) -> bool:
    """Return True if the body looks like SignalR (text or binary protocol)."""
    if is_signalr_binary(raw):
        return True
    # Text protocol: contains record separator AND the content around it looks like JSON
    separator = SIGNALR_SEPARATOR.encode()
    if separator in raw:
        index = raw.index(separator)
        before = raw[max(0, index - 1):index]
        after = raw[index + 1:index + 2]
        # Record separator should be adjacent to JSON delimiters
        if before and before[-1:] in (b"}", b"]") or after and after[:1] in (b"{", b"["):
            return True
        # Fallback: if most content around separator is printable ASCII
        sample = raw[:min(200, len(raw))].decode("utf-8", errors="replace")
        printable = sum(1 for c in sample if 0x20 <= ord(c) <= 0x7E or c in "\n\r\t")
        if printable > len(sample) * 0.5:
            return True
    return False


def is_signalr_path(path: str) -> bool:
    """Return True if the URL path looks like a SignalR / Blazor hub endpoint."""
    lowered = (path or "").lower()
    return "_blazor" in lowered or "/signalr" in lowered or "/hub" in lowered or "/hubs/" in lowered


def decode_body(raw: Optional[bytes], path: str = "") -> Optional[str]:
    """Decode a request/response body, applying SignalR decoding when appropriate."""
    if not raw:
        return None
    if is_signalr_body(raw):
        decoded = decode_signalr_body(raw)
        if decoded:
            return decoded
        logger.debug(
            "SignalR body decode failed — showing raw fallback",
            path=path, first_bytes=raw[:16].hex(), body_len=len(raw),
        )
    text = raw.decode("utf-8", errors="replace")
    if is_signalr_path(path):
        text = _LEADING_BINARY_PREFIX_RE.sub("", text)
    return _CONTROL_CHARS_RE.sub(" ", text)


def body_preview(raw: Optional[bytes], path: str = "") -> Optional[str]:
    """Generate a short body preview for the HTTP history table column."""
    if not raw:
        return None
    if is_signalr_body(raw):
        decoded = decode_signalr_body(raw)
        if decoded:
            first_line = decoded.split("\n")[0]
            return first_line[:120] if first_line else None
    text = raw[:120].decode("utf-8", errors="replace")
    text = _CONTROL_CHARS_RE.sub(" ", text)
    return text if text.strip() else None
