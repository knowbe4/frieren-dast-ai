"""
Low-level SignalR / Blazor (blazorpack) wire primitives.

Single home for the framing pieces that were previously copy-pasted across
`session_store`, `blazor_agent`, and `blazor_detector`: the record separator,
the msgpack varint length prefix (read + write), and the binary-protocol sniff.

Higher-level decoding stays with each caller because the output shapes differ
(human-readable strings for the history view vs. structured dicts for the
detector vs. frame building for the active agent). This module only holds the
byte-level primitives they all share.
"""

from __future__ import annotations

from typing import Tuple

# SignalR text-protocol record separator (0x1e), between JSON messages.
SIGNALR_SEPARATOR = "\x1e"

# DOS/PE "MZ" magic — used to spot a leaked native image in Blazor responses.
MZ_HEADER = b"\x4d\x5a"


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
