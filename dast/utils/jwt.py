"""
JWT and base64url helpers — single home for the hand-rolled JWT logic that was
previously reimplemented across the JWT plugins, the business-logic agent, and
the service graph.

No external PyJWT dependency: encoding is plain base64url over stdlib `base64`,
signing uses stdlib `hmac`/`hashlib`. Callers that only need a segment decoded
use `b64url_decode`; callers that want the parsed header/payload use
`decode_jwt`; token construction (alg:none or HMAC) uses `build_token`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Optional, Tuple

# HMAC algorithms supported by build_token; anything else falls back to SHA-256.
_HMAC_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment to raw bytes, tolerating missing padding."""
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def b64url_encode(data: bytes) -> str:
    """Encode raw bytes as base64url with padding stripped (JWT segment form)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_encode_json(data: dict) -> str:
    """Encode a dict as a compact JSON base64url segment (JWT header/payload)."""
    return b64url_encode(json.dumps(data, separators=(",", ":")).encode())


def decode_segment(segment: str) -> dict:
    """Decode a single base64url JWT segment to its parsed JSON object."""
    return json.loads(b64url_decode(segment))


def decode_jwt(token: str) -> Optional[Tuple[dict, dict]]:
    """Return (header, payload) for a well-formed 3-part JWT, else None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return decode_segment(parts[0]), decode_segment(parts[1])
    except Exception:
        return None


def decode_jwt_header(token: str) -> Optional[dict]:
    """Return the decoded JWT header (first segment), or None on failure."""
    parts = token.split(".")
    if not parts or not parts[0]:
        return None
    try:
        return decode_segment(parts[0])
    except Exception:
        return None


def decode_jwt_claims(token: str) -> Optional[dict]:
    """Return the decoded JWT payload claims (second segment), or None."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        return decode_segment(parts[1])
    except Exception:
        return None


def build_token(header: dict, payload: dict, secret: Optional[str] = None) -> str:
    """Build a JWT. secret=None yields an unsigned (alg:none) token with an
    empty signature; otherwise HMAC-sign using the algorithm in the header."""
    encoded_header = b64url_encode_json(header)
    encoded_payload = b64url_encode_json(payload)
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    if secret is None:
        signature = ""
    else:
        hash_fn = _HMAC_HASHES.get(header.get("alg", "HS256"), hashlib.sha256)
        signature = b64url_encode(hmac.new(secret.encode(), signing_input, hash_fn).digest())
    return f"{encoded_header}.{encoded_payload}.{signature}"
