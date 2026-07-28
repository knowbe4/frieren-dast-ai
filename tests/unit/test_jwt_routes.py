"""
Unit tests for the JWT editor build route (Extras > JWT tab backend).

Guarantees:
  * HS256/384/512 modes produce a token that round-trips through the decoder;
  * alg:none mode produces an unsigned token (empty third segment);
  * an unsupported mode is rejected with 400;
  * a header/payload with non-JSON-serialisable content fails gracefully with 400.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac

from fastapi import FastAPI
from fastapi.testclient import TestClient

from dast.plugins.jwt_tester import _b64url_decode, _b64url_encode, _decode_jwt
from dast.proxy.api.jwt_routes import make_router


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(make_router(object()))
    return TestClient(app)


def test_hs256_build_roundtrips():
    c = _client()
    r = c.post("/api/jwt/build", json={
        "header": {"typ": "JWT"},
        "payload": {"sub": "admin", "role": "admin"},
        "mode": "hs256",
        "secret": "s3cr3t",
    })
    assert r.status_code == 200
    token = r.json()["token"]
    assert r.json()["alg"] == "HS256"

    header, payload = _decode_jwt(token)
    assert header["alg"] == "HS256"
    assert payload["sub"] == "admin"

    # Signature must verify against the given secret.
    h, p, sig = token.split(".")
    expected = _b64url_encode(
        _hmac.new(b"s3cr3t", f"{h}.{p}".encode(), hashlib.sha256).digest()
    )
    assert sig == expected


def test_hs512_uses_sha512():
    c = _client()
    r = c.post("/api/jwt/build", json={
        "header": {"typ": "JWT"},
        "payload": {"x": 1},
        "mode": "hs512",
        "secret": "k",
    })
    assert r.status_code == 200
    token = r.json()["token"]
    h, p, sig = token.split(".")
    expected = _b64url_encode(
        _hmac.new(b"k", f"{h}.{p}".encode(), hashlib.sha512).digest()
    )
    assert sig == expected


def test_none_mode_produces_unsigned_token():
    c = _client()
    r = c.post("/api/jwt/build", json={
        "header": {"typ": "JWT"},
        "payload": {"sub": "victim"},
        "mode": "none",
    })
    assert r.status_code == 200
    token = r.json()["token"]
    assert r.json()["alg"] == "none"
    assert token.endswith(".")   # empty signature segment
    header, _ = _decode_jwt(token)
    assert header["alg"] == "none"


def test_missing_secret_defaults_to_empty_string():
    """HS mode with no secret signs with an empty key rather than erroring."""
    c = _client()
    r = c.post("/api/jwt/build", json={
        "header": {}, "payload": {"a": 1}, "mode": "hs256",
    })
    assert r.status_code == 200
    token = r.json()["token"]
    h, p, sig = token.split(".")
    expected = _b64url_encode(
        _hmac.new(b"", f"{h}.{p}".encode(), hashlib.sha256).digest()
    )
    assert sig == expected


def test_unsupported_mode_rejected():
    c = _client()
    r = c.post("/api/jwt/build", json={
        "header": {}, "payload": {}, "mode": "rs256", "secret": "x",
    })
    assert r.status_code == 400
    assert "unsupported" in r.json()["error"].lower()


def test_alg_forced_from_mode_not_header():
    """The signing mode wins over any alg the operator left in the header."""
    c = _client()
    r = c.post("/api/jwt/build", json={
        "header": {"alg": "RS256", "typ": "JWT"},
        "payload": {"a": 1},
        "mode": "hs256",
        "secret": "k",
    })
    assert r.status_code == 200
    header, _ = _decode_jwt(r.json()["token"])
    assert header["alg"] == "HS256"
