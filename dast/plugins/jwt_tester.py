"""
JWT Tester plugin — automatically probes any endpoint where a JWT is detected
in the request (Authorization: Bearer or cookie).

Fires once per unique host+path combination to avoid redundant scanning.

Tests performed (payloads from jwt.yaml):
  1. alg:none bypass (empty signature)
  2. Weak HMAC secret brute-force
  3. Claim privilege escalation (role/admin claim manipulation)
  4. kid parameter injection (path traversal, SQL)
  5. jku header injection (OOB — only when collaborator is available)
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING, Optional, Tuple

import httpx

from dast.payloads.loader import get_payloads
from dast.proxy.plugin_base import ProxyPlugin
from dast.proxy.plugin_manager import log_event
# JWT/base64url primitives live in dast.utils.jwt. Re-exported under the local
# underscore names below for backward compatibility (tests import them here).
from dast.utils.jwt import b64url_decode, b64url_encode, build_token, decode_jwt

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.([A-Za-z0-9_-]*)")


# ── JWT encoding helpers (thin aliases over dast.utils.jwt) ─────────────────

_b64url_decode = b64url_decode
_b64url_encode = b64url_encode
_decode_jwt = decode_jwt
_build_token = build_token


def _find_jwt(headers: dict) -> Optional[Tuple[str, str, str]]:
    """Return (token, header_name, location='header'|'cookie') or None."""
    for k, v in headers.items():
        if k.lower() == "authorization" and v.lower().startswith("bearer "):
            tok = v[7:].strip()
            if _JWT_RE.match(tok):
                return tok, k, "header"
    cookie = headers.get("cookie", "") or headers.get("Cookie", "")
    if cookie:
        for part in cookie.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, val = part.partition("=")
                if _JWT_RE.match(val.strip()):
                    return val.strip(), name.strip(), "cookie"
    return None


def _swap_token(headers: dict, header_name: str, location: str, new_token: str) -> dict:
    out = dict(headers)
    if location == "header":
        out[header_name] = f"Bearer {new_token}"
    else:
        cookie = out.get("cookie", "") or out.get("Cookie", "")
        out["cookie"] = re.sub(
            rf"(?<![A-Za-z0-9_-]){re.escape(header_name)}=[^;]*",
            f"{header_name}={new_token}",
            cookie,
        )
    return out


def _escalate_claims(payload: dict) -> dict:
    out = dict(payload)
    for key in ("role", "roles", "group", "groups", "scope", "scopes"):
        if key in out:
            out[key] = "admin" if isinstance(out[key], str) else list(out[key]) + ["admin"]
    for key in ("admin", "is_admin", "isAdmin", "superuser", "is_superuser"):
        if key in out:
            out[key] = True
    return out


# ── plugin ─────────────────────────────────────────────────────────────────

class JwtTesterPlugin(ProxyPlugin):
    name = "JWT Tester"
    description = (
        "Automatically tests JWT tokens for alg:none bypass, weak secrets, "
        "claim manipulation, kid injection, and jku injection. "
        "Fires once per host+path combination."
    )
    version = "1.0.0"
    author = "Frieren DAST-AI"
    active = True

    def __init__(self) -> None:
        self._seen: set = set()   # (host, path) pairs already tested

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        if entry.response_status is None or entry.method == "CONNECT":
            return

        found = _find_jwt(entry.request_headers)
        if not found:
            return

        from urllib.parse import urlparse
        parsed = urlparse(entry.url)
        key = (entry.host, parsed.path)
        if key in self._seen:
            return
        self._seen.add(key)

        # Fire probes in background — don't block passive scanning
        asyncio.create_task(self._probe(entry, store, found))

    async def _probe(
        self,
        entry: "ProxyEntry",
        store: "SessionStore",
        found: Tuple[str, str, str],
    ) -> None:
        token, header_name, location = found
        decoded = _decode_jwt(token)
        if not decoded:
            return
        orig_header, orig_payload = decoded
        orig_alg = orig_header.get("alg", "")

        # Strip proxy-internal headers; keep auth headers so we replay the original context
        forward_headers = {
            k: v for k, v in entry.request_headers.items()
            if k.lower() not in ("host", "content-length", "transfer-encoding",
                                  "connection", "accept-encoding", "x-dast-crawler")
        }
        forward_headers["x-dast-source"] = "agent"

        body = entry.request_body.decode("utf-8", errors="replace") if entry.request_body else None

        async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(10.0),
                                      follow_redirects=False) as client:
            # Baseline
            try:
                baseline = await client.request(
                    entry.method, entry.url, headers=forward_headers,
                    content=body.encode() if body else None,
                )
            except Exception:
                return
            baseline_status = baseline.status_code
            baseline_text = baseline.text
            baseline_len = len(baseline_text)

            # Verify the JWT is actually enforced: send request without auth header.
            # If the server still responds with matching status+body, the endpoint doesn't
            # use this JWT for authorization — skip all JWT attack tests to avoid FPs.
            no_auth_headers = {k: v for k, v in forward_headers.items()
                               if k.lower() not in ("authorization", "cookie")}
            try:
                no_auth_resp = await client.request(
                    entry.method, entry.url, headers=no_auth_headers,
                    content=body.encode() if body else None,
                )
                # If unauthenticated request gets same success status and non-trivially
                # similar body length, the JWT isn't doing auth — bail out entirely.
                if (no_auth_resp.status_code == baseline_status
                        and baseline_status not in (401, 403)
                        and len(no_auth_resp.text) > 50
                        and abs(len(no_auth_resp.text) - baseline_len) < baseline_len * 0.2):
                    log_event("JWT Tester", "info",
                              "Skipping JWT tests — endpoint accessible without auth token",
                              url=entry.url, source="plugin")
                    return
            except Exception:
                pass

            def _accepted(resp) -> bool:
                if resp is None:
                    return False
                # Probe must return same success status as baseline
                if resp.status_code != baseline_status:
                    if baseline_status in (401, 403) and resp.status_code == 200:
                        return True  # auth bypass: was protected, now open
                    return False
                # Response must be non-trivially long
                if len(resp.text) < 50:
                    return False
                # Response body must be substantially similar to baseline (same data served)
                # to rule out "200 but content differs" (e.g. server returned an error in JSON)
                size_ratio = len(resp.text) / max(baseline_len, 1)
                if not (0.7 <= size_ratio <= 1.3):
                    return False
                return True

            async def _try(new_token: str) -> Optional[httpx.Response]:
                h = _swap_token(forward_headers, header_name, location, new_token)
                try:
                    return await client.request(
                        entry.method, entry.url, headers=h,
                        content=body.encode() if body else None,
                    )
                except Exception:
                    return None

            def _finding(title, severity, cwe, evidence, payload_str, resp):
                resp_snippet = resp.text[:500] if resp else ""
                store.add_finding(entry.id, {
                    "title": title,
                    "severity": severity,
                    "cwe": cwe,
                    "attack_type": "jwt",
                    "evidence": evidence,
                    "payload": payload_str[:200],
                    "parameter": header_name,
                    "confirmed": True,
                    "validated_by": ["passive", "pattern"],
                    "bypass_validation": False,
                    "snippet": resp_snippet,
                }, "vulnerable")
                log_event("JWT Tester", "finding", title, url=entry.url, finding=title, source="plugin")

            # ── 1. alg:none ────────────────────────────────────────────
            for none_hdr_b64 in get_payloads("jwt", "alg_none"):
                try:
                    none_hdr = json.loads(_b64url_decode(none_hdr_b64))
                except Exception:
                    continue
                resp = await _try(_build_token(none_hdr, orig_payload, secret=None))
                if _accepted(resp):
                    _finding(
                        "JWT Algorithm Confusion — alg:none Accepted",
                        "critical", "CWE-347",
                        f"Server accepted unsigned token (alg:{none_hdr.get('alg')}). "
                        f"Original alg: {orig_alg!r}. "
                        f"Response: {resp.status_code} ({len(resp.text)} chars)",
                        f"alg:{none_hdr.get('alg')} + empty signature",
                        resp,
                    )
                    return  # no need to continue after critical

            # ── 2. Weak HMAC secrets ────────────────────────────────────
            if orig_alg.startswith("HS"):
                for secret in get_payloads("jwt", "weak_secrets"):
                    resp = await _try(_build_token(orig_header, orig_payload, secret=secret))
                    if _accepted(resp):
                        _finding(
                            "JWT Signed with Weak Secret",
                            "critical", "CWE-326",
                            f"Server accepted token re-signed with weak secret {secret!r}. "
                            f"alg={orig_alg}.",
                            f"secret={secret!r}",
                            resp,
                        )
                        return

            # ── 3. Claim privilege escalation ───────────────────────────
            escalated = _escalate_claims(orig_payload)
            if escalated != orig_payload:
                for secret in [None] + get_payloads("jwt", "weak_secrets"):
                    hdr = dict(orig_header)
                    if secret is None:
                        hdr["alg"] = "none"
                    resp = await _try(_build_token(hdr, escalated, secret=secret))
                    if _accepted(resp) and len(resp.text) != baseline_len:
                        changed = {k: escalated[k] for k in escalated if escalated.get(k) != orig_payload.get(k)}
                        _finding(
                            "JWT Privilege Escalation via Claim Manipulation",
                            "high", "CWE-285",
                            f"Server accepted modified claims {changed!r}. "
                            f"Response length changed: {baseline_len} → {len(resp.text)} chars.",
                            f"modified claims: {changed}",
                            resp,
                        )
                        return

            # ── 4. kid injection ────────────────────────────────────────
            if "kid" in orig_header:
                for kid_val in get_payloads("jwt", "kid_injection"):
                    hdr = dict(orig_header)
                    hdr["kid"] = kid_val
                    resp = await _try(_build_token(hdr, orig_payload, secret=""))
                    if _accepted(resp):
                        _finding(
                            "JWT kid Parameter Injection",
                            "high", "CWE-22",
                            f"Server accepted token with kid={kid_val!r}.",
                            f"kid={kid_val!r}",
                            resp,
                        )
                        return
