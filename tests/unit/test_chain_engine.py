"""
Unit tests for the multi-step attack-chain engine (dast/chains).

Drives the engine with a scripted, offline sender modelled on a common
signed-cookie access-control pattern (unauthenticated bootstrap -> guest token +
signed cookies -> a GraphQL field that leaks an unguessable CDN path -> content
fetch with the anon cookies -> control request that must fail). Covers extraction
(json / set_cookie / b64json / jwt_claim), template substitution, cookie
threading, control-step logic, and the scope + payload-safety gates.
"""

from __future__ import annotations

import base64
import json

import pytest

from dast.chains.engine import ChainEngine
from dast.chains.models import Chain


def _b64url(obj) -> str:
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# CloudFront policy naming a host-agnostic wildcard resource.
_POLICY = _b64url({"Statement": [{"Resource": "*/downloads/*",
                                  "Condition": {"DateLessThan": {"AWS:EpochTime": 1789057813}}}]})
# Guest JWT whose claims show no entitlement (synthetic, fictional).
_JWT = "eyJhbGciOiJSUzI1NiJ9." + _b64url({
    "account": {"can_download": False, "can_preview": False,
                "subscription_level": None, "purchased_skus": []},
}) + ".sig"
_BASE_PATH = "downloads/pkg/AbCd1234XyZ/"


def _scripted_sender():
    """A fake sender that emulates a target's per-step responses."""
    calls = []

    async def sender(method, url, headers, body):
        calls.append((method, url, dict(headers), body))
        has_cookie = "Cookie" in headers and "CloudFront-Policy" in headers.get("Cookie", "")
        has_bearer = "Bearer " in headers.get("Authorization", "")

        if url.endswith("/api/session"):
            set_cookie = (
                f"CloudFront-Policy={_POLICY}; path=/downloads, "
                f"CloudFront-Signature=abc123~def; path=/downloads, "
                f"CloudFront-Key-Pair-Id=APKAEXAMPLE00000000; path=/"
            )
            body_json = json.dumps({"guest": {"cdnJwt": _JWT}, "permissions": {}})
            return 200, {"content-type": "application/json", "set-cookie": set_cookie}, body_json

        if url.endswith("/api/graphql") and has_bearer:
            translations = [
                {"language": {"code": "en-gb"},
                 "activePackage": {"id": 580079, "fileList": {"basePath": _BASE_PATH}}},
                {"language": {"code": "de-de"},
                 "activePackage": {"id": 580080, "fileList": {"basePath": "downloads/pkg/OTHER/"}}},
            ]
            return 200, {"content-type": "application/json"}, json.dumps(
                {"data": {"storeItem": {"translations": translations}}})

        if _BASE_PATH in url:
            if has_cookie:
                return 206, {"content-type": "video/MP2T", "content-range": "bytes 0-63/6677760"}, "x" * 64
            return 403, {"content-type": "text/xml", "server": "CloudFront"}, "<Error><Code>MissingKey</Code></Error>"

        return 404, {}, "not found"

    return sender, calls


def _signed_cookie_chain() -> dict:
    return {
        "name": "guest-token-cdn-access",
        "vuln_type": "broken_access_control",
        "description": "Unauthenticated guest token + wildcard CloudFront cookies defeat a CDN paywall.",
        "steps": [
            {
                "name": "bootstrap",
                "method": "GET",
                "url": "https://store.example.com/api/session",
                "extract": [
                    {"kind": "json", "var": "jwt", "expr": "guest.cdnJwt"},
                    {"kind": "set_cookie", "var": "policy", "expr": "CloudFront-Policy"},
                    {"kind": "b64json", "var": "resource", "expr": "Statement[0].Resource", "from": "var:policy"},
                    {"kind": "jwt_claim", "var": "can_dl", "expr": "account.can_download", "from": "var:jwt"},
                ],
                "assertions": [
                    {"kind": "status_eq", "value": 200},
                    {"kind": "var_present", "var": "jwt"},
                    {"kind": "var_contains", "var": "resource", "needle": "*/downloads/*"},
                    {"kind": "var_equals", "var": "can_dl", "value": "false"},
                ],
            },
            {
                "name": "leak-basepath",
                "method": "POST",
                "url": "https://store.example.com/api/graphql",
                "headers": {"Authorization": "Bearer {{jwt}}", "Content-Type": "application/json"},
                "body": "{\"query\":\"{storeItem(uuid:\\\"x\\\"){translations{activePackage{fileList{basePath}}}}}\"}",
                "extract": [
                    {"kind": "json", "var": "base_path",
                     "expr": "data.storeItem.translations[*].activePackage.fileList.basePath"},
                ],
                "assertions": [
                    {"kind": "status_eq", "value": 200},
                    {"kind": "var_present", "var": "base_path"},
                ],
            },
            {
                "name": "fetch-content",
                "method": "GET",
                "url": "https://store.example.com/{{base_path}}config.json",
                "max_range_bytes": 64,
                "assertions": [
                    {"kind": "status_eq", "value": 206},
                    {"kind": "header_contains", "name": "content-range", "needle": "/6677760"},
                ],
            },
            {
                "name": "control-no-cookies",
                "method": "GET",
                "url": "https://store.example.com/{{base_path}}config.json",
                "send_cookies": [],
                "assertions": [
                    {"kind": "status_in", "values": [401, 403]},
                    {"kind": "body_contains", "needle": "MissingKey"},
                ],
            },
        ],
    }


@pytest.mark.asyncio
async def test_signed_cookie_chain_confirms_end_to_end():
    sender, calls = _scripted_sender()
    engine = ChainEngine(sender=sender, is_in_scope=lambda u: True)
    result = await engine.run(Chain.from_dict(_signed_cookie_chain()))

    assert result.status == "confirmed"
    assert result.confirmed is True
    assert [s.passed for s in result.steps] == [True, True, True, True]

    # The Bearer token bound in step 1 was threaded into step 2's header.
    graphql_call = next(c for c in calls if c[1].endswith("/graphql"))
    assert "Bearer eyJ" in graphql_call[2]["Authorization"]

    # The leaked basePath was templated into step 3's URL.
    content_call = calls[2]
    assert _BASE_PATH in content_call[1]
    # Content fetch was range-capped (never pulls the full asset).
    assert content_call[2].get("Range") == "bytes=0-63"

    # The control step sent NO cookies.
    control_call = calls[3]
    assert "Cookie" not in control_call[2]

    # Secrets are redacted in the reported evidence.
    assert _JWT not in result.evidence


@pytest.mark.asyncio
async def test_control_step_passing_means_credential_not_required():
    """If the 'control' request also succeeds, the cookies were not what mattered."""
    async def sender(method, url, headers, body):
        return 206, {"content-range": "bytes 0-63/100"}, "x" * 64

    chain = {
        "name": "c", "vuln_type": "x",
        "steps": [{
            "name": "control", "url": "https://t.example.com/asset",
            "send_cookies": [],
            "assertions": [{"kind": "status_in", "values": [401, 403]}],
        }],
    }
    engine = ChainEngine(sender=sender, is_in_scope=lambda u: True)
    result = await engine.run(Chain.from_dict(chain))
    assert result.status == "refuted"
    assert result.steps[0].passed is False


@pytest.mark.asyncio
async def test_out_of_scope_step_is_blocked_and_not_sent():
    sent = []

    async def sender(method, url, headers, body):
        sent.append(url)
        return 200, {}, ""

    chain = {"name": "c", "vuln_type": "x", "steps": [
        {"name": "s", "url": "https://evil.example.com/x"},
    ]}
    engine = ChainEngine(sender=sender, is_in_scope=lambda u: False)
    result = await engine.run(Chain.from_dict(chain))
    assert result.status == "blocked"
    assert sent == []  # nothing left the process


@pytest.mark.asyncio
async def test_destructive_payload_is_refused():
    sent = []

    async def sender(method, url, headers, body):
        sent.append(url)
        return 200, {}, ""

    chain = {"name": "c", "vuln_type": "x", "steps": [
        {"name": "s", "method": "POST", "url": "https://t.example.com/admin",
         "body": "'; DROP TABLE users; --"},
    ]}
    engine = ChainEngine(sender=sender, is_in_scope=lambda u: True)
    result = await engine.run(Chain.from_dict(chain))
    assert result.status == "blocked"
    assert sent == []


@pytest.mark.asyncio
async def test_auth_wall_routes_to_needs_auth():
    async def sender(method, url, headers, body):
        return 401, {}, "login required"

    chain = {"name": "c", "vuln_type": "x", "steps": [
        {"name": "s", "url": "https://t.example.com/private",
         "assertions": [{"kind": "status_eq", "value": 200}]},
    ]}
    engine = ChainEngine(sender=sender, is_in_scope=lambda u: True)
    result = await engine.run(Chain.from_dict(chain))
    assert result.status == "needs_auth"
