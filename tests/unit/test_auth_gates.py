"""Unit tests for the agentless auth-bypass engine (dast/browser/auth_gates.py)
and its wiring into proxied_browser_context.

The static scan, the URL matcher, and the route handler are tested with pure
fakes; the context wiring asserts that the init script and the composed route
handler are installed exactly once when an AuthBypassPlan is passed.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from dast.browser import auth_gates


# ── static detection ─────────────────────────────────────────────────────────

_MINIFIED_ADMIN = (
    "var e=JSON.parse(localStorage.getItem(\"access_token\"));if(!e.isLogin)"
    "return next(\"/login\");axios.interceptors.request.use(function(t){var o="
    "sessionStorage.getItem(\"token\");t.headers.Authorization=\"Bearer \"+o;"
    "return t});function generateRoutes(e){fetch(\"/api/userinfo\").then();"
    "axios.post(\"/api/permission/menu\")}"
)


def test_detects_storage_login_interceptor_permission_gates():
    report = auth_gates.detect_auth_gates([_MINIFIED_ADMIN])
    assert "storage" in report.gate_kinds
    assert "login_state" in report.gate_kinds
    assert "interceptor" in report.gate_kinds
    assert "permission" in report.gate_kinds
    assert "access_token" in report.storage_keys
    assert "token" in report.storage_keys
    # Candidate auth endpoints extracted from fetch/axios calls.
    assert any("/api/userinfo" in p for p in report.endpoint_candidates)
    assert any("permission" in p for p in report.endpoint_candidates)
    assert report.detected is True


def test_clean_bundle_yields_no_gates_but_plan_still_has_defaults():
    report = auth_gates.detect_auth_gates([
        "document.querySelector('#app').innerText='hello';console.log(1);"
    ])
    assert report.detected is False
    assert report.storage_keys == []
    plan = auth_gates.build_bypass_plan(report)
    # Defaults still cover the common surface.
    assert plan.storage_keys == list(auth_gates._DEFAULT_STORAGE_KEYS)
    assert plan.matches("https://app.test/api/auth/login")
    assert not plan.matches("https://app.test/api/orders")


def test_detected_endpoints_extend_the_stub_patterns():
    report = auth_gates.detect_auth_gates(["fetch('/api/v2/custom-auth-profile')"])
    plan = auth_gates.build_bypass_plan(report)
    assert plan.matches("https://app.test/api/v2/custom-auth-profile")
    assert not plan.matches("https://app.test/api/v2/orders")


def test_fake_body_covers_both_response_shapes():
    body = json.loads(auth_gates._fake_logged_in_body())
    # {code, data} shape
    assert body["code"] == 200 and body["data"]["roles"] == ["admin"]
    # bare {user, roles} shape
    assert body["user"]["admin"] is True and body["permissions"] == ["*"]
    # clearly synthetic token
    assert "dast-bypass" in body["token"]


# ── init script ──────────────────────────────────────────────────────────────

def test_init_script_seeds_keys_and_patches_fetch_and_xhr():
    plan = auth_gates.build_bypass_plan(
        auth_gates.detect_auth_gates([_MINIFIED_ADMIN]))
    script = auth_gates.init_script(plan)
    # Guard clause + seeding + both transport hooks.
    assert "__dastAuthBypass" in script
    assert "localStorage" in script and "sessionStorage" in script
    assert "window.fetch" in script
    assert "XMLHttpRequest" in script
    # The detected keys and the stub patterns are embedded as data.
    assert "access_token" in script and "/api/userinfo" in script
    # Deterministic (same plan -> same script).
    assert script == auth_gates.init_script(plan)


# ── route stub handler ───────────────────────────────────────────────────────

class _FakeRoute:
    def __init__(self, url, headers=None):
        self.request = SimpleNamespace(url=url, method="GET", headers=headers or {})
        self.fulfilled = None
        self.continued = None

    async def fulfill(self, **kw):
        self.fulfilled = kw

    async def continue_(self, headers=None):
        self.continued = headers


@pytest.mark.asyncio
async def test_auth_urls_are_fulfilled_and_others_forwarded():
    plan = auth_gates.build_bypass_plan(
        auth_gates.detect_auth_gates(["fetch('/api/userinfo')"]))

    async def forward(route):
        route.forwarded = True

    handler = auth_gates.make_route_guard(plan, forward=forward)

    auth_route = _FakeRoute("https://app.test/api/userinfo")
    await handler(auth_route)
    assert auth_route.fulfilled is not None
    assert auth_route.fulfilled["status"] == 200
    assert json.loads(auth_route.fulfilled["body"])["roles"] == ["admin"]
    assert not getattr(auth_route, "forwarded", False)

    normal_route = _FakeRoute("https://app.test/api/orders")
    await handler(normal_route)
    assert getattr(normal_route, "forwarded", False) is True
    assert normal_route.fulfilled is None


@pytest.mark.asyncio
async def test_forward_preserves_header_injection():
    """The composed forward is the existing header-injection handler — crawlers
    keep their session header on non-stubbed requests."""
    plan = auth_gates.build_bypass_plan()

    async def forward(route):
        route.continued = dict(route.request.headers)

    handler = auth_gates.make_route_guard(plan, forward=forward)
    route = _FakeRoute("https://app.test/api/orders", headers={"x-dast-crawler": "sess1"})
    await handler(route)
    assert route.continued.get("x-dast-crawler") == "sess1"


def test_matches_is_total():
    plan = auth_gates.build_bypass_plan()
    assert auth_gates.matches_auth_url(plan, "https://x.test/login") is True
    assert auth_gates.matches_auth_url(plan, "https://x.test/other") is False
    # An empty plan matches nothing, and never raises.
    assert auth_gates.matches_auth_url(auth_gates.AuthBypassPlan(), "https://x.test/login") is False
