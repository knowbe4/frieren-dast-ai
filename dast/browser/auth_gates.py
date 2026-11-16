"""Agentless auth-bypass — the ARTEX "three auth gates" playbook.

When a login-protected SPA has NO saved credentials, the client-side auth gates
can be fooled so the app renders its post-login shell anyway, and every API
call the shell then fires (session / profile / permission / menu) crosses the
MITM proxy and feeds the normal discovery/scan pipeline — zero credentials, zero
new recording code. Three gates, three mechanisms:

1. STATIC — detect_auth_gates() scans the app's JS bundles for the markers that
   reveal how auth is enforced client-side: token storage keys
   (localStorage/sessionStorage), login-state checks (isLogin/getToken/userInfo),
   axios interceptors injecting Authorization headers, and permission/menu
   route-generation code. The scan ALSO extracts candidate auth-API endpoint
   paths from fetch/axios calls.
2. STORAGE HOOK — an add_init_script that pre-seeds the discovered (or default)
   token keys with a clearly-synthetic value before the app's scripts run, so
   ``isLogin`` style checks pass without any server round-trip.
3. NETWORK STUB — a context.route handler that fulfils requests to the detected
   auth endpoints with a generic "logged-in" JSON (both the ``{code, data}`` and
   the bare ``{user, roles, permissions}`` shapes, roles=["admin"],
   permissions=["*"]) so permission/menu bootstrap endpoints return an admin
   identity. Requests NOT matching the patterns pass through untouched — they
   hit the real backend and are recorded by the proxy as usual.

Scope and safety: stubs only ever affect the browser context (never the proxy's
recording of real traffic), only match auth-looking paths, and the forged token
is a fixed ``dast-bypass`` marker. The backend still returns 401 to anything the
SPA sends for real — a server that trusts these forged identities IS the finding,
and it surfaces through the normal scan pipeline.
"""

from __future__ import annotations

import json as _json
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Same-statement proximity guard (dom_xss_sources._NEAR style): minified bundles
# are one huge line, so unbounded patterns would match anything anywhere.
_NEAR = r"[^;\n\"']{0,120}?"

# ── static gate markers ────────────────────────────────────────────────────────

_STORAGE_AUTH_RE = re.compile(
    r"(?:localStorage|sessionStorage)\.(?:get|set)Item\s*\(\s*[\"']"
    r"([A-Za-z0-9_.\-]*(?:token|Token|auth|Auth|jwt|JWT|session|Session|user|User)"
    r"[A-Za-z0-9_.\-]*)[\"']",
)
_LOGIN_STATE_RE = re.compile(
    r"\b(?:isLogin|is_logged_in|loggedIn|getToken|getUserInfo|userInfo|accessToken)\b"
)
# interceptor + Authorization appear close in real bundles, but the callback
# between them legitimately contains ";" (statements) — bound by length only.
_INTERCEPTOR_RE = re.compile(
    r"interceptors\.request\.use.{0,300}?[Aa]uthorization"
)
_PERMISSION_RE = re.compile(
    r"\b(?:addRoutes|generateRoutes|dynamicRoutes|asyncRoutes|permission_[a-z]+|hasPermission)\b"
)

# Candidate auth-API endpoint paths inside fetch/axios/$.ajax calls. The
# extraction looks for string literals starting with "/" (same-origin API paths)
# that carry an auth-ish keyword.
_AUTH_ENDPOINT_RE = re.compile(
    r"[\"']((?:/[A-Za-z0-9_\-./]*)?"
    r"(?:login|logout|signin|sign-out|signout|auth|token|session|me\b|/me|userinfo|"
    r"user_info|getinfo|get_info|profile|permission|permissions|menu|menus|role|roles)"
    r"[A-Za-z0-9_\-./]*)[\"']",
    re.IGNORECASE,
)

# Storage keys pre-seeded when static detection found nothing specific.
_DEFAULT_STORAGE_KEYS = ("token", "access_token", "Authorization")

# Default URL path patterns (regex, matched against the request URL) — the common
# auth/bootstrap surface of SPA admin frameworks. Endpoint strings discovered
# statically are added on top.
_DEFAULT_AUTH_URL_PATTERNS: tuple = (
    r"/login",
    r"/logout",
    r"/sign-?out",
    r"/me(?:\?|/|$)",
    r"/userinfo",
    r"/user_?info",
    r"/get[iI]nfo",
    r"/permission",
    r"/menu",
    r"/role",
)

_BYPASS_TOKEN = "dast-bypass-token"


@dataclass
class AuthGateReport:
    """What the static scan learned about a SPA's client-side auth enforcement."""

    storage_keys: List[str] = field(default_factory=list)
    gate_kinds: List[str] = field(default_factory=list)   # storage/login_state/interceptor/permission
    endpoint_candidates: List[str] = field(default_factory=list)
    markers: List[str] = field(default_factory=list)      # short evidence snippets

    @property
    def detected(self) -> bool:
        return bool(self.gate_kinds)


@dataclass
class AuthBypassPlan:
    """The executable bypass: storage keys to pre-seed + URL patterns to stub +
    the fake logged-in body. Built from an AuthGateReport (defaults fill gaps)."""

    storage_keys: List[str] = field(default_factory=list)
    url_patterns: List[re.Pattern] = field(default_factory=list)
    fake_body: str = ""

    def matches(self, url: str) -> bool:
        return any(p.search(url) for p in self.url_patterns)


def _fake_logged_in_body() -> str:
    """Generic admin-identity JSON covering the two common response shapes."""
    user = {"id": 1, "username": "dast-bypass", "name": "dast-bypass",
            "admin": True, "avatar": ""}
    body = {
        "code": 200,
        "success": True,
        "message": "ok",
        "data": {
            "user": user,
            "userInfo": user,
            "roles": ["admin"],
            "permissions": ["*"],
            "menus": [],
            "token": _BYPASS_TOKEN,
        },
        "user": user,
        "userInfo": user,
        "roles": ["admin"],
        "permissions": ["*"],
        "token": _BYPASS_TOKEN,
        "accessToken": _BYPASS_TOKEN,
    }
    return _json.dumps(body)


def detect_auth_gates(js_sources: Iterable[str]) -> AuthGateReport:
    """Scan JS bundle sources for client-side auth-enforcement markers and
    candidate auth-API endpoint paths. Pure and deterministic — no network."""
    report = AuthGateReport()
    seen_keys: set = set()
    seen_endpoints: set = set()

    for source in js_sources:
        if not source:
            continue
        for m in _STORAGE_AUTH_RE.finditer(source):
            key = m.group(1)
            if key not in seen_keys:
                seen_keys.add(key)
                report.storage_keys.append(key)
                report.gate_kinds.append("storage")
                report.markers.append(f"storage:{key}")
        if _LOGIN_STATE_RE.search(source) and "login_state" not in report.gate_kinds:
            report.gate_kinds.append("login_state")
            report.markers.append("login-state check (isLogin/getToken/userInfo)")
        if _INTERCEPTOR_RE.search(source) and "interceptor" not in report.gate_kinds:
            report.gate_kinds.append("interceptor")
            report.markers.append("axios interceptor injecting Authorization")
        if _PERMISSION_RE.search(source) and "permission" not in report.gate_kinds:
            report.gate_kinds.append("permission")
            report.markers.append("dynamic route/permission generation")
        for m in _AUTH_ENDPOINT_RE.finditer(source):
            path = m.group(1)
            if (path and len(path) > 1 and path not in seen_endpoints
                    and not path.endswith((".js", ".css", ".png", ".svg", ".woff"))):
                seen_endpoints.add(path)
                report.endpoint_candidates.append(path)

    # Dedup gate kinds while preserving order.
    report.gate_kinds = list(dict.fromkeys(report.gate_kinds))
    report.endpoint_candidates = report.endpoint_candidates[:20]
    return report


def build_bypass_plan(report: Optional[AuthGateReport] = None) -> AuthBypassPlan:
    """Executable plan from a report — detected storage keys/endpoints on top of
    the safe defaults. With no report (or a clean one) the defaults still cover
    the common SPA auth surface."""
    report = report or AuthGateReport()
    storage_keys = list(dict.fromkeys(report.storage_keys or [])) or list(_DEFAULT_STORAGE_KEYS)

    patterns = [re.compile(p) for p in _DEFAULT_AUTH_URL_PATTERNS]
    seen = [p.pattern for p in patterns]
    for path in report.endpoint_candidates:
        pattern = re.escape(path)
        if pattern not in seen:
            seen.append(pattern)
            patterns.append(re.compile(pattern))

    return AuthBypassPlan(
        storage_keys=storage_keys,
        url_patterns=patterns,
        fake_body=_fake_logged_in_body(),
    )


def init_script(plan: AuthBypassPlan) -> str:
    """Pre-navigation hook: seed the storage keys with the bypass token and
    short-circuit fetch/XHR to stubbed auth URLs before the app's scripts run
    (guard-clause style, mirroring RECORDER_INIT_SCRIPT / XSS_PROOF_INIT_SCRIPT)."""
    keys_json = _json.dumps(list(plan.storage_keys))
    patterns_json = _json.dumps([p.pattern for p in plan.url_patterns])
    body_json = _json.dumps(plan.fake_body)
    return """
(() => {
  if (window.__dastAuthBypass) return;
  window.__dastAuthBypass = true;
  const KEYS = %(keys)s;
  const TOKEN = %(token)s;
  const PATTERNS = %(patterns)s.map(p => { try { return new RegExp(p); } catch (e) { return null; } }).filter(Boolean);
  const FAKE_BODY = %(body)s;
  const isAuthUrl = (url) => {
    try {
      const u = String(url);
      return PATTERNS.some(p => p.test(u));
    } catch (e) { return false; }
  };
  const seed = (store) => { try { KEYS.forEach(k => { if (store.getItem(k) === null) store.setItem(k, TOKEN); }); } catch (e) {} };
  try { seed(window.localStorage); } catch (e) {}
  try { seed(window.sessionStorage); } catch (e) {}
  const fakeResponse = (url) => new Response(FAKE_BODY, {
    status: 200,
    headers: { "Content-Type": "application/json", "X-Dast-Bypass": "auth-stub" },
  });
  if (window.fetch) {
    const orig = window.fetch.bind(window);
    window.fetch = (input, init) => {
      const url = typeof input === "string" ? input : (input && input.url) || "";
      if (isAuthUrl(url)) return Promise.resolve(fakeResponse(url));
      return orig(input, init);
    };
  }
  const OrigOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this.__dastAuthUrl = url;
    return OrigOpen.call(this, method, url, ...rest);
  };
  const OrigSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (...args) {
    if (isAuthUrl(this.__dastAuthUrl)) {
      const xhr = this;
      setTimeout(() => {
        try {
          Object.defineProperty(xhr, "status", { value: 200 });
          Object.defineProperty(xhr, "responseText", { value: FAKE_BODY });
          Object.defineProperty(xhr, "response", { value: FAKE_BODY });
          if (typeof xhr.onreadystatechange === "function") xhr.onreadystatechange();
          if (typeof xhr.onload === "function") xhr.onload();
        } catch (e) {}
      }, 0);
      return;
    }
    return OrigSend.apply(this, args);
  };
})();
""" % {
        "keys": keys_json,
        "token": _json.dumps(_BYPASS_TOKEN),
        "patterns": patterns_json,
        "body": body_json,
    }


def matches_auth_url(plan: AuthBypassPlan, url: str) -> bool:
    """Whether a request URL should be fulfilled with the fake logged-in body."""
    try:
        return plan.matches(url)
    except Exception:  # noqa: BLE001 — a bad pattern must never break a request
        return False


def make_route_guard(plan: AuthBypassPlan, forward):
    """A Playwright ``context.route`` handler: requests matching the plan's auth
    URL patterns are fulfilled CLIENT-SIDE with the fake logged-in body (they
    never reach the proxy, so only real traffic is recorded); everything else is
    handed to ``forward`` — which composes with the existing header-injection
    handler, the same way ``read_only.make_route_guard`` composes its forward."""
    async def handler(route) -> None:
        try:
            if matches_auth_url(plan, route.request.url):
                await route.fulfill(
                    status=200,
                    content_type="application/json",
                    body=plan.fake_body,
                )
                return
        except Exception as exc:  # noqa: BLE001 — a stub failure must not drop a request
            logger.debug("auth_gates: stub check failed — forwarding", error=str(exc)[:120])
        await forward(route)
    return handler
