"""Shared account/session-state detection.

One source of truth for "is this browser session a real, authenticated, provisioned account?",
used by the autonomous run's post-login gate-check, the interactive
``activate_login_profile`` self-heal, the login-flow replayer, the SPA JSON login
strategy, and the LLM login strategy. Keeping it here (not in the proxy API layer) lets
the tools layer reuse it without depending on the dashboard service.

The public entry point is :func:`verify_authenticated` — a tri-state verdict
(True verified / False contradicted / None indeterminate) built from structural
evidence instead of the lying signals it replaces: "any cookie exists"
(``flow_replayer`` used to declare success on an analytics cookie) and "URL does
not contain /login" (a failed login that lands on /welcome reads as OK).
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional
from urllib.parse import urlparse

from dast.triage.auth_wall import looks_like_auth_wall
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# A fetch adapter: async (url) -> {"ok": bool, "status": int|None, "text": str} —
# the shape AgentBrowser.api_get already returns, so every transport wraps into it.
Fetch = Callable[[str], Awaitable[Dict[str, Any]]]

# Cookie-name substrings that suggest a SESSION cookie (as opposed to the analytics /
# CDN cookies any page visit accumulates — Cloudflare's cf_bm, Google's _ga, ...).
_SESSION_COOKIE_MARKERS = ("session", "sid", "auth", "token", "jwt")


@dataclass
class AuthVerdict:
    """Tri-state login verdict + the evidence behind it.

    ``authenticated``: True when structural evidence positively confirms a real
    authenticated session; False when evidence positively CONTRADICTS it (auth wall,
    401/403, guest account, expected session cookie missing); None when the transport
    or the app shape yields nothing conclusive — callers fail open on None (legacy
    behavior) rather than block a legitimate login.
    """

    authenticated: Optional[bool]
    reason: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthProbeConfig:
    """Per-profile probe expectations (mirrors ``LoginProfile.probe_*`` fields).

    When any field is set, login success is CONFIRMED against this config instead of
    falling back to weak heuristics: the probe endpoint must not be an auth wall, the
    dot-path must resolve truthy in the response JSON, and the named cookie must be
    present in the session jar.
    """

    probe_url: str = ""  # absolute URL or path resolved against the target origin
    expect_json_path: str = ""  # e.g. "user.id" — must resolve truthy in the JSON body
    expect_cookie: str = ""  # cookie name that must exist post-login

    @classmethod
    def from_profile(cls, profile: Any) -> "AuthProbeConfig":
        get = getattr(profile, "probe_url", "") or ""
        return cls(
            probe_url=get,
            expect_json_path=getattr(profile, "probe_expect_json_path", "") or "",
            expect_cookie=getattr(profile, "probe_expect_cookie", "") or "",
        )

    @property
    def configured(self) -> bool:
        return bool(self.probe_url or self.expect_json_path or self.expect_cookie)


def api_get_fetch(browser: Any) -> Fetch:
    """Wrap ``AgentBrowser.api_get`` into the transport-agnostic :data:`Fetch` shape."""
    async def _fetch(url: str) -> Dict[str, Any]:
        return await browser.api_get(url)
    return _fetch


def _normalize_cookies(session_cookies: Any) -> Dict[str, str]:
    """Accept Playwright cookie dicts (``[{"name": ..., "value": ...}]``) or a flat
    ``{name: value}`` mapping; return the flat name->value form."""
    if not session_cookies:
        return {}
    if isinstance(session_cookies, dict):
        return {str(k): str(v) for k, v in session_cookies.items()}
    out: Dict[str, str] = {}
    for c in session_cookies:
        try:
            out[str(c.get("name", ""))] = str(c.get("value", ""))
        except AttributeError:
            continue
    return out


def _looks_like_session_cookie(cookies: Dict[str, str]) -> Optional[str]:
    """Name of the first cookie that plausibly carries the session, or None."""
    for name in cookies:
        low = name.lower()
        if any(m in low for m in _SESSION_COOKIE_MARKERS):
            return name
    return None


def _json_path_get(data: Any, path: str) -> Any:
    """Resolve a dotted path ("user.id") inside parsed JSON; None when absent."""
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def session_is_provisioned(data: dict) -> Optional[bool]:
    """Classify an app session-endpoint JSON body (e.g. a ``/spa/session`` endpoint).

    Returns False only when it positively reports a guest/unprovisioned account
    (account id ``-1``/``<=0`` or an explicit guest marker), True when it reports a
    real account, and None when it can't tell — so the caller fails open on an
    unknown app rather than blocking a legitimate login.
    """
    if not isinstance(data, dict):
        return None
    account_id: Any = None
    account = data.get("account")
    if isinstance(account, dict):
        account_id = account.get("id")
    if account_id is None:
        user = data.get("user")
        if isinstance(user, dict):
            account_id = user.get("account_id") or user.get("accountId")
    if account_id is None:
        account_id = data.get("account_id") or data.get("accountId")
    if account_id is not None:
        try:
            return int(account_id) > 0
        except (TypeError, ValueError):
            return None
    user = data.get("user")
    if isinstance(user, dict) and user:
        return True
    if data.get("guest") is True:
        return False
    return None


async def _fetch_json(fetch: Fetch, url: str) -> Optional[dict]:
    """GET ``url`` through the adapter and parse the body as JSON; None on any failure."""
    resp = await fetch(url)
    if not resp.get("ok") or resp.get("status") != 200:
        return None
    try:
        data = _json.loads(resp.get("text") or "")
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


async def session_endpoint_state(
    fetch: Fetch,
    base_url: str,
    probe: Optional[AuthProbeConfig] = None,
) -> Optional[bool]:
    """Classify the app session endpoint (part (b) of the historical check).

    Probes ``probe.probe_url`` (absolute, or a path resolved against the origin) —
    default ``/spa/session``, the KMSAT-style endpoint this check was built for — with
    ``X-Requested-With: XMLHttpRequest`` and classifies the body with
    :func:`session_is_provisioned`. A configured ``expect_json_path`` overrides the
    generic classifier: it must resolve truthy for True, and its ABSENCE alongside a
    200 is NOT a contradiction (the app may shape the endpoint differently) — only a
    positively guest-shaped body or an auth wall contradicts. Returns None when the
    endpoint is missing/non-JSON/non-200 so callers fail open. Never raises.
    """
    try:
        parsed = urlparse(base_url)
        if not parsed.scheme or not parsed.netloc:
            return None
        origin = f"{parsed.scheme}://{parsed.netloc}"
        raw = (probe.probe_url if probe and probe.probe_url else "") or "/spa/session"
        url = raw if raw.startswith("http") else origin + (raw if raw.startswith("/") else f"/{raw}")

        resp = await fetch(url)
        status = resp.get("status")
        text = resp.get("text", "") or ""
        # A wall is classified on the STATUS first — a 401/403 IS a valid response,
        # so do not gate the check on the transport's 2xx-style `ok` flag.
        if status is not None and looks_like_auth_wall(int(status or 0), url, text):
            return False
        if not resp.get("ok") or status != 200:
            return None
        data = _json.loads(text)
        provisioned = session_is_provisioned(data)
        if provisioned is not None:
            return provisioned
        if probe and probe.expect_json_path:
            # Truthy path → confirmed. An ABSENT path is NOT a contradiction — the
            # app may shape the endpoint differently — it just yields no evidence.
            return True if _json_path_get(data, probe.expect_json_path) else None
        return None
    except (ValueError, TypeError):
        return None
    except Exception as exc:  # noqa: BLE001 — detection is best-effort, never break the caller
        logger.debug("account_state: session endpoint check skipped", error=str(exc)[:160])
        return None


async def verify_authenticated(
    fetch: Fetch,
    *,
    base_url: str,
    probe: Optional[AuthProbeConfig] = None,
    session_cookies: Any = None,
) -> AuthVerdict:
    """Tri-state structural verdict on whether a session is really authenticated.

    Evidence tiers (first match wins):

    1. NEGATIVE — the origin root or the probe endpoint is an auth wall
       (:func:`dast.triage.auth_wall.looks_like_auth_wall`) → ``False``.
    2. NEGATIVE — a configured ``expect_cookie`` is absent from the session jar →
       ``False`` (the operator defined the session; its absence IS the answer).
    3. POSITIVE — the probe endpoint reports a provisioned account
       (:func:`session_is_provisioned`) or the configured ``expect_json_path``
       resolves truthy → ``True``.
    4. POSITIVE — any session-looking cookie exists in the jar (name containing
       session/sid/auth/token/jwt — cf_bm/_ga do not count) → ``True``.
    5. None — nothing conclusive; callers fail open.

    ``fetch`` is an async adapter returning ``{"ok", "status", "text"}``
    (:func:`api_get_fetch` wraps an AgentBrowser; the flow replayer wraps
    ``page.request``). ``session_cookies`` accepts Playwright cookie dicts or a flat
    name->value map. Never raises.
    """
    evidence: Dict[str, Any] = {}
    try:
        cookies = _normalize_cookies(session_cookies)
        parsed = urlparse(base_url)
        if parsed.scheme and parsed.netloc:
            origin = f"{parsed.scheme}://{parsed.netloc}"
            # (1a) Root wall: a GET of / that renders a login page is a clear contradiction.
            root = await fetch(f"{origin}/")
            root_status = root.get("status")
            # Same as the endpoint check: classify on status, not on the ok flag.
            if root_status is not None and looks_like_auth_wall(
                    int(root_status or 0), f"{origin}/", root.get("text", "") or ""):
                return AuthVerdict(False, "origin root is an auth wall",
                                   {"probe": f"{origin}/", "status": root_status})
            # (1b/3) The probe endpoint (explicit config, else the classic /spa/session).
            endpoint_verdict = await session_endpoint_state(fetch, base_url, probe)
            if endpoint_verdict is False:
                return AuthVerdict(False, "session endpoint reports an auth wall or guest",
                                   evidence)
            if endpoint_verdict is True:
                return AuthVerdict(True, "session endpoint reports a provisioned account",
                                   evidence)
        # (2) A configured cookie is a hard expectation — but only when the caller
        # actually handed over the jar; without it the absence proves nothing.
        if probe and probe.expect_cookie and session_cookies is not None:
            if probe.expect_cookie in cookies:
                evidence["session_cookie"] = probe.expect_cookie
                return AuthVerdict(True, "expected session cookie present", evidence)
            return AuthVerdict(False, "expected session cookie missing",
                               {"expected_cookie": probe.expect_cookie})
        # (4) Session-looking cookie heuristic (replaces `bool(cookies)`).
        name = _looks_like_session_cookie(cookies)
        if name:
            evidence["session_cookie"] = name
            return AuthVerdict(True, "session cookie present", evidence)
        return AuthVerdict(None, "no conclusive evidence", evidence)
    except Exception as exc:  # noqa: BLE001 — detection is best-effort, never break the caller
        logger.debug("account_state: verify_authenticated skipped", error=str(exc)[:160])
        return AuthVerdict(None, f"verification error: {str(exc)[:120]}", evidence)


async def session_is_authenticated(
    browser: Any,
    base_url: str,
    probe: Optional[AuthProbeConfig] = None,
) -> Optional[bool]:
    """Best-effort check that the browser's current session is a real, authenticated account.

    False only when positively unauthenticated (auth wall) or a guest/unprovisioned account; True
    on a real account; None when it can't tell (so callers fail open rather than force a needless
    re-login). ``probe`` (from the profile) overrides the default ``/spa/session`` endpoint and
    adds cookie expectations. Never raises.
    """
    try:
        # This check classifies a browser context whose cookie jar is NOT handed over,
        # so drop the expect_cookie leg (its absence would read as a false contradiction);
        # only the probe endpoint + JSON expectations apply here.
        endpoint_probe = AuthProbeConfig(
            probe_url=probe.probe_url if probe else "",
            expect_json_path=probe.expect_json_path if probe else "",
        )
        verdict = await verify_authenticated(
            api_get_fetch(browser), base_url=base_url, probe=endpoint_probe,
            session_cookies=None,
        )
        return verdict.authenticated
    except Exception as exc:  # noqa: BLE001 — detection is best-effort, never break the caller
        logger.debug("account_state: session check skipped", error=str(exc)[:160])
        return None
