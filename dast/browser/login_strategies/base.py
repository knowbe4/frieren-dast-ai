"""The LoginStrategy seam: the shared result/context types and the strategy protocol
that the login cascade is built from.

A login strategy is one way to reach an authenticated state (deterministic form-fill, a
SPA JSON auth endpoint, an LLM driving the browser). Each conforms to ``LoginStrategy``:
``can_attempt`` decides whether it is applicable given what earlier strategies already did,
and ``attempt`` tries it and returns a ``LoginResult``. The cascade driver
(``login_cascade.adaptive_login``) iterates the registered strategies in order, stopping on
the first success or a terminal human wall (MFA/CAPTCHA).

``LoginResult`` carries two kinds of information: the public outcome (``ok``/``engine``/
``url``/... — serialized verbatim by the HTTP route and the agent tools) and internal driver
signals (``terminal``/``reachable``) that stay out of ``to_dict`` so the API/tool contract
never drifts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol

from dast.browser.sso_domains import sso_domains

# A decider maps (page_snapshot, context) -> one action dict, or None to stop.
# context carries: email, password, target_url, history (prior actions).
AuthDecider = Callable[[Dict[str, Any], Dict[str, Any]], Optional[Dict[str, Any]]]

_MAX_LLM_STEPS = 8

_LOGIN_PATHS = ("/login", "/signin", "/sign_in", "/sign-in",
                "/auth/login", "/u/login", "/authorize")
_SSO_DOMAINS = sso_domains()


@dataclass
class LoginResult:
    """Outcome of one login strategy (and, aggregated, of the whole cascade).

    The first six fields are the public contract returned verbatim by ``to_dict`` (the HTTP
    route and agent tools serialize it). ``terminal``/``reachable``/``endpoint`` are internal
    signals the driver and ``can_attempt`` hooks read; they are deliberately NOT serialized.
    """

    ok: bool
    engine: str  # strategy name: "deterministic" | "spa_api" | "llm" | "none"
    url: str
    llm_steps: int = 0
    actions: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""
    # Internal driver signals (not serialized):
    terminal: bool = False  # a human wall (MFA/CAPTCHA): stop the whole cascade, do not escalate
    reachable: Optional[bool] = None  # did this strategy reach its target surface? (form-fill)
    endpoint: str = ""  # the JSON auth endpoint that worked (spa_api only; for journaling)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "engine": self.engine,
            "url": self.url,
            "llm_steps": self.llm_steps,
            "actions": self.actions,
            "error": self.error,
        }


@dataclass
class LoginContext:
    """Everything a strategy needs for one login attempt. Mirrors ``adaptive_login``'s
    arguments, plus ``prior`` (results produced by earlier strategies this attempt, so a
    strategy's ``can_attempt`` can react to them) and defaulted forward-hook slots
    (``flow``/``proxy_port``) for strategies not yet implemented (recorded-flow/SSO)."""

    browser: Any
    url: str
    email: str
    password: str
    totp_secret: Optional[str] = None  # base32 2FA seed (test accounts only)
    success_url_suffix: Optional[str] = None
    in_scope: Optional[Callable[[str], bool]] = None
    store: Any = None
    session: Any = None
    decide: Optional[AuthDecider] = None
    max_llm_steps: int = _MAX_LLM_STEPS
    prior: List[LoginResult] = field(default_factory=list)
    # Forward hooks (unused in Phase 1): a future recorded-flow / SSO strategy joins by
    # reading these instead of changing the protocol.
    flow: Any = None
    proxy_port: Optional[int] = None


class LoginStrategy(Protocol):
    """One way to log in. Strategies are registered and tried in order by the cascade."""

    name: str

    async def can_attempt(self, ctx: LoginContext) -> bool:
        """Whether this strategy applies given ``ctx`` (notably ``ctx.prior``)."""
        ...

    async def attempt(self, ctx: LoginContext) -> LoginResult:
        """Try to log in. Never raises — failures degrade to ``LoginResult(ok=False, ...)``."""
        ...


def looks_authenticated(url: str, success_url_suffix: Optional[str]) -> bool:
    """Decide whether *url* represents a logged-in state.

    When ``success_url_suffix`` is given (tests, or a known post-login path) it is the ground
    truth. Otherwise fall back to the heuristic the deterministic engine uses: not sitting on
    a login/auth path and not parked on an SSO domain.
    """
    low = (url or "").lower()
    if success_url_suffix:
        return low.split("?")[0].rstrip("/").endswith(success_url_suffix.rstrip("/"))
    path = low.split("?")[0]
    on_login = any(path.endswith(p) or f"{p}/" in path for p in _LOGIN_PATHS)
    on_sso = any(d in low for d in _SSO_DOMAINS)
    return not on_login and not on_sso


async def current_url(browser: Any) -> str:
    """The browser's current URL via a snapshot, or '' if it cannot be read."""
    try:
        snap = await browser.snapshot()
        return str(snap.get("url", ""))
    except Exception:
        return ""
