"""Deterministic form-fill login as a LoginStrategy.

Wraps ``AgentBrowser.login`` (the DOM form-fill engine) and maps its result to a
``LoginResult``, classifying the outcome into the ``reachable``/``terminal`` signals the
cascade driver uses: a form that could not be REACHED (``reachable=False``) falls through to
the SPA JSON-API strategy; a form that was reached but failed (``reachable=True``) is left to
the LLM; an MFA/CAPTCHA wall is ``terminal`` and stops the cascade.

The ~315-line form-fill itself stays in ``AgentBrowser`` for now (it is deeply coupled to that
class's page/selector helpers); this strategy is a thin, behavior-preserving wrapper and the
physical extraction is deferred.
"""

from __future__ import annotations

from dast.browser.login_strategies.base import (
    LoginContext,
    LoginResult,
    looks_authenticated,
)
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Error-message markers meaning the form could not be REACHED — it is in an iframe/closed
# shadow root (no email/password/submit field), the submit was non-actionable ("no submit
# button actionable" matches via substring), or the fill RAISED. These are the structured
# replacement for the cascade's old ``_form_unreachable`` string gate.
_UNREACHABLE_MARKERS = (
    "no email field", "no password field", "no submit button", "form login raised",
)


def _is_unreachable(error: str) -> bool:
    low = (error or "").lower()
    return any(marker in low for marker in _UNREACHABLE_MARKERS)


class FormStrategy:
    """Deterministic, token-free DOM form-fill. Always attempted (it is the cheapest path)."""

    name = "deterministic"

    async def can_attempt(self, ctx: LoginContext) -> bool:
        return True

    async def attempt(self, ctx: LoginContext) -> LoginResult:
        try:
            det = await ctx.browser.login(ctx.url, ctx.email, ctx.password)
        except Exception as exc:
            logger.warning("form login: deterministic engine raised", error=str(exc)[:200])
            # A raised form-fill (e.g. a submit button that never becomes actionable) must
            # fall through to the SPA JSON strategy, not read as a reachable, succeeding form.
            det = {"logged_in": False, "url": ctx.url,
                   "error": f"form login raised: {str(exc)[:200]}"}

        det_url = str(det.get("url") or ctx.url)
        if det.get("logged_in") and looks_authenticated(det_url, ctx.success_url_suffix):
            logger.info("form login: solved by deterministic engine", url=det_url)
            return LoginResult(ok=True, engine="deterministic", url=det_url, reachable=True)

        # MFA/CAPTCHA are human-in-the-loop walls, not selector problems — stop the cascade.
        if det.get("mfa_required"):
            logger.info("form login: MFA required, not escalating", url=det_url)
            return LoginResult(ok=False, engine="deterministic", url=det_url,
                               error="mfa_required", terminal=True, reachable=True)

        error = str(det.get("error", ""))
        return LoginResult(ok=False, engine="deterministic", url=det_url,
                           error=error, reachable=not _is_unreachable(error))
