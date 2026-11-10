"""Adaptive login: try the deterministic heuristic first, escalate to the LLM only
if it fails.

In a real login attempt we always try the cheap, token-free path first -
``AgentBrowser.login()`` with its fixed selector lists and two-step/SSO/MFA
handling. Only when that cannot reach an authenticated state do we hand control to
the model, which reads a page snapshot and drives the browser primitives
(fill/click/wait/navigate) one action at a time - the way a human adapts when a
form does not look like the common case (odd field names, a custom submit control,
an extra consent click).

The LLM step is injected as a ``decide`` callable so the cascade mechanics are
unit-testable without a model (a scripted decider stands in for the LLM); the
default decider (``make_llm_decider``) routes through ``bedrock_client`` with a
schema-forced action and prompt-injection fencing.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from dast.browser.login_strategies.base import (
    _MAX_LLM_STEPS,
    AuthDecider,
    LoginContext,
    LoginResult,
    looks_authenticated as _looks_authenticated,
)
from dast.browser.login_strategies.llm import (
    LlmStrategy,
    _apply_action,  # noqa: F401 — re-exported; the scope test imports it from this module
    make_llm_decider,  # noqa: F401 — re-exported; evals/tools import it from this module
)
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# The cascade's result type is the shared LoginResult (promoted from the old
# LoginCascadeResult); the alias keeps every `from ... import LoginCascadeResult` caller working.
LoginCascadeResult = LoginResult


def _journal(url: str, outcome: str, **fields: str) -> None:
    """Record a login outcome to the per-host journal (~/.dast-ai). Best-effort: a
    journal error must never break a login."""
    try:
        from dast.session import login_journal
        login_journal.record(url, outcome, **fields)
    except Exception as exc:  # noqa: BLE001 — journaling is non-critical
        logger.debug("adaptive_login: journal write failed", error=str(exc)[:120])


async def adaptive_login(
    browser: Any,
    url: str,
    email: str,
    password: str,
    *,
    decide: Optional[AuthDecider] = None,
    success_url_suffix: Optional[str] = None,
    max_llm_steps: int = _MAX_LLM_STEPS,
    in_scope: Optional[Callable[[str], bool]] = None,
    store: Optional[Any] = None,
    session: Optional[Any] = None,
) -> LoginCascadeResult:
    """Log in, trying the deterministic engine first and the LLM only on failure.

    Returns a :class:`LoginCascadeResult` recording which engine succeeded and the
    actions the LLM took (if any). Never raises - failures degrade to ok=False.
    """
    # --- Phase 1: deterministic, token-free ---------------------------------
    try:
        det = await browser.login(url, email, password)
    except Exception as exc:
        logger.warning("adaptive_login: deterministic engine raised",
                       error=str(exc)[:200])
        # Preserve the failure reason (do NOT wipe it to {}): a raised form-fill
        # (e.g. a disabled submit button that never becomes actionable) must still
        # fall through to the SPA JSON-API strategy below, not be mistaken for a
        # reachable, succeeding form.
        det = {"logged_in": False, "url": url, "error": f"form login raised: {str(exc)[:200]}"}

    det_url = str(det.get("url") or url)
    if det.get("logged_in") and _looks_authenticated(det_url, success_url_suffix):
        logger.info("adaptive_login: solved by deterministic engine", url=det_url)
        _journal(url, "success", strategy="deterministic", success_url=det_url)
        return LoginCascadeResult(ok=True, engine="deterministic", url=det_url)

    # MFA/CAPTCHA are human-in-the-loop walls, not selector problems - do not burn
    # LLM steps trying to brute them. Surface the signal and stop.
    if det.get("mfa_required"):
        logger.info("adaptive_login: MFA required, not escalating to LLM", url=det_url)
        _journal(url, "error", strategy="deterministic", reason="mfa_required")
        return LoginCascadeResult(ok=False, engine="deterministic", url=det_url,
                                  error="mfa_required")

    # --- Phase 1.5: SPA JSON-API login (DOM-independent) --------------------
    # Fire when the deterministic form-fill could not REACH a usable form — the form is
    # in an iframe/closed shadow root ("no email/password/submit field"), OR the submit
    # button is disabled/non-actionable (now surfaced as "no submit button actionable"),
    # OR the form-fill RAISED (preserved as "form login raised"). In those cases the app
    # may still expose a JSON auth endpoint we can POST to directly — what reliably works
    # for these SPAs, and the ONLY path that works under read_only (api_post bypasses the
    # route guard that aborts a form-submit POST). A form that WAS reached but needs an
    # extra step (consent/2FA) is deliberately left to the LLM (it does not match below),
    # so a blind JSON POST is not fired at every ordinary form.
    _err = str(det.get("error", "")).lower()
    _form_unreachable = (
        any(s in _err for s in ("no email field", "no password field", "no submit button"))
        or "form login raised" in _err
    )
    if _form_unreachable:
        try:
            from dast.browser.login_strategies import spa_api
            spa = await spa_api.attempt(browser, url, email, password,
                                        store=store, session=session, in_scope=in_scope)
            if spa.get("ok") and spa.get("logged_in"):
                logger.info("adaptive_login: solved by SPA JSON-API strategy",
                            endpoint=spa.get("endpoint"))
                return LoginCascadeResult(ok=True, engine="spa_api", url=spa.get("url") or url)
        except Exception as exc:
            logger.warning("adaptive_login: spa_api strategy raised", error=str(exc)[:200])

    # --- Phase 2: LLM-driven fallback over the browser primitives -----------
    logger.info("adaptive_login: deterministic engine did not authenticate, "
                "escalating to LLM", url=det_url)
    ctx = LoginContext(
        browser, url, email, password,
        success_url_suffix=success_url_suffix, in_scope=in_scope,
        store=store, session=session, decide=decide, max_llm_steps=max_llm_steps,
    )
    result = await LlmStrategy().attempt(ctx)
    if result.ok:
        _journal(url, "success", strategy=result.engine, success_url=result.url)
    else:
        _journal(url, "error", strategy=result.engine,
                 reason=result.error or "login not completed")
    return result


__all__ = ["adaptive_login", "make_llm_decider", "LoginCascadeResult", "AuthDecider"]
