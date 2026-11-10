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

from typing import Any, Callable, Dict, List, Optional

from dast.ai import prompt_safety
from dast.browser.login_strategies.base import (
    _MAX_LLM_STEPS,
    AuthDecider,
    LoginResult,
    current_url as _current_url,
    looks_authenticated as _looks_authenticated,
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
    decider = decide or make_llm_decider()
    logger.info("adaptive_login: deterministic engine did not authenticate, "
                "escalating to LLM", url=det_url)
    try:
        await browser.navigate(url)
    except Exception as exc:
        logger.warning("adaptive_login: re-navigate before LLM failed",
                       error=str(exc)[:200])

    history: List[Dict[str, Any]] = []
    for step in range(max_llm_steps):
        current = await _current_url(browser)
        if _looks_authenticated(current, success_url_suffix) and current != url:
            logger.info("adaptive_login: solved by LLM fallback",
                        url=current, steps=step)
            _journal(url, "success", strategy="llm", success_url=current)
            return LoginCascadeResult(ok=True, engine="llm", url=current,
                                      llm_steps=step, actions=history)
        try:
            snapshot = await browser.snapshot()
        except Exception as exc:
            logger.warning("adaptive_login: snapshot failed", error=str(exc)[:200])
            break

        context = {"email": email, "password": password,
                   "target_url": url, "history": list(history)}
        try:
            action = decider(snapshot, context)
        except Exception as exc:
            logger.warning("adaptive_login: decider raised", error=str(exc)[:200])
            break
        if not action or action.get("action") == "stop":
            logger.info("adaptive_login: LLM chose to stop", step=step)
            break

        history.append(action)
        ok = await _apply_action(browser, action, in_scope)
        if not ok:
            logger.debug("adaptive_login: action did not apply cleanly",
                         action=action.get("action"), selector=action.get("selector"))

    final = await _current_url(browser)
    authenticated = _looks_authenticated(final, success_url_suffix) and final != url
    engine = "llm" if history else "none"
    logger.info("adaptive_login: finished", ok=authenticated, engine=engine,
                url=final, llm_steps=len(history))
    if authenticated:
        _journal(url, "success", strategy=engine, success_url=final)
    else:
        _journal(url, "error", strategy=engine, reason="login not completed")
    return LoginCascadeResult(
        ok=authenticated, engine=engine, url=final,
        llm_steps=len(history), actions=history,
        error="" if authenticated else "login not completed",
    )


async def _apply_action(browser: Any, action: Dict[str, Any],
                        in_scope: Optional[Callable[[str], bool]] = None) -> bool:
    """Execute one decider action against the browser. Returns False on error.

    A ``navigate`` action is scope-gated: the decider reads untrusted target page
    content, so a prompt-injected navigate to an out-of-scope URL (credential/SSRF
    exfil) must be refused. ``fill``/``click``/``wait`` act on the already-loaded,
    in-scope page.
    """
    kind = str(action.get("action") or "").lower()
    selector = str(action.get("selector") or "")
    try:
        if kind == "fill":
            await browser.fill(selector, str(action.get("value") or ""))
        elif kind == "click":
            await browser.click(selector, expect_nav=bool(action.get("expect_navigation")))
        elif kind == "wait":
            await browser.wait_for(selector)
        elif kind == "navigate":
            if in_scope is not None and not in_scope(selector):
                logger.warning("adaptive_login: refused out-of-scope navigate",
                               url=selector[:120])
                return False
            await browser.navigate(selector)
        else:
            return False
        return True
    except Exception as exc:
        logger.debug("adaptive_login: _apply_action error",
                     kind=kind, error=str(exc)[:160])
        return False


_DECIDER_SYSTEM = """\
You are driving a web browser to log in to an application on behalf of an \
authorized security operator. The deterministic auto-login already failed, so you \
must adapt like a human: look at the page snapshot and choose exactly ONE next \
browser action that advances the login.

Rules:
- Fill the username/email field with the provided email, and the password field \
with the provided password. Never invent or guess credentials.
- Identify fields and buttons from the snapshot (names, ids, types, button text). \
Prefer stable selectors (#id, [name=...], input[type=...]).
- The page may have MORE THAN ONE form (e.g. a header search box). Act only on the \
login form: match the field/button to the login form's id/name and, when several \
forms exist, scope the selector to it (e.g. "#login-form input[type=submit]", \
"form[name=loginform] [type=submit]"). A generic "button[type=submit]" may hit a \
search or newsletter button instead - avoid it when multiple submits exist.
- To submit, pick the control whose text clearly means sign-in (Sign In, Log In, \
Continue, Next, Yes), never one that says Search/Go/Subscribe.
- Some flows need an extra click (Continue/Next) before the password appears, or a \
consent/Authorize/Stay-signed-in button after the password. Take them one step at a time.
- Do not attempt to solve CAPTCHAs or MFA/OTP challenges; choose "stop" if you hit one.
- Choose "stop" when the page is clearly logged in, or when no action can progress."""


def make_llm_decider(model_id: Optional[str] = None) -> AuthDecider:
    """Default decider: ask the model for the next login action, schema-forced.

    Routed through ``bedrock_client.invoke_json`` with ``LOGIN_ACTION_SCHEMA`` so a
    malformed action is impossible. The untrusted page snapshot is fenced with
    ``prompt_safety``. Any AI error degrades to None (stop), never raising.
    """
    import json

    from dast.ai import bedrock_client
    from dast.ai.schemas import LOGIN_ACTION_SCHEMA

    def decide(snapshot: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        snapshot_json = json.dumps({
            "url": snapshot.get("url"),
            "title": snapshot.get("title"),
            "forms": snapshot.get("forms"),
            "buttons": snapshot.get("buttons"),
            "links": snapshot.get("links"),
        }, default=str)[:8000]
        history_json = json.dumps(context.get("history") or [], default=str)[:2000]
        user = (
            f"Credentials to use:\n  email: {context.get('email')}\n"
            f"  password: {context.get('password')}\n\n"
            f"Actions already taken this attempt:\n{history_json}\n\n"
            "Current page snapshot:\n"
            + prompt_safety.wrap_untrusted(snapshot_json, "page_snapshot")
            + "\n\nReturn the single next action."
        )
        system = _DECIDER_SYSTEM + "\n\n" + prompt_safety.UNTRUSTED_CONTENT_DIRECTIVE
        try:
            result = bedrock_client.invoke_json(
                system=system,
                user=user,
                model_id=model_id,
                temperature=0,
                schema=LOGIN_ACTION_SCHEMA,
            )
        except Exception as exc:
            logger.warning("adaptive_login: LLM decider call failed",
                           error=str(exc)[:200])
            return None
        if not isinstance(result, dict) or not result.get("action"):
            return None
        return result

    return decide


__all__ = ["adaptive_login", "make_llm_decider", "LoginCascadeResult", "AuthDecider"]
