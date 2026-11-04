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

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from dast.ai import prompt_safety
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# A decider maps (page_snapshot, context) -> one action dict, or None to stop.
# context carries: email, password, target_url, history (prior actions).
AuthDecider = Callable[[Dict[str, Any], Dict[str, Any]], Optional[Dict[str, Any]]]

_LOGIN_PATHS = ("/login", "/signin", "/sign_in", "/sign-in",
                "/auth/login", "/u/login", "/authorize")
_SSO_DOMAINS = ("auth0", "okta", "login.microsoftonline",
                "accounts.google", "cognito")

_MAX_LLM_STEPS = 8


@dataclass
class LoginCascadeResult:
    """Outcome of an adaptive login attempt."""

    ok: bool
    engine: str  # "deterministic" | "llm" | "none"
    url: str
    llm_steps: int = 0
    actions: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "engine": self.engine,
            "url": self.url,
            "llm_steps": self.llm_steps,
            "actions": self.actions,
            "error": self.error,
        }


def _looks_authenticated(url: str, success_url_suffix: Optional[str]) -> bool:
    """Decide whether *url* represents a logged-in state.

    When ``success_url_suffix`` is given (tests, or a known post-login path) it is
    the ground truth. Otherwise fall back to the heuristic the deterministic engine
    uses: not sitting on a login/auth path and not parked on an SSO domain.
    """
    low = (url or "").lower()
    if success_url_suffix:
        return low.split("?")[0].rstrip("/").endswith(success_url_suffix.rstrip("/"))
    path = low.split("?")[0]
    on_login = any(path.endswith(p) or f"{p}/" in path for p in _LOGIN_PATHS)
    on_sso = any(d in low for d in _SSO_DOMAINS)
    return not on_login and not on_sso


async def _current_url(browser: Any) -> str:
    try:
        snap = await browser.snapshot()
        return str(snap.get("url", ""))
    except Exception:
        return ""


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
        det = {"logged_in": False, "url": url}

    det_url = str(det.get("url") or url)
    if det.get("logged_in") and _looks_authenticated(det_url, success_url_suffix):
        logger.info("adaptive_login: solved by deterministic engine", url=det_url)
        return LoginCascadeResult(ok=True, engine="deterministic", url=det_url)

    # MFA/CAPTCHA are human-in-the-loop walls, not selector problems - do not burn
    # LLM steps trying to brute them. Surface the signal and stop.
    if det.get("mfa_required"):
        logger.info("adaptive_login: MFA required, not escalating to LLM", url=det_url)
        return LoginCascadeResult(ok=False, engine="deterministic", url=det_url,
                                  error="mfa_required")

    # --- Phase 1.5: SPA JSON-API login (DOM-independent) --------------------
    # Only when the deterministic form-fill could NOT REACH the form (no email/password/
    # submit field found) — i.e. the form is in an iframe or a closed shadow root. In that
    # case the app may still expose a JSON auth endpoint we can POST to directly (this is
    # what works for the the SPAs). We gate on "form unreachable" so a login that DID
    # reach the form but needs an extra step (consent/MFA/2FA) is left to the LLM, and so a
    # blind JSON POST is not fired at every ordinary form.
    _err = str(det.get("error", "")).lower()
    _form_unreachable = any(s in _err for s in
                            ("no email field", "no password field", "no submit button"))
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
