"""LLM-driven login as a LoginStrategy.

When the deterministic form-fill cannot authenticate and the SPA JSON-API path does not apply,
the model reads a page snapshot and drives the browser primitives (fill/click/wait/navigate)
one action at a time — the way a human adapts to an odd field name, a custom submit control,
or an extra consent click.

The LLM step is injected as a ``decide`` callable so the loop is unit-testable without a model
(a scripted decider stands in); the default decider (``make_llm_decider``) routes through
``bedrock_client`` with a schema-forced action and prompt-injection fencing. This strategy does
NOT journal — the cascade driver owns journaling (it knows the host + final outcome).
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from dast.ai import prompt_safety
from dast.browser.login_strategies.base import (
    AuthDecider,
    LoginContext,
    LoginResult,
    current_url,
    looks_authenticated,
)
from dast.utils.logger import get_logger

logger = get_logger(__name__)


class LlmStrategy:
    """LLM-driven fallback over the browser primitives. Always applicable (it is the last
    resort after the deterministic and SPA JSON-API strategies)."""

    name = "llm"

    async def can_attempt(self, ctx: LoginContext) -> bool:
        return True

    async def attempt(self, ctx: LoginContext) -> LoginResult:
        decider = ctx.decide or make_llm_decider()
        logger.info("llm login: escalating to the model", url=ctx.url)
        try:
            await ctx.browser.navigate(ctx.url)
        except Exception as exc:
            logger.warning("llm login: re-navigate before LLM failed", error=str(exc)[:200])

        history: List[Dict[str, Any]] = []
        for step in range(ctx.max_llm_steps):
            current = await current_url(ctx.browser)
            if looks_authenticated(current, ctx.success_url_suffix) and current != ctx.url:
                logger.info("llm login: solved", url=current, steps=step)
                return LoginResult(ok=True, engine="llm", url=current,
                                   llm_steps=step, actions=history)
            try:
                snapshot = await ctx.browser.snapshot()
            except Exception as exc:
                logger.warning("llm login: snapshot failed", error=str(exc)[:200])
                break

            context = {"email": ctx.email, "password": ctx.password,
                       "target_url": ctx.url, "history": list(history)}
            try:
                action = decider(snapshot, context)
            except Exception as exc:
                logger.warning("llm login: decider raised", error=str(exc)[:200])
                break
            if not action or action.get("action") == "stop":
                logger.info("llm login: model chose to stop", step=step)
                break

            history.append(action)
            ok = await _apply_action(ctx.browser, action, ctx.in_scope)
            if not ok:
                logger.debug("llm login: action did not apply cleanly",
                             action=action.get("action"), selector=action.get("selector"))

        final = await current_url(ctx.browser)
        authenticated = looks_authenticated(final, ctx.success_url_suffix) and final != ctx.url
        engine = "llm" if history else "none"
        logger.info("llm login: finished", ok=authenticated, engine=engine,
                    url=final, llm_steps=len(history))
        return LoginResult(
            ok=authenticated, engine=engine, url=final,
            llm_steps=len(history), actions=history,
            error="" if authenticated else "login not completed",
        )


async def _apply_action(browser: Any, action: Dict[str, Any],
                        in_scope: Optional[Callable[[str], bool]] = None) -> bool:
    """Execute one decider action against the browser. Returns False on error.

    A ``navigate`` action is scope-gated: the decider reads untrusted target page content, so
    a prompt-injected navigate to an out-of-scope URL (credential/SSRF exfil) must be refused.
    ``fill``/``click``/``wait`` act on the already-loaded, in-scope page.
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
                logger.warning("llm login: refused out-of-scope navigate", url=selector[:120])
                return False
            await browser.navigate(selector)
        else:
            return False
        return True
    except Exception as exc:
        logger.debug("llm login: _apply_action error", kind=kind, error=str(exc)[:160])
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

    Routed through ``bedrock_client.invoke_json`` with ``LOGIN_ACTION_SCHEMA`` so a malformed
    action is impossible. The untrusted page snapshot is fenced with ``prompt_safety``. Any AI
    error degrades to None (stop), never raising.
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
            logger.warning("llm login: LLM decider call failed", error=str(exc)[:200])
            return None
        if not isinstance(result, dict) or not result.get("action"):
            return None
        return result

    return decide
