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
from urllib.parse import urlparse

from dast.browser.login_strategies.base import (
    _MAX_LLM_STEPS,
    AuthDecider,
    LoginContext,
    LoginResult,
)
from dast.browser.login_strategies.llm import (
    _apply_action,  # noqa: F401 — re-exported; the scope test imports it from this module
    make_llm_decider,  # noqa: F401 — re-exported; evals/tools import it from this module
)
from dast.browser.login_strategies.registry import ordered_strategies
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
    totp_secret: Optional[str] = None,
    decide: Optional[AuthDecider] = None,
    success_url_suffix: Optional[str] = None,
    max_llm_steps: int = _MAX_LLM_STEPS,
    in_scope: Optional[Callable[[str], bool]] = None,
    store: Optional[Any] = None,
    session: Optional[Any] = None,
) -> LoginCascadeResult:
    """Log in by driving the registered login strategies in order (deterministic form ->
    SPA JSON-API -> LLM by default), stopping at the first success or a terminal human wall
    (MFA/CAPTCHA).

    Returns a :class:`LoginCascadeResult` recording which engine succeeded and the actions the
    LLM took (if any). Never raises - failures degrade to ok=False.
    """
    ctx = LoginContext(
        browser, url, email, password,
        totp_secret=totp_secret,
        success_url_suffix=success_url_suffix, in_scope=in_scope,
        store=store, session=session, decide=decide, max_llm_steps=max_llm_steps,
    )
    host = urlparse(url).hostname
    last = LoginResult(ok=False, engine="none", url=url, error="login not completed")
    for strategy in ordered_strategies(host):
        if not await strategy.can_attempt(ctx):
            continue
        result = await strategy.attempt(ctx)
        ctx.prior.append(result)
        last = result
        # spa_api self-journals (only it knows the endpoint/body-shape); the driver journals
        # the others. An intermediate non-terminal failure is NOT journaled — only a success,
        # a terminal MFA wall, or (below) the final fall-through outcome is.
        if strategy.name != "spa_api":
            if result.ok:
                _journal(url, "success", strategy=result.engine, success_url=result.url)
            elif result.terminal:
                _journal(url, "error", strategy=result.engine,
                         reason=result.error or "login not completed")
        if result.ok or result.terminal:
            return result

    if last.engine != "spa_api":  # spa_api already journaled its own terminal outcome
        _journal(url, "error", strategy=last.engine,
                 reason=last.error or "login not completed")
    return last


__all__ = ["adaptive_login", "make_llm_decider", "LoginCascadeResult", "AuthDecider"]
