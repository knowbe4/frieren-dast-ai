"""
Login-flow replayer — re-executes a recorded LoginFlow through the proxy.

Runs the steps in a Chromium page routed through the local proxy (headed by
default, so a human can solve an interactive challenge). Credential secrets are
substituted at replay time from the chosen credential — they are never stored in
the flow. When a captcha / bot-wall is detected the replayer calls ``on_pause``
and blocks on ``resume_event`` until the analyst solves it and clicks Continue,
then proceeds (the "call the analyst in, then continue" requirement).

Returns a dict: {success, error, cookies, auth_headers, storage_state, needed_human}.
Never raises to the caller — failures are captured in ``error``.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Awaitable, Callable, Dict, Optional

from dast.profiles.flow import LoginFlow, has_captcha, resolve_value
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_AUTH_HEADER_KEYS = ("authorization", "x-auth-token", "x-api-key")


async def _maybe_pause_for_human(
    page,
    reason: str,
    on_pause: Optional[Callable[[str], Awaitable[None]]],
    resume_event: Optional[asyncio.Event],
    pause_timeout: float,
) -> bool:
    """If a human is needed, notify and block on resume_event. Returns True if paused."""
    if on_pause is None or resume_event is None:
        logger.warning("flow replay blocked but no pause channel wired", reason=reason)
        return False
    logger.info("flow replay pausing for human", reason=reason)
    resume_event.clear()
    await on_pause(reason)
    try:
        await asyncio.wait_for(resume_event.wait(), timeout=pause_timeout)
    except asyncio.TimeoutError:
        logger.warning("flow replay pause timed out", reason=reason, timeout=pause_timeout)
        return True
    logger.info("flow replay resumed by human", reason=reason)
    return True


async def _run_step(page, step, username: str, password: str) -> None:
    """Execute one LoginStep."""
    if step.action == "navigate":
        await page.goto(step.value or "", timeout=step.timeout_ms, wait_until="domcontentloaded")
    elif step.action == "fill":
        value = resolve_value(step, username, password)
        loc = page.locator(step.selector).first
        await loc.wait_for(state="visible", timeout=step.timeout_ms)
        await loc.fill(value)
    elif step.action == "click":
        loc = page.locator(step.selector).first
        await loc.wait_for(state="visible", timeout=step.timeout_ms)
        await loc.click()
    elif step.action == "wait_for":
        if step.selector:
            await page.locator(step.selector).first.wait_for(
                state="visible", timeout=step.timeout_ms
            )
        elif step.value:
            await page.wait_for_url(re.compile(step.value), timeout=step.timeout_ms)
    elif step.action == "press":
        await page.keyboard.press(step.value or "Enter")


async def replay_login_flow(
    *,
    proxy_port: int,
    flow: LoginFlow,
    username: str = "",
    password: str = "",
    headless: bool = False,
    on_pause: Optional[Callable[[str], Awaitable[None]]] = None,
    resume_event: Optional[asyncio.Event] = None,
    pause_timeout: float = 300.0,
) -> Dict[str, Any]:
    """Replay ``flow`` and return the resulting session."""
    from playwright.async_api import async_playwright

    result: Dict[str, Any] = {
        "success": False, "error": "", "cookies": [],
        "auth_headers": {}, "storage_state": None, "needed_human": False,
    }
    if flow.is_empty:
        result["error"] = "flow has no steps"
        return result

    proxy_url = f"http://127.0.0.1:{proxy_port}"
    auth_headers: Dict[str, str] = {}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=headless, proxy={"server": proxy_url},
            args=["--ignore-certificate-errors"],
        )
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        def _on_request(request) -> None:
            for k, v in (request.headers or {}).items():
                if k.lower() in _AUTH_HEADER_KEYS:
                    auth_headers[k] = v

        page.on("request", _on_request)

        try:
            if flow.start_url:
                await page.goto(flow.start_url, timeout=20000, wait_until="domcontentloaded")

            for step in flow.steps:
                # Before each step, check for a bot-wall and hand off to a human.
                try:
                    content = await page.content()
                except Exception:
                    content = ""
                if has_captcha(content):
                    result["needed_human"] = True
                    await _maybe_pause_for_human(
                        page, "captcha detected", on_pause, resume_event, pause_timeout
                    )
                await _run_step(page, step, username, password)

            # Optional explicit success check.
            if flow.success_url_regex:
                try:
                    await page.wait_for_url(re.compile(flow.success_url_regex), timeout=10000)
                except Exception:
                    pass

            cookies = await context.cookies()
            try:
                storage_state = await context.storage_state()
            except Exception:
                storage_state = {"cookies": cookies, "origins": []}
            result.update({
                "success": bool(cookies),
                "cookies": cookies,
                "auth_headers": auth_headers,
                "storage_state": storage_state,
            })
        except Exception as exc:
            logger.error("login flow replay failed", error=str(exc))
            result["error"] = str(exc)
        finally:
            try:
                await browser.close()
            except Exception:
                pass

    return result
