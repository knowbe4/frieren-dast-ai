"""
Shared Playwright-through-proxy browser launcher.

Both the bounded ``SpaCrawler`` and the exhaustive ``SpaExplorer`` need the same
setup: a Chromium routed through the local MITM proxy, every request tagged with
the crawler header (so entries get ``source="crawler"``), the read-only network
guard, and the captured session cookies injected so the browse runs
authenticated. This module owns that one copy; the two crawlers differ only in
how they drive the page.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Callable, List, Optional

from dast.proxy.session_store import SessionStore
from dast.utils import read_only as read_only_policy
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Header injected by the crawler browser so the proxy can tag entries correctly.
CRAWLER_HEADER = "x-dast-crawler"


@asynccontextmanager
async def proxied_browser_context(
    store: SessionStore,
    proxy_port: int,
    session_id: str,
    *,
    read_only: bool = False,
    headless: bool = True,
    log_cb: Optional[Callable[[str], None]] = None,
):
    """Launch a proxied, authenticated browser context.

    Yields ``(context, page, request_count)`` where ``request_count`` is a
    one-element list whose ``[0]`` is the running request total. Closes the
    browser on exit. ``log_cb`` (optional) receives human-readable progress
    lines for the read-only block counter and cookie-injection summary.
    """
    from playwright.async_api import async_playwright

    def _log(message: str) -> None:
        if log_cb is not None:
            try:
                log_cb(message)
            except Exception as exc:  # noqa: BLE001 — logging must never break a crawl
                logger.debug("browser_session: log_cb failed", error=str(exc))

    proxy_url = f"http://127.0.0.1:{proxy_port}"
    request_count: List[int] = [0]

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=headless,
            proxy={"server": proxy_url},
            args=["--ignore-certificate-errors"],
        )
        try:
            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 900},
            )

            # Inject the crawler header on ALL requests (navigation + fetch/XHR):
            # set_extra_http_headers only covers navigations.
            async def _inject_header(route):
                headers = {**route.request.headers, CRAWLER_HEADER: session_id}
                request_count[0] += 1
                if request_count[0] <= 5 or request_count[0] % 20 == 0:
                    logger.debug("browser request", n=request_count[0],
                                 method=route.request.method,
                                 url=route.request.url[:100], session_id=session_id)
                await route.continue_(headers=headers)

            if read_only:
                blocked = [0]

                def _count_block(method: str, url: str) -> None:
                    blocked[0] += 1
                    if blocked[0] <= 5 or blocked[0] % 20 == 0:
                        _log(f"Read-only: blocked {method} {url[:100]} ({blocked[0]} blocked so far)")

                await context.route("**/*", read_only_policy.make_route_guard(
                    "crawler", forward=_inject_header, on_block=_count_block))
            else:
                await context.route("**/*", _inject_header)

            # Inject session cookies captured by the proxy during browse/login.
            # get_crawl_cookies() also surfaces NAMED/headless-login cookies that
            # live in named_sessions and are invisible to the shared jar.
            cookies = store.get_crawl_cookies()
            if cookies:
                try:
                    await context.add_cookies(cookies)
                    _log(f"Injected {len(cookies)} session cookie(s) — browse will use the authenticated session")
                except Exception as exc:
                    # add_cookies is atomic: one bad cookie rejects the batch.
                    # Retry individually so a single bad entry doesn't strand auth.
                    logger.warning("browser_session: batch cookie injection failed, retrying individually",
                                   error=str(exc))
                    injected = 0
                    for cookie in cookies:
                        try:
                            await context.add_cookies([cookie])
                            injected += 1
                        except Exception as inner:
                            logger.warning("browser_session: skipping malformed cookie",
                                           cookie=cookie.get("name", ""), error=str(inner))
                    _log(f"Injected {injected}/{len(cookies)} session cookie(s) — browse will use the authenticated session")
            else:
                _log("No session cookies in proxy store — if the target requires auth, "
                     "log in via the Browse tab first")

            page = await context.new_page()
            yield context, page, request_count
        finally:
            await browser.close()
