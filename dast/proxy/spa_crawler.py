"""
SPA crawler — launches a Playwright browser routed through the local MITM proxy,
navigates to a target URL, clicks through interactive elements, and records all
API calls into the SessionStore via the proxy (same pipeline as Browse session).

Routing through proxy means:
  - Scope / bypass rules apply automatically
  - Session cookies captured during Browse flow to the crawler automatically
  - All entries are tagged source="crawler" via X-DAST-Crawler header

Designed to be driven from the dashboard: start/stop via asyncio.Event.
Progress is reported via an async callback so the dashboard can push
log lines to the browser over WebSocket.
"""

import asyncio
import time
import uuid
from typing import Callable, List, Optional
from urllib.parse import urlparse

from dast.proxy.session_store import SessionStore
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_CLICKABLE = (
    "button:not([disabled])",
    "a[href]",
    "[role='button']:not([disabled])",
    "[role='tab']",
    "[role='menuitem']",
    "[role='option']",
    "input[type='submit']:not([disabled])",
    "select",
)

_SKIP_HOSTS = {
    "google-analytics.com", "googletagmanager.com", "segment.com",
    "mixpanel.com", "amplitude.com", "hotjar.com", "launchdarkly.com",
    "sentry.io", "bugsnag.com", "fonts.googleapis.com", "fonts.gstatic.com",
}

_SKIP_EXTENSIONS = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                   ".ico", ".woff", ".woff2", ".ttf", ".map", ".webp", ".avif"}

# Destructive actions the crawler must NEVER click — these destroy session or data
_DANGEROUS_KEYWORDS = {
    "logout", "log out", "log-out", "sign out", "sign-out", "signout",
    "delete account", "deactivate", "close account", "cancel account",
    "revoke", "end session", "terminate session",
    "unsubscribe", "remove all", "delete all", "clear all",
    "reset password", "change password",
}

# Header injected by the crawler browser so the proxy can tag entries correctly
_CRAWLER_HEADER = "x-dast-crawler"


class SpaCrawler:
    def __init__(
        self,
        store: SessionStore,
        log_cb: Callable,
        stop_event: asyncio.Event,
        proxy_port: int = 8080,
    ):
        self._store = store
        self._log_cb = log_cb
        self._stop = stop_event
        self._proxy_port = proxy_port
        self.session_id: str = str(uuid.uuid4())[:8]

    def _log(self, msg: str) -> None:
        import inspect
        logger.debug(msg, session_id=self.session_id)
        if inspect.iscoroutinefunction(self._log_cb):
            asyncio.ensure_future(self._log_cb(msg))
        else:
            self._log_cb(msg)

    async def run(
        self,
        target_url: str,
        auth_cookies: Optional[list] = None,  # kept for compat, not needed when routing via proxy
        max_clicks: int = 200,
        headless: bool = True,
        extra_seeds: Optional[List[str]] = None,
    ) -> None:
        from playwright.async_api import async_playwright

        proxy_url = f"http://127.0.0.1:{self._proxy_port}"
        self._log(f"Crawler session {self.session_id} starting → {target_url}")
        self._log(f"Routing through proxy {proxy_url} — scope/bypass rules and session cookies apply")

        # Tag this session in the store so proxy entries get source="crawler"
        self._store.active_crawler_session_id = self.session_id

        parsed = urlparse(target_url)
        base_host = parsed.netloc

        # Build allowed hosts from scope rules — for multi-domain apps
        settings = getattr(self._store, "_settings", None)
        def _is_allowed_host(host: str) -> bool:
            if host == base_host:
                return True
            if settings and settings.is_in_scope(f"https://{host}/"):
                return True
            return False

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=headless,
                proxy={"server": proxy_url},
                args=["--ignore-certificate-errors"],
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 900},
            )

            # Inject crawler header on ALL requests (including JS fetch/XHR)
            # set_extra_http_headers only works for navigation, not subrequests
            _request_count = [0]
            async def _inject_crawler_header(route):
                headers = {**route.request.headers, _CRAWLER_HEADER: self.session_id}
                _request_count[0] += 1
                if _request_count[0] <= 5 or _request_count[0] % 20 == 0:
                    logger.debug("crawler request",
                                 n=_request_count[0],
                                 method=route.request.method,
                                 url=route.request.url[:100],
                                 session_id=self.session_id)
                await route.continue_(headers=headers)
            await context.route("**/*", _inject_crawler_header)

            # Inject session cookies captured by the proxy during the browse/login
            # flow. Uses get_crawl_cookies() (not get_all_cookies()) so cookies
            # from NAMED / headless-credentials logins — which are isolated in
            # named_sessions and invisible to the shared jar — are also injected;
            # otherwise a logged-in user's crawl runs unauthenticated.
            all_cookies = self._store.get_crawl_cookies()
            if all_cookies:
                try:
                    await context.add_cookies(all_cookies)
                    self._log(f"Injected {len(all_cookies)} session cookie(s) from proxy store — crawler will use authenticated session")
                except Exception as exc:
                    # add_cookies is atomic — one malformed cookie rejects the whole
                    # batch. Retry cookie-by-cookie so a single bad entry doesn't
                    # strand an otherwise-valid session (log-and-continue).
                    logger.warning("crawler: batch cookie injection failed, retrying individually", error=str(exc))
                    injected = 0
                    for cookie in all_cookies:
                        try:
                            await context.add_cookies([cookie])
                            injected += 1
                        except Exception as inner:
                            logger.warning("crawler: skipping malformed cookie",
                                           cookie=cookie.get("name", ""), error=str(inner))
                    self._log(f"Injected {injected}/{len(all_cookies)} session cookie(s) from proxy store — crawler will use authenticated session")
            else:
                self._log("No session cookies in proxy store — if the target requires authentication, use the Browse tab to log in first, then start the crawl")

            page = await context.new_page()

            # If the scanner already declared this host unreachable, don't spend a
            # 45s navigation timeout on it — abort the crawl immediately.
            from dast.scanners.active_checks import is_host_dead
            if is_host_dead(parsed.hostname or base_host):
                self._log(f"Host unreachable ({base_host}) — skipping crawl")
                await browser.close()
                self._store.active_crawler_session_id = None
                return

            self._log(f"Navigating to {target_url}")
            try:
                await page.goto(target_url, wait_until="networkidle", timeout=45000)
            except Exception as e:
                # networkidle timeout is common on SPAs with long-poll/websockets — continue anyway
                self._log(f"Navigation note: {e}" if "timeout" in str(e).lower() else f"Navigation error: {e}")
            # Extra settle time for JS frameworks (React/Vue/Angular router)
            await asyncio.sleep(3)

            current_url = page.url
            if current_url != target_url and any(
                kw in current_url.lower() for kw in ("login", "signin", "auth", "sso", "account")
            ):
                self._log(f"WARNING: redirected to login page ({current_url}) — not authenticated")
                self._log(f"Injected {len(all_cookies)} cookie(s) but the session was not accepted — the cookies may be expired, or the login set an Authorization header rather than a cookie")
                self._log("To fix: open the Browse tab, log in to the target again (a fresh login updates the captured session), then start the crawl again")
            else:
                self._log(f"Page loaded: {current_url}")
                # Trigger lazy-loaded content: scroll to bottom then back to top
                try:
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await asyncio.sleep(1)
                    await page.evaluate("window.scrollTo(0, 0)")
                    await asyncio.sleep(0.5)
                except Exception as exc:
                    logger.debug("crawler: scroll failed", error=str(exc))

            # Exploration: click-based route discovery for SPAs
            # SPAs have no <a href> — navigation happens via onClick handlers
            # Strategy: click elements, detect URL changes, go back, repeat
            clicked_fps: set = set()
            visited_routes: set = {page.url.split("?")[0].split("#")[0]}
            discovered_routes: list = []

            # Also collect any real links from DOM (rare in SPAs but helps)
            link_urls: set = set()
            await self._collect_links(page, link_urls, _is_allowed_host)
            for lnk in link_urls:
                lk = lnk.split("?")[0].split("#")[0]
                if lk not in visited_routes:
                    discovered_routes.append(lnk)

            # Main exploration loop: interact + navigate discovered routes
            clicks = 0
            stale_rounds = 0
            while clicks < max_clicks and not self._stop.is_set():
                clicks_before = len(clicked_fps)

                # Interact with current page
                await self._interact_page(page, _is_allowed_host, max_per_page=20,
                                          clicked_fps=clicked_fps,
                                          routes_to_visit=discovered_routes,
                                          visited_urls=visited_routes)
                clicks = len(clicked_fps)

                # If no new clicks happened, try navigating to a discovered route
                if clicks == clicks_before:
                    if discovered_routes:
                        route = discovered_routes.pop(0)
                        route_key = route.split("?")[0].split("#")[0]
                        if route_key in visited_routes:
                            continue
                        visited_routes.add(route_key)
                        # Skip routes on hosts the scanner already found unreachable.
                        if is_host_dead(urlparse(route).hostname or ""):
                            logger.debug("crawler: skipping route on unreachable host", url=route)
                            continue
                        try:
                            await page.goto(route, wait_until="load", timeout=15000)
                        except Exception as exc:
                            logger.debug("crawler: route navigation timeout", url=route, error=str(exc))
                            try:
                                await page.wait_for_load_state("domcontentloaded", timeout=5000)
                            except Exception:
                                logger.debug("crawler: route domcontent timeout, skipping", url=route)
                                continue
                        await asyncio.sleep(1.5)
                        self._log(f"Navigated to: {page.url} ({len(visited_routes)} routes, {len(discovered_routes)} queued)")
                        stale_rounds = 0
                    else:
                        stale_rounds += 1
                        if stale_rounds >= 3:
                            self._log("No new elements or routes — exploration complete")
                            break
                        # Try going back to find more
                        try:
                            await page.go_back()
                            await asyncio.sleep(1)
                        except Exception as exc:
                            logger.debug("crawler: go_back failed", error=str(exc))
                            break
                else:
                    stale_rounds = 0

            # Extra seeds
            seeds = list(extra_seeds or [])
            if seeds:
                self._log(f"Processing {len(seeds)} extra seed URLs")
            for seed_url in seeds:
                if self._stop.is_set():
                    break
                self._log(f"Seed: {seed_url}")
                try:
                    await page.goto(seed_url, wait_until="load", timeout=20000)
                    await asyncio.sleep(1.5)
                    await self._interact_page(page, _is_allowed_host, max_per_page=20,
                                              clicked_fps=clicked_fps,
                                              routes_to_visit=discovered_routes,
                                              visited_urls=visited_routes)
                except Exception as e:
                    self._log(f"Seed navigation error: {e}")

            await browser.close()

        # Clear crawler tag
        self._store.active_crawler_session_id = None

        # Count entries recorded during the crawl
        crawl_start_ts = time.time() - 600
        crawler_entries = [e for e in self._store.all_entries() if e.source == "crawler" and e.ts >= crawl_start_ts]
        browse_entries = [e for e in self._store.all_entries() if e.source == "browse" and e.ts >= crawl_start_ts]
        total_browser_requests = _request_count[0]

        self._log(f"Crawl complete — {clicks} clicks, {len(crawler_entries)} crawler entries, "
                  f"{len(browse_entries)} browse entries, {total_browser_requests} total browser requests")
        if len(crawler_entries) == 0 and total_browser_requests > 0:
            self._log(f"WARNING: Browser made {total_browser_requests} requests but none tagged as crawler. "
                      f"This likely means the proxy source tagging is not working correctly.")
        logger.info("Crawl finished",
                    session_id=self.session_id,
                    clicks=clicks,
                    crawler_entries=len(crawler_entries),
                    browse_entries=len(browse_entries),
                    browser_requests=total_browser_requests,
                    routes_visited=len(visited_routes) if 'visited_routes' in dir() else 0)

    async def _collect_links(self, page, discovered: set, is_allowed_host) -> None:
        """Extract all internal <a href> links from the current page DOM."""
        try:
            links = await page.evaluate("""() => {
                const links = new Set();
                document.querySelectorAll('a[href]').forEach(a => {
                    const href = a.href;
                    if (href && !href.startsWith('javascript:') && !href.startsWith('#'))
                        links.add(href);
                });
                // Also grab navigation items from role=link, data-href, ng-href, routerLink
                document.querySelectorAll('[data-href],[ng-href],[routerlink],[href]').forEach(el => {
                    const h = el.getAttribute('data-href') || el.getAttribute('ng-href')
                              || el.getAttribute('routerlink') || el.getAttribute('href');
                    if (h && h.startsWith('/')) links.add(window.location.origin + h);
                });
                return [...links];
            }""")
            for link in links:
                try:
                    parsed = urlparse(link)
                    if not parsed.netloc:
                        continue
                    if not is_allowed_host(parsed.netloc):
                        continue
                    # Skip static assets
                    path_lower = parsed.path.lower()
                    if any(path_lower.endswith(ext) for ext in _SKIP_EXTENSIONS):
                        continue
                    # Skip dangerous paths
                    if any(seg in path_lower for seg in
                           ("logout", "signout", "sign-out", "log-out", "/delete", "deactivate")):
                        continue
                    discovered.add(link.split("#")[0])
                except Exception as exc:
                    logger.debug("crawler: link parse error", link=link[:100], error=str(exc))
        except Exception as exc:
            logger.warning("crawler: collect_links JS failed", error=str(exc))

    async def _interact_page(self, page, is_allowed_host, max_per_page: int,
                            clicked_fps: set, routes_to_visit: list = None,
                            visited_urls: set = None) -> None:
        """Click interactive elements and track URL changes to discover SPA routes."""
        elements = []
        for selector in _CLICKABLE:
            try:
                els = await page.query_selector_all(selector)
                elements.extend(els)
            except Exception as exc:
                logger.debug("crawler: selector query failed", selector=selector, error=str(exc))

        if elements:
            self._log(f"Found {len(elements)} clickable elements")

        clicked = 0
        url_before = page.url
        for el in elements:
            if self._stop.is_set() or clicked >= max_per_page:
                break
            try:
                visible = await el.is_visible()
                if not visible:
                    continue

                tag = await el.evaluate("e => e.tagName.toLowerCase()")
                text = (await el.text_content() or "").strip()[:60]
                href = await el.get_attribute("href") or ""
                aria = await el.get_attribute("aria-label") or ""

                # Skip destructive elements
                combined = f"{text} {aria} {href}".lower()
                if any(kw in combined for kw in _DANGEROUS_KEYWORDS):
                    continue
                if href and any(seg in href.lower() for seg in
                                ("logout", "signout", "sign-out", "log-out",
                                 "end-session", "revoke", "/delete")):
                    continue

                # For <a> with external href, check scope
                if tag == "a" and href.startswith("http"):
                    if not is_allowed_host(urlparse(href).netloc):
                        continue

                fp = f"{tag}:{text}:{href}:{aria}"
                if fp in clicked_fps:
                    continue
                clicked_fps.add(fp)

                await el.scroll_into_view_if_needed()
                await el.click(timeout=3000)
                clicked += 1
                self._log(f"Clicked <{tag}> '{text or aria}' ({len(clicked_fps)} total)")

                # Wait for SPA route change and API calls
                try:
                    await page.wait_for_load_state("networkidle", timeout=4000)
                except Exception:
                    await asyncio.sleep(0.8)  # networkidle timeout — normal for SPAs with WebSockets

                # Check if URL changed — discovered a new SPA route
                url_after = page.url
                if url_after != url_before and visited_urls is not None:
                    route_key = url_after.split("?")[0].split("#")[0]
                    if route_key not in visited_urls:
                        self._log(f"  → New route: {url_after}")
                        visited_urls.add(route_key)
                    # Stay on new page — wait for API calls to settle (short timeout)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass  # networkidle timeout expected — WebSocket/long-poll keeps network busy
                    url_before = url_after
                    # Break out of element loop to re-scan elements on the new page
                    break

            except Exception as exc:
                logger.debug("crawler: element interaction failed", error=str(exc))
