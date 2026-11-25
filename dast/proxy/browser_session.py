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
from typing import TYPE_CHECKING, Callable, List, Optional

from dast.proxy.session_store import SessionStore
from dast.utils import read_only as read_only_policy
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.browser.auth_gates import AuthBypassPlan

logger = get_logger(__name__)

# Header injected by the crawler browser so the proxy can tag entries correctly.
CRAWLER_HEADER = "x-dast-crawler"


def _named_session_cookies(
    store: "SessionStore", session_name: Optional[str], target_host: Optional[str]
) -> List[dict]:
    """Cookies of the active login-profile session to seed the crawler with.

    When a copilot run has authenticated via ``activate_login_profile`` the
    resulting session's cookies live in ``store.named_sessions[session_name]``,
    NOT in the shared Browse jar / ``auth_storage_state``. Pull them here so the
    crawl/explore browser context rides that session and crawls AUTHENTICATED.

    Host-scoped (same matching as the raw-tool auth path) when the target host is
    known, falling back to the session's full cookie set when the host-scoped view
    is empty (the browser still domain-gates each cookie). Returns [] for a
    non-copilot caller (no ``session_name``) so the legacy Browse-flow seeding is
    left untouched. Never raises."""
    if not session_name:
        return []
    try:
        if target_host and hasattr(store, "get_named_session_cookies_for_host"):
            scoped = store.get_named_session_cookies_for_host(session_name, target_host) or []
            if scoped:
                return scoped
        if hasattr(store, "get_named_session_cookies"):
            return store.get_named_session_cookies(session_name) or []
    except Exception as exc:  # noqa: BLE001 — fall back to the Browse jar on any error
        logger.warning("browser_session: named-session cookie read failed",
                       session_name=session_name, error=str(exc))
    return []


async def _auth_storage_state(store: "SessionStore") -> Optional[dict]:
    """The authenticated Playwright storage_state to seed the crawler with, if any.

    Prefers a LIVE Browse login (snapshot its context now so it is fresh), else the
    last captured blob persisted when a login closed. Returns None when neither is
    available (crawler then falls back to the Set-Cookie cookie jar). A storage_state
    with no cookies and no origins is treated as empty.
    """
    session = getattr(store, "active_browse_session", None)
    if session is not None:
        try:
            state = await session.get_storage_state()
            if state and (state.get("cookies") or state.get("origins")):
                # Persist the fresh login so it survives a proxy restart without the
                # operator having to log in again (updated on every crawl seed).
                from dast.proxy.auth_state_store import save_auth_state
                store.auth_storage_state = state
                save_auth_state(state)
                return state
        except Exception as exc:  # noqa: BLE001 — fall back to the jar on any error
            logger.warning("browser_session: live storage_state capture failed", error=str(exc))
    blob = getattr(store, "auth_storage_state", None)
    if blob and (blob.get("cookies") or blob.get("origins")):
        return blob
    return None


@asynccontextmanager
async def proxied_browser_context(
    store: SessionStore,
    proxy_port: int,
    session_id: str,
    *,
    read_only: bool = False,
    headless: bool = True,
    log_cb: Optional[Callable[[str], None]] = None,
    auth_bypass: Optional["AuthBypassPlan"] = None,
    session_name: Optional[str] = None,
    target_host: Optional[str] = None,
):
    """Launch a proxied, authenticated browser context.

    Yields ``(context, page, request_count)`` where ``request_count`` is a
    one-element list whose ``[0]`` is the running request total. Closes the
    browser on exit. ``log_cb`` (optional) receives human-readable progress
    lines for the read-only block counter and cookie-injection summary.

    ``session_name`` (optional, in-process copilot): the active login-profile
    session's name. When set and that named session has cookies (host-scoped to
    ``target_host`` when given), the context is seeded with THOSE cookies and they
    take priority over the Browse ``auth_storage_state`` — so a crawl/explore run
    started under an ``activate_login_profile`` session crawls authenticated
    instead of landing on the login page. With no ``session_name`` (non-copilot /
    MCP callers) the legacy Browse-flow seeding is used unchanged.

    ``auth_bypass`` (optional, agentless mode): an
    ``dast.browser.auth_gates.AuthBypassPlan`` — the pre-navigation storage hook
    is installed and requests matching the plan's auth-URL patterns are fulfilled
    client-side with a fake logged-in body (they never reach the proxy), so a
    login-walled SPA renders its post-login shell without credentials while all
    REAL outbound traffic still crosses the MITM and is recorded.
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

    # When a copilot run has an active login-profile (named) session, that session
    # is the authoritative auth and its cookies seed the context directly (below).
    # Otherwise prefer the REAL authenticated session from a live/last Browse
    # login: its Playwright storage_state carries httpOnly session cookies AND
    # localStorage that the proxy's Set-Cookie jar never captured (OIDC callbacks,
    # token-in-storage SPAs). Without either the crawler loads logged-out.
    named_cookies = _named_session_cookies(store, session_name, target_host)
    storage_state = None if named_cookies else await _auth_storage_state(store)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=headless,
            proxy={"server": proxy_url},
            args=["--ignore-certificate-errors"],
        )
        try:
            # device_scale_factor=1 so a viewport screenshot's pixels map 1:1 to
            # page.mouse.click CSS coordinates (needed by the vision navigator).
            context_kwargs = {"ignore_https_errors": True,
                              "viewport": {"width": 1280, "height": 900},
                              "device_scale_factor": 1}
            if storage_state:
                context_kwargs["storage_state"] = storage_state
            context = await browser.new_context(**context_kwargs)

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
                if auth_bypass is not None:
                    from dast.browser.auth_gates import init_script, make_route_guard

                    await context.add_init_script(init_script(auth_bypass))
                    _log("Agentless auth-bypass active: storage hook installed, "
                         f"{len(auth_bypass.url_patterns)} auth-URL pattern(s) stubbed")
                    await context.route(
                        "**/*", make_route_guard(auth_bypass, forward=_inject_header))
                else:
                    await context.route("**/*", _inject_header)

            if storage_state:
                origins = len(storage_state.get("origins") or [])
                _log(f"Seeded authenticated session from live Browse login "
                     f"({len(storage_state.get('cookies') or [])} cookies, {origins} storage origin(s))")
                page = await context.new_page()
                yield context, page, request_count
                return

            # Seed cookies: the active login-profile session's cookies take
            # priority (copilot path); otherwise fall back to the proxy's merged
            # crawl jar. get_crawl_cookies() also surfaces NAMED/headless-login
            # cookies that live in named_sessions and are invisible to the shared jar.
            cookies = named_cookies or store.get_crawl_cookies()
            _cookie_src = "active login-profile session" if named_cookies else "proxy session jar"
            if cookies:
                try:
                    await context.add_cookies(cookies)
                    _log(f"Injected {len(cookies)} session cookie(s) from the {_cookie_src} — "
                         "browse will use the authenticated session")
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
