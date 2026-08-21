"""
Network interceptor — wires into a BrowserContext to capture all
requests and responses (including fetch/XHR) as Interaction objects.

Uses Playwright's context.route() for global interception across every
page and popup in the context. This is preferred over page.route()
because it survives navigations and catches background requests.
"""

import time
from typing import Callable, List, Optional
from urllib.parse import urlparse

from playwright.async_api import BrowserContext, Request, Response, Route

from dast.models import HttpRequest, HttpResponse, Interaction
from dast.utils.logger import get_logger

logger = get_logger(__name__)


_NOISE_DOMAINS = {
    # Analytics / tracking
    "google-analytics.com", "googletagmanager.com", "segment.com",
    "mixpanel.com", "amplitude.com", "hotjar.com", "heap.io",
    "fullstory.com", "logrocket.com", "datadog-browser-agent.com",
    # CDN / fonts
    "fonts.googleapis.com", "fonts.gstatic.com", "cdnjs.cloudflare.com",
    "jsdelivr.net", "unpkg.com", "bootstrapcdn.com",
    # Social / auth providers (passthrough — don't intercept OAuth flows)
    "accounts.google.com", "login.microsoftonline.com", "auth0.com",
    "okta.com", "cognito-idp.amazonaws.com",
}

_NOISE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".map",
}


class NetworkInterceptor:
    """
    Attaches to a BrowserContext and records HTTP traffic.

    Two scope modes:
    - Fixed scope (base_domain provided): only captures requests to that domain
      and its subdomains. Used by the automated crawler.
    - Auto scope (base_domain=None): captures any domain the user visits,
      excluding known noise (analytics, CDNs, OAuth providers). Domains are
      added to scope the first time the user navigates to them. Used by the
      manual browse command so the user never has to specify a target URL.

    Usage:
        interceptor = NetworkInterceptor(context, base_domain="app.example.com")
        await interceptor.attach()
        interactions = interceptor.drain()
    """

    def __init__(
        self,
        context: BrowserContext,
        base_domain: Optional[str] = None,
        on_interaction: Optional[Callable[[Interaction], None]] = None,
    ):
        self._context = context
        self._base_domain = base_domain        # None = auto-scope
        self._scoped_domains: set = set()      # populated in auto-scope mode
        self._on_interaction = on_interaction
        self._interactions: List[Interaction] = []

    async def attach(self) -> None:
        """Wire route handler at context level (captures all pages)."""
        await self._context.route("**/*", self._handle_route)

        if self._base_domain is None:
            # Auto-scope: watch page navigations so we can add new domains to scope
            self._context.on("page", self._on_new_page)

    def _on_new_page(self, page) -> None:
        page.on("framenavigated", self._on_frame_navigated)

    def _on_frame_navigated(self, frame) -> None:
        if not frame.parent_frame:  # main frame only
            netloc = urlparse(frame.url).netloc
            if netloc and not self._is_noise(netloc) and netloc not in self._scoped_domains:
                self._scoped_domains.add(netloc)

    async def _handle_route(self, route: Route, request: Request) -> None:
        url = request.url
        parsed = urlparse(url)

        if not self._is_in_scope(parsed.netloc, parsed.path):
            await route.continue_()
            return

        start = time.time()
        req = HttpRequest(
            method=request.method,
            url=url,
            headers=dict(request.headers),
            body=request.post_data,
            timestamp=start,
        )

        try:
            response: Response = await route.fetch()
            duration_ms = (time.time() - start) * 1000

            resp_body = ""
            try:
                resp_body = await response.text()
            except Exception:
                pass

            resp = HttpResponse(
                status_code=response.status,
                headers=dict(response.headers),
                body=resp_body,
                duration_ms=duration_ms,
                timestamp=time.time(),
            )

            interaction = Interaction(
                request=req,
                response=resp,
                page_url=request.frame.url if request.frame else "",
                triggered_by=request.resource_type,
            )

            self._interactions.append(interaction)
            if self._on_interaction:
                self._on_interaction(interaction)

            await route.fulfill(response=response)

        except Exception as exc:
            logger.debug("interceptor: route handling failed, continuing", error=str(exc))
            await route.continue_()

    def _is_in_scope(self, netloc: str, path: str = "") -> bool:
        if not netloc:
            return False
        if any(path.lower().endswith(ext) for ext in _NOISE_EXTENSIONS):
            return False
        if self._base_domain:
            return netloc == self._base_domain or netloc.endswith(f".{self._base_domain}")
        # Auto-scope: accept any domain the user has navigated to
        return netloc in self._scoped_domains and not self._is_noise(netloc)

    def _is_noise(self, netloc: str) -> bool:
        return any(netloc == d or netloc.endswith(f".{d}") for d in _NOISE_DOMAINS)

    @property
    def scoped_domains(self) -> set:
        """Domains currently in scope (auto-scope mode)."""
        return set(self._scoped_domains)

    def drain(self) -> List[Interaction]:
        """Return all captured interactions and clear the buffer."""
        result = list(self._interactions)
        self._interactions.clear()
        return result
