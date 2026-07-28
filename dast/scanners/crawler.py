"""
Browser-based crawler — discovers endpoints by navigating the app.

Combines two strategies:
  1. DOM crawl: click links, buttons, navigate routes (SPA-aware)
  2. Network intercept: collect every fetch/XHR seen during navigation
"""

import asyncio
import time
from typing import List, Optional, Set
from urllib.parse import urlparse

from playwright.async_api import BrowserContext, Page, TimeoutError as PwTimeout

from dast.browser.interceptor import NetworkInterceptor
from dast.models import Endpoint, EndpointParameter, HttpRequest, Interaction
from dast.utils.audit_log import AuditLog
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".css", ".map",
}


class CrawlerWorker:
    def __init__(
        self,
        context: BrowserContext,
        base_url: str,
        max_depth: int = 5,
        max_pages: int = 50,
        delay_ms: int = 100,
        audit: Optional[AuditLog] = None,
    ):
        self._context = context
        self._base_url = base_url
        self._origin = urlparse(base_url).netloc
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._delay_ms = delay_ms
        self._audit = audit

        self._visited: Set[str] = set()
        self._endpoints: List[Endpoint] = []
        self._interactions: List[Interaction] = []

        self._interceptor = NetworkInterceptor(
            context=context,
            base_domain=self._origin,
            on_interaction=self._interactions.append,
        )

    async def crawl(self, start_urls: List[str]) -> List[Endpoint]:
        await self._interceptor.attach()

        queue: List[tuple[str, int]] = [(u, 0) for u in start_urls]
        pages_done = 0

        while queue and pages_done < self._max_pages:
            url, depth = queue.pop(0)

            if url in self._visited or depth > self._max_depth:
                continue
            if not self._in_scope(url):
                continue

            self._visited.add(url)
            new_links, status, duration_ms, interactions_before = await self._visit_page(url, depth)
            pages_done += 1

            if self._audit:
                self._audit.crawled(
                    url,
                    status=status,
                    depth=depth,
                    links_found=len(new_links),
                    interactions_captured=len(self._interactions) - interactions_before,
                    duration_ms=duration_ms,
                )

            for link in new_links:
                if link not in self._visited:
                    queue.append((link, depth + 1))

            await asyncio.sleep(self._delay_ms / 1000)

        endpoints = self._build_endpoints()

        # Log each discovered endpoint to audit
        if self._audit:
            for ep in endpoints:
                self._audit.endpoint_discovered(ep)

        logger.info(
            "Crawl finished",
            pages_visited=pages_done,
            endpoints_found=len(endpoints),
            interactions_total=len(self._interactions),
            skipped_out_of_scope=len(self._visited) - pages_done,
        )
        return endpoints

    async def _visit_page(
        self, url: str, depth: int
    ) -> tuple[List[str], int, float, int]:
        """
        Visit a single page. Returns (new_links, http_status, duration_ms, interactions_before).
        """
        interactions_before = len(self._interactions)
        page: Page = await self._context.new_page()
        links: List[str] = []
        status = 0
        start = time.time()

        try:
            logger.debug(
                "Crawling page",
                url=url,
                depth=depth,
                queue_remaining="?",
            )
            resp = await page.goto(url, wait_until="networkidle", timeout=20_000)
            status = resp.status if resp else 0

            if resp and resp.status >= 400:
                logger.debug(
                    "Page returned error status",
                    url=url,
                    status=resp.status,
                )
                return links, status, (time.time() - start) * 1000, interactions_before

            await page.wait_for_timeout(500)

            # Collect links from DOM
            hrefs = await page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => e.href)"
            )
            for href in hrefs:
                clean = self._clean_url(href)
                if clean:
                    links.append(clean)

            logger.debug(
                "Page crawled",
                url=url,
                status=status,
                links_found=len(links),
                depth=depth,
            )

            await self._interact_with_page(page, url)

        except PwTimeout:
            logger.warning("Page navigation timed out", url=url, depth=depth)
            if self._audit:
                self._audit.page_error(url, error="timeout", depth=depth)
        except Exception as e:
            logger.warning(
                "Page crawl error",
                url=url,
                depth=depth,
                error=str(e),
                exc_info=True,
            )
            if self._audit:
                self._audit.page_error(url, error=str(e), depth=depth)
        finally:
            await page.close()

        return links, status, (time.time() - start) * 1000, interactions_before

    async def _interact_with_page(self, page: Page, url: str) -> None:
        try:
            buttons = await page.locator("button:visible").all()
            clicked = 0
            for btn in buttons[:5]:
                try:
                    label = (await btn.text_content() or "").lower()
                    if any(w in label for w in ("delete", "remove", "logout", "sign out")):
                        continue
                    await btn.click(timeout=1000)
                    await page.wait_for_timeout(300)
                    clicked += 1
                except Exception:
                    pass
            if clicked:
                logger.debug("Interacted with page buttons", url=url, clicked=clicked)
        except Exception as e:
            logger.debug("Page interaction failed", url=url, error=str(e))

    def _build_endpoints(self) -> List[Endpoint]:
        seen: Set[str] = set()
        endpoints: List[Endpoint] = []

        for interaction in self._interactions:
            req = interaction.request
            key = f"{req.method}:{req.url.split('?')[0]}"

            if key in seen:
                existing = next(
                    (e for e in endpoints if f"{e.method}:{e.url}" == key), None
                )
                if existing:
                    _merge_parameters(existing, req)
                continue

            seen.add(key)
            endpoint = _interaction_to_endpoint(interaction)
            endpoints.append(endpoint)

        return endpoints

    def _in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc == self._origin or parsed.netloc.endswith(f".{self._origin}")

    def _clean_url(self, url: str) -> Optional[str]:
        if not url or url.startswith(("javascript:", "mailto:", "tel:", "#")):
            return None
        url = url.split("#")[0]
        if any(url.lower().endswith(ext) for ext in _SKIP_EXTENSIONS):
            return None
        if not self._in_scope(url):
            return None
        return url


def _interaction_to_endpoint(interaction: Interaction) -> Endpoint:
    import json as _json
    req = interaction.request
    parsed = urlparse(req.url)
    params: List[EndpointParameter] = []

    if parsed.query:
        for part in parsed.query.split("&"):
            if "=" in part:
                name, value = part.split("=", 1)
                params.append(EndpointParameter(name=name, location="query", value=value))

    if req.body:
        try:
            body_data = _json.loads(req.body)
            if isinstance(body_data, dict):
                for k, v in body_data.items():
                    params.append(EndpointParameter(
                        name=k, location="body", value=str(v),
                        inferred_type=_infer_type(v),
                    ))
        except Exception:
            for part in req.body.split("&"):
                if "=" in part:
                    name, value = part.split("=", 1)
                    params.append(EndpointParameter(name=name, location="body", value=value))

    return Endpoint(
        url=req.url.split("?")[0],
        method=req.method,
        parameters=params,
        content_type=req.headers.get("content-type", ""),
        sample_request=req,
        sample_response=interaction.response,
        discovered_via="network_intercept",
    )


def _merge_parameters(endpoint: Endpoint, req: HttpRequest) -> None:
    existing_names = {p.name for p in endpoint.parameters}
    parsed = urlparse(req.url)
    if parsed.query:
        for part in parsed.query.split("&"):
            if "=" in part:
                name, value = part.split("=", 1)
                if name not in existing_names:
                    endpoint.parameters.append(
                        EndpointParameter(name=name, location="query", value=value)
                    )


def _infer_type(value) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, dict):
        return "object"
    return "string"
