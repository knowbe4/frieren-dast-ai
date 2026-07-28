"""
Manual browse session — open Chromium for the user to navigate freely.

The interceptor runs silently in background capturing all network traffic.
When the user closes the browser or presses Ctrl+C, the captured session
is persisted to disk and can be attacked immediately or replayed later.

This mirrors a "Proxy > HTTP history" workflow:
  1. Browse the app as a real user
  2. Every request/response is recorded
  3. Selected (or all) endpoints are sent to the attack engine
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Callable, List, Optional
from urllib.parse import urlparse

from playwright.async_api import BrowserContext, Page, async_playwright

from dast.browser.interceptor import NetworkInterceptor
from dast.models import Endpoint, Interaction
from dast.scanners.crawler import _interaction_to_endpoint, _merge_parameters
from dast.utils.logger import get_logger

logger = get_logger(__name__)


class ManualBrowseSession:
    """
    Runs a visible Chromium window. The user browses freely.
    All network traffic within scope is intercepted and catalogued.

    Two modes:
    - base_url provided: browser opens at that URL; only traffic to that
      domain (and subdomains) is recorded.
    - base_url=None: browser opens a blank page; any domain the user
      navigates to is automatically added to scope. Noise domains (analytics,
      CDNs, OAuth providers) are silently ignored.

    Usage:
        # navigate to a specific app
        session = ManualBrowseSession(base_url="https://app.example.com")

        # free-roam: scope is determined by where you browse
        session = ManualBrowseSession()

        endpoints = await session.run()
        session.save("session.json")
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        on_endpoint_discovered: Optional[Callable[[Endpoint], None]] = None,
    ):
        self._base_url = base_url
        self._origin = urlparse(base_url).netloc if base_url else None
        self._on_endpoint = on_endpoint_discovered
        self._interactions: List[Interaction] = []
        self._endpoints: List[Endpoint] = []
        self._seen_keys: set = set()
        self._start_time: float = 0.0
        self._context: Optional[BrowserContext] = None
        self._interceptor: Optional[NetworkInterceptor] = None

    async def run(self) -> List[Endpoint]:
        """
        Open Chromium, let the user browse, collect everything.
        Returns when the browser is closed.
        """
        self._start_time = time.time()

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=False,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--window-size=1400,900",
                ],
            )

            self._context = await browser.new_context(
                viewport={"width": 1400, "height": 900},
                ignore_https_errors=True,
                java_script_enabled=True,
                service_workers="block",
            )

            self._interceptor = NetworkInterceptor(
                context=self._context,
                base_domain=self._origin,  # None = auto-scope
                on_interaction=self._handle_interaction,
            )
            await self._interceptor.attach()

            page: Page = await self._context.new_page()
            if self._base_url:
                await page.goto(self._base_url, wait_until="domcontentloaded", timeout=30_000)

            logger.info(
                "Manual browse session started",
                url=self._base_url or "(free roam — navigate to any app)",
                tip="Browse normally. Close the browser window when done.",
            )

            # Block until the browser is closed by the user
            try:
                await self._wait_for_close(browser)
            except asyncio.CancelledError:
                pass

            await browser.close()

        duration = time.time() - self._start_time
        logger.info(
            "Browse session ended",
            duration_s=round(duration, 1),
            endpoints=len(self._endpoints),
            interactions=len(self._interactions),
        )
        return self._endpoints

    def _handle_interaction(self, interaction: Interaction) -> None:
        """Called for every intercepted request/response."""
        self._interactions.append(interaction)

        req = interaction.request
        key = f"{req.method}:{req.url.split('?')[0]}"

        if key in self._seen_keys:
            existing = next(
                (e for e in self._endpoints
                 if f"{e.method}:{e.url}" == key),
                None,
            )
            if existing:
                _merge_parameters(existing, req)
            return

        self._seen_keys.add(key)
        endpoint = _interaction_to_endpoint(interaction)
        self._endpoints.append(endpoint)

        if self._on_endpoint:
            self._on_endpoint(endpoint)

    async def _wait_for_close(self, browser) -> None:
        """Wait until all browser pages are closed."""
        while browser.is_connected():
            await asyncio.sleep(0.5)

    @property
    def scoped_domains(self) -> list:
        if self._interceptor:
            return sorted(self._interceptor.scoped_domains)
        return [self._origin] if self._origin else []

    def save(self, path: Path) -> None:
        """Persist captured session to JSON for later replay or attack."""
        data = {
            "base_url": self._base_url,
            "scoped_domains": self.scoped_domains,
            "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_s": round(time.time() - self._start_time, 1),
            "endpoint_count": len(self._endpoints),
            "endpoints": [_endpoint_to_dict(e) for e in self._endpoints],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("Session saved", path=str(path))

    @classmethod
    def load(cls, path: Path) -> List[Endpoint]:
        """Load a previously saved session and return its endpoints."""
        data = json.loads(path.read_text(encoding="utf-8"))
        return [_dict_to_endpoint(e) for e in data.get("endpoints", [])]

    @property
    def endpoint_count(self) -> int:
        return len(self._endpoints)

    @property
    def interaction_count(self) -> int:
        return len(self._interactions)


def _endpoint_to_dict(e: Endpoint) -> dict:
    return {
        "url": e.url,
        "method": e.method,
        "content_type": e.content_type,
        "auth_required": e.auth_required,
        "discovered_via": e.discovered_via,
        "parameters": [
            {
                "name": p.name,
                "location": p.location,
                "value": p.value,
                "inferred_type": p.inferred_type,
            }
            for p in e.parameters
        ],
        "sample_request": {
            "method": e.sample_request.method,
            "url": e.sample_request.url,
            "headers": e.sample_request.headers,
            "body": e.sample_request.body,
        } if e.sample_request else None,
        "sample_response": {
            "status_code": e.sample_response.status_code,
            "headers": e.sample_response.headers,
            "body": e.sample_response.body[:2000],
        } if e.sample_response else None,
    }


def _dict_to_endpoint(d: dict) -> Endpoint:
    from dast.models import EndpointParameter, HttpRequest, HttpResponse
    params = [
        EndpointParameter(
            name=p["name"],
            location=p["location"],
            value=p.get("value", ""),
            inferred_type=p.get("inferred_type", "string"),
        )
        for p in d.get("parameters", [])
    ]

    sample_req = None
    if d.get("sample_request"):
        r = d["sample_request"]
        sample_req = HttpRequest(
            method=r["method"],
            url=r["url"],
            headers=r.get("headers", {}),
            body=r.get("body"),
        )

    sample_resp = None
    if d.get("sample_response"):
        r = d["sample_response"]
        sample_resp = HttpResponse(
            status_code=r["status_code"],
            headers=r.get("headers", {}),
            body=r.get("body", ""),
        )

    return Endpoint(
        url=d["url"],
        method=d["method"],
        parameters=params,
        content_type=d.get("content_type", ""),
        auth_required=d.get("auth_required", False),
        discovered_via=d.get("discovered_via", "manual_browse"),
        sample_request=sample_req,
        sample_response=sample_resp,
    )
