"""
XSS agent — reflected, stored, and DOM cross-site scripting.

Detection strategy:
  1. Probe each parameter with seed payloads from xss.yaml
  2. If a payload appears unencoded in the response, launch browser validation
     to confirm JS execution (handles cases where source != sink)
  3. If probe was blocked/encoded, ask the LLM mutator for a bypass variant
     and retry (up to MAX_ITERATIONS times per parameter)
  4. Also crawls follow-up URLs from the response looking for stored XSS sinks
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.mutator import build_mutator_context, next_payload
from dast.agents.block_detector import detect_block
from dast.agents.payload_filter import get_filtered_payloads
from dast.payloads.loader import get_payloads
from dast.scanners.active_checks import _fmt_http_pair, _inject_body, _inject_multipart, _inject_query, _send, prepend_import_payloads
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_REFLECTED_RE = re.compile(
    r'<(?:img[^>]+onerror|script|svg[^>]+onload|body[^>]+onload|details[^>]+ontoggle|input[^>]+onfocus)[^>]*>'
    r'|javascript:alert',
    re.IGNORECASE,
)
_CONFIRM_MARKER = "DAST_XSS_CONFIRM"


def _param_marker(param_name: str) -> str:
    """Generate a unique short marker per parameter for stored XSS identification."""
    import hashlib
    h = hashlib.md5(param_name.encode()).hexdigest()[:6]
    return f"dxss_{h}"


def _tagged_payload(payload: str, param_name: str) -> str:
    """Embed a unique param marker into an XSS payload so we can identify
    which field rendered it on the output page."""
    marker = _param_marker(param_name)
    # Replace the alert argument with our marker
    if "alert(1)" in payload:
        return payload.replace("alert(1)", f"alert('{marker}')")
    if "alert(" in payload:
        return payload.replace("alert(", f"alert('{marker}',")
    # For payloads without alert, append marker as a comment
    return f"{payload}<!--{marker}-->"


async def _browser_confirm(url: str, proxy_port: int) -> tuple[bool, str]:
    """
    Open URL in a headless browser via proxy and check if DAST_XSS_CONFIRM
    was called. Returns (confirmed, reason).

    reason values:
      "confirmed"       — JS executed (alert fired or marker in DOM)
      "csp_or_sink"     — browser ran but JS did not execute (CSP, DOM sink, different page)
      "timeout"         — page did not load within timeout
      "error:<msg>"     — browser failed to launch or crashed
    """
    import asyncio
    try:
        from playwright.async_api import async_playwright, TimeoutError as PwTimeout
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                proxy={"server": f"http://127.0.0.1:{proxy_port}"},
            )
            ctx = await browser.new_context(ignore_https_errors=True)
            page = await ctx.new_page()

            confirmed = False

            def handle_dialog(dialog):
                nonlocal confirmed
                if _CONFIRM_MARKER in dialog.message:
                    confirmed = True
                asyncio.create_task(dialog.dismiss())

            page.on("dialog", handle_dialog)

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            except PwTimeout:
                await browser.close()
                return False, "timeout"

            await page.wait_for_timeout(1500)

            if not confirmed:
                content = await page.content()
                if _CONFIRM_MARKER in content and _REFLECTED_RE.search(content):
                    confirmed = True

            await browser.close()
            return (True, "confirmed") if confirmed else (False, "csp_or_sink")
    except Exception as e:
        logger.debug("XSS browser validation failed", error=str(e))
        return False, f"error:{str(e)[:120]}"


class XssAgent(VulnAgent):
    name = "XSS Agent"
    attack_type = "xss"
    description = (
        "Tests for reflected, stored, and DOM XSS. "
        "Uses browser validation to confirm JS execution even when source != sink."
    )

    def __init__(self, proxy_port: int = 8080):
        self._proxy_port = proxy_port

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        # Payload groups filtered to what is relevant for this target's tech stack.
        seed_payloads = get_filtered_payloads("xss", target) or get_payloads("xss", "basic")

        # Includes the per-host WAF memory (vendor, blocked + bypassed payloads)
        # so the mutator can reuse a bypass proven on another endpoint.
        tech_context: Optional[str] = build_mutator_context(target, "xss")

        for param in target.params:
            finding = await self._probe_param(target, client, param, seed_payloads, tech_context)
            if finding:
                findings.append(finding)

        return findings

    async def _probe_param(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        seed_payloads: List[str],
        tech_context: Optional[str] = None,
    ) -> Optional[AgentFinding]:
        payloads_to_try = prepend_import_payloads(list(seed_payloads), param["name"], "xss", target)
        tried: set = set()

        # Capture baseline (clean) request/response before any payload injection.
        baseline_raw_request = ""
        baseline_raw_response = ""
        try:
            baseline_resp, _ = await self._send_probe(target, client, param, param.get("value", "test"))
            if baseline_resp is not None:
                baseline_raw_request, baseline_raw_response = _fmt_http_pair(baseline_resp)
        except Exception:
            pass

        mutation_iteration = 0
        block_seen = False  # did an earlier probe on this param get blocked?
        for iteration, payload in enumerate(payloads_to_try):
            if payload in tried:
                continue
            tried.add(payload)

            # Tag payload with unique per-param marker for stored XSS identification
            tagged = _tagged_payload(payload, param["name"])
            resp, injected_url = await self._send_probe(target, client, param, tagged)
            if resp is None:
                continue

            body_text = resp.text
            content_type = resp.headers.get("content-type", "").lower()

            # JSON/204 responses: payload was stored, not reflected.
            # Check for stored XSS by fetching a page that renders the value.
            if "application/json" in content_type or resp.status_code == 204:
                stored_finding = await self._check_stored_xss(
                    target, client, param, tagged, resp
                )
                if stored_finding:
                    # Restore original value to undo the mutation
                    await self._restore_value(target, client, param)
                    return stored_finding
                continue

            # Check for unencoded reflection — must appear in an HTML context
            if tagged in body_text and _REFLECTED_RE.search(body_text):
                if block_seen:
                    self.observe("waf_bypass", payload=payload, signal="payload reflected unencoded after prior block")
                confirm_payload = f'<img src=x onerror=alert("{_CONFIRM_MARKER}")>'
                confirm_resp, confirm_url = await self._send_probe(target, client, param, confirm_payload)
                browser_confirmed, browser_reason = await _browser_confirm(
                    confirm_url or target.url, self._proxy_port
                )

                # Extract response snippet around the reflection point
                match = _REFLECTED_RE.search(body_text)
                snippet = ""
                if match:
                    start = max(0, match.start() - 80)
                    snippet = body_text[start:match.end() + 80].strip()

                # The probe with payload is the exploit proof.
                probe_request, probe_response = _fmt_http_pair(resp)

                _reason_label = {
                    "confirmed":  "JS executed in browser",
                    "csp_or_sink": "browser ran — JS did not execute (CSP, different sink, or alert suppressed)",
                    "timeout":    "browser timed out loading the page",
                }.get(browser_reason, browser_reason)

                if browser_confirmed:
                    evidence = (
                        f"Payload reflected unencoded and JS executed in browser "
                        f"(status {resp.status_code}) — parameter '{param['name']}'"
                    )
                else:
                    evidence = (
                        f"Payload reflected unencoded (status {resp.status_code}) — "
                        f"{_reason_label}. "
                        f"Parameter '{param['name']}' — manual review recommended."
                    )

                return AgentFinding(
                    title="Reflected Cross-Site Scripting (XSS)",
                    severity="high",
                    cwe="CWE-79",
                    attack_type="xss",
                    evidence=evidence,
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=browser_confirmed,
                    browser_confirmed=browser_confirmed,
                    browser_confirm_reason=browser_reason,
                    raw_response_snippet=snippet,
                    raw_request=baseline_raw_request,
                    raw_response=baseline_raw_response,
                    probe_request=probe_request,
                    probe_response=probe_response,
                )

            # Still have seed payloads — don't burn LLM budget yet
            if iteration < len(seed_payloads) - 1:
                continue

            verdict = detect_block(resp.status_code, body_text)
            if verdict.is_block:
                block_seen = True
                self.observe("waf_block", payload=payload, signal=verdict.signal)

            mutation = await next_payload(
                attack_type="xss",
                original_payload=payload,
                parameter=param["name"],
                response_status=resp.status_code,
                response_snippet=body_text[:600],
                iteration=mutation_iteration,
                tried_payloads=list(tried),
                tech_context=tech_context,
            )
            mutation_iteration += 1
            if mutation is None:
                break
            logger.debug(
                "XSS mutator", param=param["name"], action=mutation.action,
                rationale=mutation.rationale,
            )
            payloads_to_try.append(mutation.payload)

        return None

    async def _send_probe(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        payload: str,
    ):
        if param["location"] == "query":
            url = _inject_query(target.url, param["name"], payload)
            resp = await _send(client, target.method, url, target.headers, target.body)
            return resp, url
        elif param["location"] in ("body", "body_graphql"):
            body = _inject_body(
                target.body or "", param["name"], payload,
                target.headers.get("content-type", ""),
                location=param["location"],
            )
            resp = await _send(client, target.method, target.url, target.headers, body)
            return resp, target.url
        elif param["location"].startswith("multipart_"):
            raw = _inject_multipart(target.raw_body or b"", param["name"], payload)
            resp = await _send(client, target.method, target.url, target.headers, raw)
            return resp, target.url
        return None, target.url


    async def _check_stored_xss(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        payload: str,
        inject_resp: "httpx.Response",
    ) -> Optional[AgentFinding]:
        """After injecting into a stored endpoint (PUT/POST → 204/JSON),
        fetch pages that might render the stored value.

        Strategy (in order):
          1. Referer header — the page the user was on when submitting (most likely render page)
          2. Origin + path variations — the SPA page that displays this data
          3. GET on same URL — REST resources sometimes return the full object
        """
        import asyncio
        await asyncio.sleep(0.5)

        # Build list of URLs to check for rendered payload
        urls_to_check: list = []

        # 1. Referer — most reliable for stored XSS (page that triggered the PUT)
        referer = target.headers.get("referer", "") or target.headers.get("Referer", "")
        if referer and referer.startswith("http"):
            urls_to_check.append(referer)

        # 2. Origin path — SPA root that renders data from this API
        origin = target.headers.get("origin", "") or target.headers.get("Origin", "")
        if origin and origin.startswith("http") and origin != referer:
            urls_to_check.append(origin + "/")

        # 3. GET on same URL
        get_url = target.url.split("?")[0]
        if get_url not in urls_to_check:
            urls_to_check.append(get_url)

        logger.debug("stored_xss: checking %d render URLs", len(urls_to_check),
                     param=param["name"], urls=urls_to_check[:3])

        for check_url in urls_to_check:
            try:
                get_resp = await _send(client, "GET", check_url, target.headers, None)
            except Exception as exc:
                logger.debug("stored_xss: GET failed", url=check_url, error=str(exc))
                continue

            if get_resp is None:
                continue

            body_text = get_resp.text
            content_type = get_resp.headers.get("content-type", "").lower()

            # Check HTML responses for unencoded payload (look for marker OR full payload)
            marker = _param_marker(param["name"])
            if "html" in content_type:
                if (payload in body_text or marker in body_text) and _REFLECTED_RE.search(body_text):
                    return self._build_stored_finding(
                        target, param, payload, inject_resp, get_resp, check_url
                    )

            # Check JSON responses — payload stored unescaped means the backend
            # doesn't sanitize; if any HTML page consumes this JSON, it's exploitable
            if "json" in content_type and (payload in body_text or marker in body_text):
                raw_req, raw_resp = _fmt_http_pair(get_resp)
                inject_req, _ = _fmt_http_pair(inject_resp)

                from dast.proxy.plugin_manager import log_event
                log_event("agent", "finding",
                          f"Stored XSS (JSON): {param['name']} — payload stored unescaped",
                          url=target.url, finding="Stored XSS (JSON)", source="agent")
                logger.info("Stored XSS in JSON", param=param["name"],
                            inject_url=target.url, render_url=check_url)

                return AgentFinding(
                    title="Stored XSS — Payload Stored Unescaped in API Response",
                    severity="medium",
                    cwe="CWE-79",
                    attack_type="xss",
                    evidence=(
                        f"Payload '{payload}' was injected via {target.method} into parameter "
                        f"'{param['name']}' (returned {inject_resp.status_code}). "
                        f"GET {check_url} returns the payload unescaped in JSON. "
                        f"If any frontend renders this field as innerHTML, stored XSS is exploitable.\n\n"
                        f"Injection:\n{inject_req}\n\n"
                        f"API response containing payload:\n{raw_resp[:2000]}"
                    ),
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                    raw_request=inject_req,
                    raw_response=raw_resp[:2000],
                )

        return None

    def _build_stored_finding(
        self, target: "CheckTarget", param: dict, payload: str,
        inject_resp: "httpx.Response", render_resp: "httpx.Response", render_url: str,
    ) -> AgentFinding:
        raw_req, raw_resp = _fmt_http_pair(render_resp)
        inject_req, _ = _fmt_http_pair(inject_resp)

        from dast.proxy.plugin_manager import log_event
        log_event("agent", "finding",
                  f"Stored XSS confirmed: {param['name']} renders on {render_url}",
                  url=target.url, finding="Stored XSS", source="agent")
        logger.info("Stored XSS confirmed", param=param["name"],
                    inject_url=target.url, render_url=render_url)

        return AgentFinding(
            title="Stored Cross-Site Scripting (XSS)",
            severity="high",
            cwe="CWE-79",
            attack_type="xss",
            evidence=(
                f"Payload '{payload}' was injected via {target.method} into parameter "
                f"'{param['name']}' (returned {inject_resp.status_code}). "
                f"The payload renders unencoded in HTML at {render_url}.\n\n"
                f"Injection request:\n{inject_req}\n\n"
                f"Rendered page:\n{raw_resp[:2000]}"
            ),
            confirmed=True,
            payload=payload,
            parameter=param["name"],
            url=target.url,
            request_method=target.method,
            bypass_validation=True,
            raw_request=inject_req,
            raw_response=raw_resp[:2000],
            probe_request=inject_req,
            probe_response=raw_resp[:2000],
        )

    async def _restore_value(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
    ) -> None:
        """Restore the original value after a stored XSS probe to avoid data corruption."""
        original_value = param.get("value", "")
        if not original_value and not target.body:
            return
        try:
            resp = await _send(client, target.method, target.url, target.headers, target.body)
            if resp and resp.status_code in (200, 204):
                logger.debug("xss: restored original value", param=param["name"], url=target.url)
            else:
                logger.warning("xss: restore failed",
                               param=param["name"], status=resp.status_code if resp else None)
        except Exception as exc:
            logger.warning("xss: restore error", param=param["name"], error=str(exc))


from dast.ai.coordinator import Coordinator
Coordinator.register(XssAgent)
