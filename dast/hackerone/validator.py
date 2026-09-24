"""
HackerOne vulnerability validator.

Given a parsed H1Report, attempts to reproduce the vulnerability and returns
a structured verdict. Validation strategy depends on vuln_type:

  xss            — headless Playwright loads the proof_url; checks for alert/DOM marker.
                   If blocked by auth → request manual browser session.
  sqli / ssti    — sends the proof_url via httpx; checks for error patterns / evaluation.
  open_redirect  — follows redirects; checks Location header.
  ssrf           — registers an OOB callback and polls for a hit; otherwise flags for
                   manual review with an LLM credibility assessment.
  dns_takeover   — DNS resolution checks: NXDOMAIN / SERVFAIL on NS records.
  auth_bypass    — strips auth headers and checks if response is still 200.
  other / unknown— LLM analyses the report text + response and gives a verdict.

When a request fails with a 401/403 or the page redirects to a login screen the
validator sets status="needs_auth" so the caller can open a browser, let the
user authenticate, then call validate_with_session() with the collected cookies.

This module is the orchestrating entry point. The building blocks live in:
  url_safety   — URL safety gate, proof-URL repair, payload substitution, cookies
  auth_wall    — authentication-wall detection
  xss_browser  — Playwright XSS execution + observation
  oob          — interactsh OOB client for SSRF
  dns_checks   — DNS evidence collection for takeover reports
  llm_verdict  — LLM prompts, calls and verdict parsing

The underscore-prefixed names below are re-exported for existing importers
(API routes, triage agent, copilot, tests). Validators reference them through
this module's globals so tests can monkeypatch ``validator._is_safe_url`` etc.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional

from dast.hackerone import evidence, payload_safety
from dast.hackerone.auth_wall import looks_like_auth_wall as _looks_like_auth_wall
from dast.hackerone.dns_checks import collect_dns_evidence
from dast.hackerone.dns_checks import extract_domain as _extract_domain
from dast.hackerone.llm_verdict import llm_analyse_response as _llm_analyse_response
from dast.hackerone.llm_verdict import llm_dns_verdict as _llm_dns_verdict
from dast.hackerone.llm_verdict import llm_repair_proof_url as _llm_repair_proof_url
from dast.hackerone.llm_verdict import llm_ssrf_assessment as _llm_ssrf_assessment
from dast.hackerone.llm_verdict import llm_verdict_http as _llm_verdict_http
from dast.hackerone.llm_verdict import parse_llm_verdict as _parse_llm_verdict
from dast.hackerone.oob import H1InteractshSession as _InteractshSession
from dast.hackerone.parser import H1Report
from dast.hackerone.url_safety import is_safe_url as _is_safe_url
from dast.hackerone.url_safety import repair_proof_url as _repair_proof_url
from dast.hackerone.url_safety import sanitise_cookies as _sanitise_cookies
from dast.hackerone.url_safety import substitute_payload_in_url as _substitute_payload_in_url
from dast.hackerone.xss_browser import (
    XssBrowserRun,
    observed_execution_mechanism,
    run_xss_in_browser,
)
from dast.hackerone.xss_browser import payload_exfil_hosts as _payload_exfil_hosts
from dast.hackerone.xss_browser import trigger_interaction_xss as _trigger_interaction_xss
from dast.utils.logger import get_logger

logger = get_logger(__name__)

__all__ = [
    "ValidationResult",
    "validate",
    "_extract_domain",
    "_InteractshSession",
    "_is_safe_url",
    "_llm_analyse_response",
    "_llm_dns_verdict",
    "_llm_repair_proof_url",
    "_llm_verdict_http",
    "_looks_like_auth_wall",
    "_parse_llm_verdict",
    "_payload_exfil_hosts",
    "_repair_proof_url",
    "_sanitise_cookies",
    "_substitute_payload_in_url",
    "_trigger_interaction_xss",
    "_validate_dns_takeover",
    "_validate_http",
    "_validate_ssrf",
    "_validate_xss",
]

_ALLOWED_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
_BODY_METHODS = ("POST", "PUT", "PATCH", "DELETE")
_STRIPPED_REPORT_HEADERS = ("authorization", "cookie")
_HTTP_TIMEOUT_SECONDS = 15
_SSRF_POLL_SECONDS = 120
_SSRF_POLL_INTERVAL_SECONDS = 5


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


def _new_job_id() -> str:
    return str(uuid.uuid4())[:8]


@dataclass
class _ValidationRun:
    """Per-run bookkeeping shared by every result a validator can return."""

    vuln_type: str
    proof_url: str
    payload: str
    job_id: str = field(default_factory=_new_job_id)
    started_at: float = field(default_factory=time.monotonic)
    checks_run: List[str] = field(default_factory=list)

    def result(self, status: str, evidence_text: str, **extra: Any) -> ValidationResult:
        """Build a ValidationResult carrying this run's id, trail and elapsed time."""
        return ValidationResult(
            job_id=self.job_id,
            status=status,
            vuln_type=self.vuln_type,
            proof_url=self.proof_url,
            payload=self.payload,
            evidence=evidence_text,
            checks_run=self.checks_run,
            duration_ms=int((time.monotonic() - self.started_at) * 1000),
            **extra,
        )

    def unsafe_url_error(self, action: str) -> ValidationResult:
        """Error result for a proof URL the safety gate refused (private/non-http)."""
        return self.result("error", evidence.build_error(
            vuln_type=self.vuln_type, proof_url=self.proof_url,
            error=f"Proof URL rejected: must be a public http/https URL (got: {self.proof_url[:100]}).",
            likely_cause=(
                "The URL points at a private/loopback/internal address or uses a non-http(s) "
                f"scheme, which the validator refuses to {action} for safety. Use the public "
                "target URL, or reproduce manually against the intended host."
            ),
        ))


# ── XSS validation ───────────────────────────────────────────────────────────

def _xss_auth_wall_result(run: _ValidationRun, browser_run: XssBrowserRun) -> ValidationResult:
    status_label = browser_run.response_status if browser_run.response_status is not None else "?"
    return run.result(
        "needs_auth",
        evidence.build_inconclusive(
            vuln_type="xss", proof_url=run.proof_url, payload=run.payload,
            reason=(
                f"The target showed an authentication wall (HTTP "
                f"{status_label}, redirected to {browser_run.final_url}), so the "
                "payload could not be exercised. Open a browser, log in, and re-run "
                "with the session, or reproduce manually while authenticated."
            ),
        ),
        screenshot_b64=browser_run.screenshot_b64,
    )


def _xss_confirmed_result(
    run: _ValidationRun, browser_run: XssBrowserRun, mechanism: str,
) -> ValidationResult:
    mechanism_details: Dict[str, Any] = {}
    if mechanism == "dialog":
        mechanism_details["dialog_message"] = browser_run.alert_message or None
    elif mechanism == "redirect":
        mechanism_details["exfil_host"] = browser_run.exfil_navigation
    return run.result(
        "confirmed",
        evidence.build_confirmed_xss(
            proof_url=run.proof_url, payload=run.payload,
            mechanism=mechanism, **mechanism_details,
        ),
        screenshot_b64=browser_run.screenshot_b64,
    )


def _xss_no_execution_result(
    run: _ValidationRun, browser_run: XssBrowserRun, llm_label: str,
) -> ValidationResult:
    observed = ""
    if browser_run.navigated_hosts:
        observed = (
            "The browser only navigated to: "
            + ", ".join(dict.fromkeys(browser_run.navigated_hosts))
            + " (no off-origin host from the payload was reached)."
        )
    return run.result(
        "needs_manual",
        evidence.build_inconclusive(
            vuln_type="xss", proof_url=run.proof_url, payload=run.payload,
            reason=(
                "No XSS execution was observed when the browser loaded the proof URL "
                "and interacted with the injected element: no JavaScript dialog fired, "
                "no off-origin redirect to a host in the payload, and no live reflected "
                "alert. The endpoint may sanitize the input, require authentication, or "
                "need an interaction the automated pass did not perform."
            ),
            observed=observed,
            llm_advisory=llm_label,
        ),
        screenshot_b64=browser_run.screenshot_b64,
    )


async def _retry_xss_with_llm_repair(
    report: H1Report,
    run: _ValidationRun,
    browser_run: XssBrowserRun,
    proxy_port: Optional[int],
    cookies: Dict[str, str],
    screenshot: bool,
) -> Optional[ValidationResult]:
    """
    Ask the LLM to repair the INPUT URL once and re-drive the browser with it.

    The payload may be mangled in a way the deterministic repair did not catch
    (odd encoding, described in prose, etc.). The LLM only proposes a corrected
    URL — the browser still has to actually execute it for a confirmation.
    Returns None when no usable repair was proposed.
    """
    repaired_url = await _llm_repair_proof_url(report, run.proof_url, browser_run.page_content[:2000])
    if not repaired_url or repaired_url == run.proof_url or not _is_safe_url(repaired_url):
        return None
    run.checks_run.append("llm_url_repair")
    retry = await _validate_xss(
        replace(report, proof_url=repaired_url), proxy_port, cookies=cookies,
        screenshot=screenshot, _llm_repair_attempted=True,
    )
    # Merge the check trail so the UI shows the repair happened.
    retry.checks_run = run.checks_run + [check for check in retry.checks_run if check not in run.checks_run]
    return retry


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
    # Deterministically repair the proof URL so the browser drives the intended
    # payload (e.g. re-encode bare '+' inside a javascript: redirect as %2b,
    # which the browser would otherwise decode to a space and break the JS).
    run = _ValidationRun(vuln_type="xss", proof_url=_repair_proof_url(report.proof_url),
                         payload=report.payload)
    if not run.proof_url:
        return run.result("error", evidence.build_error(
            vuln_type="xss", proof_url="",
            error="No proof URL found in the report.",
            likely_cause=(
                "The parser could not extract a target URL from the report text. "
                "Paste the exact PoC URL, or set it in the 'Override URL' field, then retry."
            ),
        ))
    if not _is_safe_url(run.proof_url):
        return run.unsafe_url_error("drive")

    cookies = _sanitise_cookies(cookies or {})
    try:
        browser_run = await run_xss_in_browser(
            run.proof_url, report.payload, proxy_port, cookies, screenshot, run.checks_run,
        )
        if browser_run.auth_wall:
            return _xss_auth_wall_result(run, browser_run)

        # ── Confirmation requires OBSERVED execution ──────────────────────────
        # For XSS the browser is the authority: we confirm only on a signal the
        # browser actually observed (a dialog fired, an off-origin redirect to an
        # attacker host in the payload, or the payload reflected unescaped with a
        # live alert() call). Reading the response source and reasoning "this
        # would execute" is NOT confirmation — it is the false-positive path that
        # this validator must never take.
        mechanism = observed_execution_mechanism(browser_run)
        if mechanism:
            return _xss_confirmed_result(run, browser_run, mechanism)

        if not _llm_repair_attempted:
            retry = await _retry_xss_with_llm_repair(
                report, run, browser_run, proxy_port, cookies, screenshot,
            )
            if retry is not None:
                return retry

        # Run the LLM as an ADVISORY analysis only — its reasoning is surfaced to
        # help the human, but for XSS it can never flip the verdict to confirmed
        # (it only sees static source, so a "confirmed" from it would be
        # speculation). Result stays needs_manual so a human follows the repro steps.
        run.checks_run.append("llm_analysis")
        reasoning = await _llm_analyse_response(
            report, browser_run.page_content[:3000], browser_run.response_status or 0,
        )
        _advisory_confirmed, llm_label = _parse_llm_verdict(reasoning)
        return _xss_no_execution_result(run, browser_run, llm_label)

    except Exception as exc:
        logger.debug("XSS validation error", error=str(exc))
        return run.result("error", evidence.build_error(
            vuln_type="xss", proof_url=run.proof_url,
            error=str(exc)[:200],
            likely_cause=(
                "The headless browser could not complete the run (e.g. the target was "
                "unreachable, a navigation/timeout error, or Playwright/chromium is not "
                "available). Retry, or reproduce manually in a browser."
            ),
        ))


# ── HTTP-based validation (sqli, open_redirect, generic) ─────────────────────

@dataclass
class _PreparedRequest:
    """The request actually sent after the payload-safety gate."""

    url: str
    body: str
    neutralised: bool = False
    blocked_evidence: str = ""   # non-empty => do NOT send anything


def _apply_payload_safety(report: H1Report, proof_url: str, body: str) -> _PreparedRequest:
    """
    Never send a destructive payload to a live target to "validate" it.

    If the payload is destructive, substitute a detection-equivalent safe variant
    wherever it appears (URL and/or body). If it cannot be neutralised or located,
    return a blocked request carrying the manual-review evidence instead.
    """
    safety = payload_safety.make_safe(report.payload or proof_url, report.vuln_type)
    if not safety.is_destructive:
        return _PreparedRequest(url=proof_url, body=body)

    withheld = "Nothing was sent to the target (the destructive payload was withheld)."
    if not safety.safe_variant:
        return _PreparedRequest(url=proof_url, body=body, blocked_evidence=evidence.build_inconclusive(
            vuln_type=report.vuln_type, proof_url=proof_url, payload=report.payload,
            reason=(
                f"Auto-validation was blocked for safety: {safety.reason}. The reported "
                "payload would perform a destructive action against the live target and "
                "could not be rewritten into a safe, detection-equivalent probe."
            ),
            observed=withheld,
            extra_suggestions=[
                "Reproduce in a NON-production / read-only environment only.",
                "Use a non-destructive proof (boolean/time-based for SQLi; a harmless "
                "marker for command injection) instead of the destructive statement.",
            ],
        ))

    # Substitute the safe variant wherever the payload appears — URL and/or
    # request body (a POST/PUT PoC carries its payload in the body).
    send_url = _substitute_payload_in_url(proof_url, report.payload, safety.safe_variant)
    send_body = body
    body_substituted = False
    if send_body and report.payload and report.payload in send_body:
        send_body = send_body.replace(report.payload, safety.safe_variant)
        body_substituted = True
    if report.payload and send_url == proof_url and not body_substituted:
        # Could not locate the payload in the URL or body to replace it — do not
        # risk sending the destructive original.
        return _PreparedRequest(url=proof_url, body=body, blocked_evidence=evidence.build_inconclusive(
            vuln_type=report.vuln_type, proof_url=proof_url, payload=report.payload,
            reason=(
                f"Auto-validation was blocked for safety: {safety.reason}. The payload "
                "could not be located in the proof URL or request body to substitute a "
                "non-destructive probe, so nothing was sent."
            ),
            observed=withheld,
        ))
    return _PreparedRequest(url=send_url, body=send_body, neutralised=True)


def _report_http_method(report: H1Report) -> str:
    """The report's HTTP method, defaulting to GET for anything unrecognised."""
    method = (report.http_method or "GET").upper()
    return method if method in _ALLOWED_HTTP_METHODS else "GET"


def _build_request_headers(report: H1Report, cookies: Dict[str, str]) -> Dict[str, str]:
    """
    Report-supplied headers minus Authorization/Cookie (the active session
    supplies auth), plus the session cookies.
    """
    headers: Dict[str, str] = {
        header_name: header_value
        for header_name, header_value in (report.request_headers or {}).items()
        if header_name.lower() not in _STRIPPED_REPORT_HEADERS
    }
    cookie_header = "; ".join(f"{name}={value}" for name, value in cookies.items())
    if cookie_header:
        headers["Cookie"] = cookie_header
    return headers


def _format_raw_request(method: str, url: str, headers: Dict[str, str], body: str) -> str:
    raw_request = "\n".join([f"{method} {url} HTTP/1.1"] + [f"{k}: {v}" for k, v in headers.items()]) + "\n"
    if body:
        raw_request += "\n" + body[:2000]
    return raw_request


def _format_raw_response(status: int, headers: Any, body: str) -> str:
    header_lines = "\n".join(f"{k}: {v}" for k, v in headers.items())
    return f"HTTP/1.1 {status}\n" + header_lines + "\n\n" + body[:3000]


async def _validate_http(
    report: H1Report,
    proxy_port: int,
    cookies: Optional[Dict[str, str]] = None,
) -> ValidationResult:
    """Send the proof URL via httpx and analyse the response."""
    run = _ValidationRun(vuln_type=report.vuln_type, proof_url=report.proof_url,
                         payload=report.payload)
    proof_url = run.proof_url
    if not _is_safe_url(proof_url):
        return run.unsafe_url_error("send to")

    # Honor the method/body extracted from the report so POST/PUT/JSON PoCs
    # reproduce faithfully, not just GET proof URLs.
    method = _report_http_method(report)
    run.checks_run.append("payload_safety")
    prepared = _apply_payload_safety(report, proof_url, report.request_body or "")
    if prepared.blocked_evidence:
        return run.result("needs_manual", prepared.blocked_evidence)
    if prepared.neutralised:
        run.checks_run.append("payload_neutralized")

    try:
        import httpx

        headers = _build_request_headers(report, _sanitise_cookies(cookies or {}))
        # Only carry a body for methods that take one.
        request_body = prepared.body if method in _BODY_METHODS else ""

        async with httpx.AsyncClient(
            proxy=f"http://127.0.0.1:{proxy_port}", verify=False, follow_redirects=True,
            timeout=_HTTP_TIMEOUT_SECONDS, headers=headers,
        ) as client:
            run.checks_run.append("http_request")
            response = await client.request(
                method, prepared.url,
                content=request_body.encode("utf-8") if request_body else None,
            )

        body = response.text
        status = response.status_code

        if _looks_like_auth_wall(status, str(response.url), body):
            return run.result("needs_auth", evidence.build_inconclusive(
                vuln_type=report.vuln_type, proof_url=proof_url, payload=report.payload,
                reason=(
                    f"The target returned an authentication wall (HTTP {status}), so the "
                    "payload could not be exercised unauthenticated. Provide a logged-in "
                    "session (open a browser and authenticate) and re-run, or reproduce "
                    "manually while logged in."
                ),
            ))

        run.checks_run.append("response_analysis")
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
        return run.result(
            "confirmed" if confirmed else "needs_manual",
            result_evidence,
            severity=severity if confirmed else "",
            raw_request=_format_raw_request(method, prepared.url, headers, request_body)[:2000],
            raw_response=_format_raw_response(status, response.headers, body)[:4000],
        )

    except Exception as exc:
        logger.debug("HTTP validation error", error=str(exc))
        return run.result("error", evidence.build_error(
            vuln_type=report.vuln_type, proof_url=proof_url,
            error=str(exc)[:200],
            likely_cause=(
                "The HTTP request to the target failed (unreachable host, timeout, TLS "
                "error, or proxy issue). Retry, or reproduce the request manually."
            ),
        ))


# ── DNS takeover validation ───────────────────────────────────────────────────

def _dns_takeover_evidence(
    report: H1Report, target_domain: str, dns_findings: str, confirmed: bool, llm_label: str,
) -> str:
    if not confirmed:
        return evidence.build_inconclusive(
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
    return evidence_text


async def _validate_dns_takeover(report: H1Report) -> ValidationResult:
    """
    Check for dangling NS / CNAME records that indicate DNS takeover risk.
    Uses dnspython if available, falls back to subprocess dig/nslookup.
    """
    run = _ValidationRun(vuln_type="dns_takeover", proof_url=report.proof_url, payload="")

    # Extract the target domain from the report text / URLs
    target_domain = _extract_domain(report)
    if not target_domain:
        return run.result("needs_manual", evidence.build_inconclusive(
            vuln_type="dns_takeover", proof_url=report.proof_url, payload="",
            reason=(
                "Could not determine the target domain from the report. Set it in the "
                "'Override domain' field and re-run."
            ),
            extra_suggestions=[
                "dig NS <domain> +short   (look for SERVFAIL / NXDOMAIN)",
                "dig CNAME <domain> +short",
            ],
        ))

    dns_evidence = collect_dns_evidence(target_domain, run.checks_run)
    dns_findings = "\n".join(dns_evidence.lines)

    # LLM verdict on collected evidence — requires ≥95% confidence
    run.checks_run.append("llm_verdict")
    llm_verdict = await _llm_dns_verdict(report, target_domain, dns_findings)
    llm_confirmed, llm_label = _parse_llm_verdict(llm_verdict)
    confirmed = dns_evidence.dangling or llm_confirmed

    return run.result(
        "confirmed" if confirmed else "needs_manual",
        _dns_takeover_evidence(report, target_domain, dns_findings, confirmed, llm_label),
    )


# ── SSRF / OOB validation via interactsh ─────────────────────────────────────

def _ssrf_manual_instructions(oob_url: str, original_payload: str) -> str:
    """Operator instructions for re-triggering the SSRF against an OOB URL."""
    if oob_url:
        return (
            f"OOB URL (interactsh): {oob_url}\n\n"
            f"Steps to confirm:\n"
            f"1. Re-trigger the SSRF using this URL as the callback:\n"
            f"   {oob_url}\n"
            f"2. Original payload for reference:\n"
            f"   {original_payload}\n"
            f"3. Validator is polling for 120s — auto-confirms if hit received"
        )
    return (
        f"interactsh (oast.pro) is not reachable from this machine.\n\n"
        f"To confirm manually:\n"
        f"1. Use https://app.interactsh.com to get an OOB URL\n"
        f"2. Re-trigger the SSRF with that URL as the callback\n"
        f"3. Original payload for reference:\n"
        f"   {original_payload}"
    )


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
    run = _ValidationRun(vuln_type="ssrf", proof_url=report.proof_url, payload=report.payload)

    session = _InteractshSession()
    registered = await session.register()
    run.checks_run.append("interactsh_register" if registered else "interactsh_unavailable")
    oob_url = session.url if registered else ""
    instructions = _ssrf_manual_instructions(
        oob_url, report.payload or "(see report for injection point)",
    )

    callback_received = False
    if registered:
        run.checks_run.append("oob_polling")
        callback_received = await session.poll_for(_SSRF_POLL_SECONDS, _SSRF_POLL_INTERVAL_SECONDS)
        await session.deregister()

    if callback_received:
        run.checks_run.append("oob_callback_received")
        return run.result(
            "confirmed", f"OOB callback received on {oob_url} via interactsh — SSRF confirmed.",
        )

    run.checks_run.append("llm_credibility_assessment")
    assessment = await _llm_ssrf_assessment(report)
    reason = "No OOB callback received" if registered else "interactsh unreachable"
    return run.result("needs_manual", (
        f"{reason}.\n\n"
        f"LLM credibility assessment:\n{assessment}\n\n"
        f"Manual confirmation steps:\n{instructions}"
    ))


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
    vuln_type = report.vuln_type
    if vuln_type == "xss":
        return await _validate_xss(report, proxy_port, cookies=cookies)
    if vuln_type == "dns_takeover":
        return await _validate_dns_takeover(report)
    if vuln_type == "ssrf":
        # SSRF requires an OOB callback. Uses interactsh (oast.pro) as the
        # public callback server — no local listener, no ngrok needed.
        return await _validate_ssrf(report, proxy_port=proxy_port)
    # sqli, ssti, open_redirect, lfi, idor, csrf, auth_bypass, info_disclosure,
    # business_logic, privilege_escalation, rce, xxe, other, unknown — and any
    # unrecognised type — go through the generic HTTP reproduction path.
    return await _validate_http(report, proxy_port, cookies=cookies)
