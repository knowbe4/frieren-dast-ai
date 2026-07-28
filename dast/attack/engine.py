"""
Attack engine — feedback-loop core of Frieren DAST-AI.

For each endpoint, runs up to N iterations of:
  1. Generate payloads (AI)
  2. Deliver payload via browser
  3. Analyze response (AI)
  4. NEEDS_RETRY → mutate payload and repeat

Every attempt is written to the audit log with full req/resp detail.
"""

import asyncio
import json
import time
from typing import Callable, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from playwright.async_api import BrowserContext, Page, TimeoutError as PwTimeout

from dast.ai.payload_generator import generate_payloads, mutate_payload
from dast.ai.response_analyzer import analyze_attempt
from dast.models import (
    AttackAttempt,
    AttackPayload,
    AttackVerdict,
    Endpoint,
    Finding,
    HttpRequest,
    HttpResponse,
    Severity,
    ScanConfig,
)
from dast.session.manager import SessionManager
from dast.utils.audit_log import AuditLog
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_SEVERITY_MAP = {
    "xss": Severity.HIGH,
    "sqli": Severity.CRITICAL,
    "idor": Severity.HIGH,
    "ssrf": Severity.HIGH,
    "open_redirect": Severity.MEDIUM,
    "auth_bypass": Severity.CRITICAL,
    "mass_assignment": Severity.HIGH,
    "graphql_injection": Severity.HIGH,
}

_CWE_MAP = {
    "xss": "CWE-79",
    "sqli": "CWE-89",
    "idor": "CWE-639",
    "ssrf": "CWE-918",
    "open_redirect": "CWE-601",
    "auth_bypass": "CWE-287",
    "mass_assignment": "CWE-915",
    "graphql_injection": "CWE-89",
}


class AttackEngine:
    def __init__(
        self,
        config: ScanConfig,
        session_manager: SessionManager,
        audit: Optional[AuditLog] = None,
    ):
        self._config = config
        self._session = session_manager
        self._audit = audit

    async def attack_all(
        self,
        endpoints: List[Endpoint],
        context_pool,
        seed_map: Optional[dict] = None,
    ) -> List[Finding]:
        """
        Attack a fixed list of endpoints.

        seed_map: optional dict mapping id(endpoint) → AttackPayload. When
        provided, the seed payload is sent as the very first attempt before
        AI-generated payloads. Used by the verify command to front-load the
        payload inferred from Stage 2 reasoning.
        """
        sem = asyncio.Semaphore(self._config.parallel_workers)
        findings: List[Finding] = []
        lock = asyncio.Lock()

        async def attack_one(endpoint: Endpoint):
            async with sem:
                async with context_pool.acquire() as ctx:
                    if not await self._session.is_healthy(ctx):
                        logger.warning(
                            "Session expired before attack, rolling back",
                            url=endpoint.url,
                        )
                        ok = await self._session.rollback(ctx)
                        if self._audit:
                            self._audit.session_rollback(
                                reason="session_expired_before_attack", success=ok
                            )
                        if not ok:
                            logger.error(
                                "Session rollback failed, skipping endpoint",
                                url=endpoint.url,
                            )
                            return

                    seed = (seed_map or {}).get(id(endpoint))
                    new_findings = await self._attack_endpoint(endpoint, ctx, seed_payload=seed)
                    async with lock:
                        findings.extend(new_findings)

        await asyncio.gather(*[attack_one(ep) for ep in endpoints])
        return findings

    async def attack_live(
        self,
        endpoint_queue: "asyncio.Queue[Optional[Endpoint]]",
        context_pool,
        on_finding: Optional[Callable[["Finding"], None]] = None,
    ) -> List[Finding]:
        """
        Drain endpoints from a live queue and attack them as they arrive.

        Caller signals end-of-stream by putting None into the queue.
        on_finding is called immediately when a finding is confirmed so
        the CLI can surface it to the user in real time.
        """
        sem = asyncio.Semaphore(self._config.parallel_workers)
        findings: List[Finding] = []
        lock = asyncio.Lock()
        tasks: List[asyncio.Task] = []

        async def attack_one(endpoint: Endpoint):
            async with sem:
                async with context_pool.acquire() as ctx:
                    if not await self._session.is_healthy(ctx):
                        logger.warning(
                            "Session expired before live attack, rolling back",
                            url=endpoint.url,
                        )
                        ok = await self._session.rollback(ctx)
                        if self._audit:
                            self._audit.session_rollback(
                                reason="session_expired_before_attack", success=ok
                            )
                        if not ok:
                            logger.error(
                                "Session rollback failed, skipping endpoint",
                                url=endpoint.url,
                            )
                            return

                    new_findings = await self._attack_endpoint(endpoint, ctx)
                    async with lock:
                        findings.extend(new_findings)
                        if on_finding:
                            for f in new_findings:
                                on_finding(f)

        while True:
            endpoint = await endpoint_queue.get()
            if endpoint is None:
                break
            task = asyncio.create_task(attack_one(endpoint))
            tasks.append(task)

        if tasks:
            await asyncio.gather(*tasks)

        return findings

    async def _attack_endpoint(
        self,
        endpoint: Endpoint,
        context: BrowserContext,
        seed_payload: Optional[AttackPayload] = None,
    ) -> List[Finding]:
        # Endpoints from verify have a sample_request body — always try them even without
        # query parameters (POST /graphql has no query params but body is the payload).
        has_body = bool(endpoint.sample_request and endpoint.sample_request.body)
        if not endpoint.parameters and endpoint.method == "GET" and not has_body and not seed_payload:
            if self._audit:
                self._audit.attack_skip(endpoint, reason="no_injectable_parameters")
            logger.debug(
                "Skipping endpoint — no injectable parameters",
                method=endpoint.method,
                url=endpoint.url,
            )
            return []

        # Seed payload (from SAST finding inference) goes first; AI payloads follow.
        ai_payloads = generate_payloads(endpoint, self._config.enabled_attack_types)
        payloads = ([seed_payload] if seed_payload else []) + ai_payloads

        if not payloads:
            if self._audit:
                self._audit.attack_skip(endpoint, reason="ai_generated_no_payloads")
            logger.debug(
                "AI generated no payloads for endpoint",
                method=endpoint.method,
                url=endpoint.url,
            )
            return []

        logger.info(
            "Attacking endpoint",
            method=endpoint.method,
            url=endpoint.url,
            param_count=len(endpoint.parameters),
            payload_count=len(payloads),
            seeded=seed_payload is not None,
            attack_types=list({p.attack_type for p in payloads}),
        )
        if self._audit:
            self._audit.attack_start(
                endpoint,
                attack_type=",".join({p.attack_type for p in payloads}),
                payload_count=len(payloads),
            )

        findings: List[Finding] = []

        for payload in payloads:
            attempt = await self._send_attack(endpoint, payload, context, iteration=1)
            if not attempt:
                continue

            verdict, evidence, confidence = analyze_attempt(attempt)
            attempt.verdict = verdict
            attempt.evidence = evidence
            attempt.ai_reasoning = evidence

            logger.debug(
                "Attack attempt result",
                method=endpoint.method,
                url=endpoint.url,
                attack_type=payload.attack_type,
                payload=payload.value[:80],
                injection_point=payload.injection_point,
                status=attempt.response.status_code if attempt.response else None,
                verdict=verdict.value,
                confidence=round(confidence, 2),
                evidence=evidence[:120],
            )

            if self._audit:
                self._audit.attack_attempt(
                    attempt, verdict=verdict, evidence=evidence, confidence=confidence
                )

            if verdict == AttackVerdict.VULNERABLE and confidence >= self._config.confidence_threshold:
                finding = self._build_finding(endpoint, attempt, evidence, confidence)
                findings.append(finding)
                logger.warning(
                    "FINDING CONFIRMED",
                    title=finding.title,
                    severity=finding.severity.value,
                    cwe=finding.cwe,
                    confidence=round(confidence, 2),
                    url=endpoint.url,
                    evidence=evidence[:200],
                )
                if self._audit:
                    self._audit.finding_confirmed(finding)
                continue

            # Feedback loop
            for iteration in range(2, self._config.max_attack_iterations + 1):
                if verdict not in (AttackVerdict.NEEDS_RETRY, AttackVerdict.INCONCLUSIVE):
                    break

                mutated = mutate_payload(attempt, iteration)
                if not mutated:
                    logger.debug(
                        "AI decided no further mutation worthwhile",
                        url=endpoint.url,
                        attack_type=payload.attack_type,
                        iteration=iteration,
                    )
                    break

                if self._audit:
                    self._audit.mutation(
                        endpoint,
                        iteration=iteration,
                        attack_type=payload.attack_type,
                        original_payload=attempt.payload.value,
                        mutated_payload=mutated.value,
                        reason=mutated.rationale,
                    )

                logger.debug(
                    "Payload mutated, retrying",
                    url=endpoint.url,
                    iteration=iteration,
                    original=attempt.payload.value[:60],
                    mutated=mutated.value[:60],
                    rationale=mutated.rationale,
                )

                attempt = await self._send_attack(endpoint, mutated, context, iteration)
                if not attempt:
                    break

                verdict, evidence, confidence = analyze_attempt(attempt)
                attempt.verdict = verdict
                attempt.evidence = evidence

                logger.debug(
                    "Mutation attempt result",
                    url=endpoint.url,
                    iteration=iteration,
                    verdict=verdict.value,
                    confidence=round(confidence, 2),
                    evidence=evidence[:120],
                )

                if self._audit:
                    self._audit.attack_attempt(
                        attempt, verdict=verdict, evidence=evidence, confidence=confidence
                    )

                if verdict == AttackVerdict.VULNERABLE and confidence >= self._config.confidence_threshold:
                    finding = self._build_finding(endpoint, attempt, evidence, confidence)
                    findings.append(finding)
                    logger.warning(
                        "FINDING CONFIRMED (after mutation)",
                        title=finding.title,
                        severity=finding.severity.value,
                        iteration=iteration,
                        url=endpoint.url,
                    )
                    if self._audit:
                        self._audit.finding_confirmed(finding)
                    break

        return findings

    async def _send_attack(
        self,
        endpoint: Endpoint,
        payload: AttackPayload,
        context: BrowserContext,
        iteration: int,
    ) -> Optional[AttackAttempt]:
        page: Page = await context.new_page()
        captured_req: Optional[HttpRequest] = None
        captured_resp: Optional[HttpResponse] = None
        start = time.time()

        try:
            injected_url, injected_body, injected_headers = self._inject_payload(endpoint, payload)

            logger.debug(
                "Sending attack request",
                method=endpoint.method,
                url=injected_url,
                attack_type=payload.attack_type,
                injection_point=payload.injection_point,
                injection_location=payload.injection_location,
                payload=payload.value[:100],
                iteration=iteration,
            )

            if endpoint.method == "GET":
                resp = await page.goto(injected_url, wait_until="domcontentloaded", timeout=15_000)
                await page.wait_for_timeout(500)
                captured_req = HttpRequest(
                    method="GET", url=injected_url,
                    headers={}, body=None,
                )
                if resp:
                    body = await page.content()
                    captured_resp = HttpResponse(
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        duration_ms=(time.time() - start) * 1000,
                    )
            else:
                result = await page.evaluate(
                    """async ({url, method, headers, body}) => {
                        try {
                            const resp = await fetch(url, {
                                method, headers, body,
                                credentials: 'include'
                            });
                            const text = await resp.text();
                            return {
                                status: resp.status,
                                headers: Object.fromEntries(resp.headers.entries()),
                                body: text,
                                ok: true
                            };
                        } catch (e) {
                            return {status: 0, headers: {}, body: '', ok: false, error: e.message};
                        }
                    }""",
                    {
                        "url": injected_url,
                        "method": endpoint.method,
                        "headers": injected_headers,
                        "body": injected_body,
                    },
                )
                if not result.get("ok"):
                    logger.debug(
                        "Fetch inside browser failed",
                        url=injected_url,
                        error=result.get("error"),
                    )
                    return None

                captured_req = HttpRequest(
                    method=endpoint.method,
                    url=injected_url,
                    headers=injected_headers,
                    body=injected_body,
                )
                captured_resp = HttpResponse(
                    status_code=result["status"],
                    headers=result.get("headers", {}),
                    body=result.get("body", ""),
                    duration_ms=(time.time() - start) * 1000,
                )

            logger.debug(
                "Attack response received",
                url=injected_url,
                status=captured_resp.status_code if captured_resp else None,
                body_length=len(captured_resp.body) if captured_resp else 0,
                duration_ms=round((time.time() - start) * 1000, 1),
            )

        except PwTimeout:
            logger.warning(
                "Attack request timed out",
                url=endpoint.url,
                payload=payload.value[:80],
                iteration=iteration,
            )
        except Exception as e:
            logger.error(
                "Attack request error",
                url=endpoint.url,
                payload=payload.value[:80],
                iteration=iteration,
                error=str(e),
                exc_info=True,
            )
        finally:
            await page.close()

        if not captured_req or not captured_resp:
            return None

        return AttackAttempt(
            endpoint=endpoint,
            payload=payload,
            request=captured_req,
            response=captured_resp,
            iteration=iteration,
        )

    def _inject_payload(self, endpoint: Endpoint, payload: AttackPayload):
        url = endpoint.url
        body: Optional[str] = None
        headers = {}

        if endpoint.sample_request:
            headers = dict(endpoint.sample_request.headers)
            headers.pop("content-length", None)
            headers.pop("Content-Length", None)

        if payload.injection_location == "query":
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[payload.injection_point] = [payload.value]
            url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

        elif payload.injection_location == "body":
            if endpoint.sample_request and endpoint.sample_request.body:
                try:
                    body_data = json.loads(endpoint.sample_request.body)
                    body_data[payload.injection_point] = payload.value
                    body = json.dumps(body_data)
                    headers["content-type"] = "application/json"
                except Exception:
                    body = f"{payload.injection_point}={payload.value}"
                    headers["content-type"] = "application/x-www-form-urlencoded"
            else:
                body = json.dumps({payload.injection_point: payload.value})
                headers["content-type"] = "application/json"

        elif payload.injection_location == "header":
            headers[payload.injection_point] = payload.value

        elif payload.injection_location == "path":
            parts = url.rstrip("/").rsplit("/", 1)
            url = f"{parts[0]}/{payload.value}" if len(parts) > 1 else f"{url}/{payload.value}"

        return url, body, headers

    def _build_finding(
        self, endpoint: Endpoint, attempt: AttackAttempt, evidence: str, confidence: float
    ) -> Finding:
        attack_type = attempt.payload.attack_type
        return Finding(
            title=f"{attack_type.upper()} in {endpoint.method} {endpoint.url}",
            severity=_SEVERITY_MAP.get(attack_type, Severity.MEDIUM),
            attack_type=attack_type,
            endpoint=endpoint,
            evidence=evidence,
            ai_reasoning=attempt.ai_reasoning,
            confirmed_attempts=[attempt],
            cwe=_CWE_MAP.get(attack_type, ""),
            confidence=confidence,
        )
