"""
Discovery agent — SSTI, open redirect, CRLF injection, HTTP method tampering.
SSTI payloads loaded from ssti.yaml; LLM mutator generates WAF bypass variants.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.mutator import build_mutator_context, next_payload
from dast.agents.block_detector import detect_block
from dast.agents.payload_filter import get_filtered_payloads
from dast.payloads.loader import get_detection_payloads
from dast.scanners.active_checks import _fmt_http_pair, _inject_body, _inject_multipart, _inject_query, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

def _ssti_hit(payload: str, expected: str, response_text: str) -> bool:
    """
    True only when the expected value appears as a standalone evaluated result.

    Two conditions must BOTH hold:
      1. The raw payload is NOT present verbatim — if the server stored the expression
         unchanged, it was never evaluated (storage ≠ template execution).
      2. The expected product appears as an isolated integer — not as a substring
         inside a UUID, larger number, or hex sequence.
    """
    if payload in response_text:
        return False  # payload echoed back unchanged — not evaluated
    # The expected value must be surrounded by non-digit, non-hex-letter, non-hyphen chars
    # so "79014691" doesn't fire on "7901469100" or inside a UUID segment.
    return bool(re.search(r'(?<![0-9a-fA-F\-])' + re.escape(expected) + r'(?![0-9a-fA-F\-])', response_text))


_REDIRECT_URL_KEYWORDS = (
    "url", "redirect", "next", "return", "goto", "dest", "destination",
    "redir", "continue", "target",
)
_CRLF_PAYLOAD = "foo%0d%0aSet-Cookie:%20crlf=injected"
_CRLF_MATCH = "crlf=injected"


class DiscoveryAgent(VulnAgent):
    name = "Discovery Agent"
    attack_type = "discovery"
    description = "Tests for SSTI, open redirect, CRLF injection, HTTP method tampering"

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        findings.extend(await self._check_ssti(target, client))
        findings.extend(await self._check_open_redirect(target, client))
        findings.extend(await self._check_crlf(target, client))
        findings.extend(await self._check_http_methods(target, client))
        return findings

    async def _check_ssti(
        self, target: "CheckTarget", client: "httpx.AsyncClient"
    ) -> List[AgentFinding]:
        ssti_payloads = get_filtered_payloads("ssti", target)
        if not ssti_payloads:
            # No evidence of server-side template rendering — skip SSTI entirely
            return []
        # detection_payloads are dicts with expected values; pass as seed, obfuscation as empty
        detection_payloads = get_detection_payloads("ssti")
        obfuscation_payloads: list = []

        for param in target.params:
            finding = await self._probe_ssti_param(
                target, client, param, detection_payloads, obfuscation_payloads
            )
            if finding:
                return [finding]
        return []

    async def _probe_ssti_param(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        seed_payloads: List[Dict[str, Any]],
        obfuscation_payloads: List[Dict[str, Any]],
    ) -> Optional[AgentFinding]:
        all_seeds = seed_payloads + obfuscation_payloads
        payloads_to_try = list(all_seeds)
        tried: set = set()
        mutation_iteration = 0
        block_seen = False  # did an earlier probe on this param get blocked?
        tech_context = build_mutator_context(target, "ssti")

        for iteration, item in enumerate(payloads_to_try):
            if isinstance(item, str):
                payload = item
                expected = None
            else:
                payload = item.get("payload", "")
                expected = item.get("expected")

            if not payload or payload in tried:
                continue
            tried.add(payload)

            resp = await self._send_probe(target, client, param, payload)
            if resp is None:
                continue

            hit = (
                (expected is not None and _ssti_hit(payload, expected, resp.text))
                or (expected is None and re.search(r"\b49\b|\buid=\d+\b", resp.text)
                    and payload not in resp.text)
            )
            if hit:
                if block_seen:
                    self.observe("waf_bypass", payload=payload, signal="payload succeeded after prior block")
                raw_request, raw_response = _fmt_http_pair(resp)
                return AgentFinding(
                    title="Server-Side Template Injection (SSTI)",
                    severity="critical",
                    cwe="CWE-94",
                    attack_type="ssti",
                    evidence=(
                        f"Template expression {payload!r} evaluated"
                        + (f" to {expected!r}" if expected else " — server-side execution confirmed")
                        + f" in param '{param['name']}'"
                    ),
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                    raw_request=raw_request,
                    raw_response=raw_response,
                )

            if iteration >= len(all_seeds) - 1:
                verdict = detect_block(resp.status_code, resp.text)
                if verdict.is_block:
                    block_seen = True
                    self.observe("waf_block", payload=payload, signal=verdict.signal)
                mutation = await next_payload(
                    attack_type="ssti",
                    original_payload=payload,
                    parameter=param["name"],
                    response_status=resp.status_code,
                    response_snippet=resp.text[:500],
                    iteration=mutation_iteration,
                    tried_payloads=list(tried),
                    tech_context=tech_context,
                )
                mutation_iteration += 1
                if mutation is None:
                    break
                logger.debug(
                    "SSTI mutator", param=param["name"], action=mutation.action,
                    rationale=mutation.rationale,
                )
                payloads_to_try.append({"payload": mutation.payload, "expected": "79014691"})

        return None

    async def _check_open_redirect(
        self, target: "CheckTarget", client: "httpx.AsyncClient"
    ) -> List[AgentFinding]:
        findings = []
        redirect_payloads = [
            "https://evil.example.com",
            "//evil.example.com",
            "/\\evil.example.com",
        ]
        for param in target.params:
            if not any(kw in param["name"].lower() for kw in _REDIRECT_URL_KEYWORDS):
                continue
            for payload in redirect_payloads:
                if param["location"] != "query":
                    continue
                url = _inject_query(target.url, param["name"], payload)
                resp = await _send(client, target.method, url, target.headers, target.body)
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("location", "")
                    if "evil.example.com" in loc:
                        raw_request, raw_response = _fmt_http_pair(resp)
                        findings.append(AgentFinding(
                            title="Open Redirect",
                            severity="medium",
                            cwe="CWE-601",
                            attack_type="open_redirect",
                            evidence=f"Server redirected to {loc!r}",
                            payload=payload,
                            parameter=param["name"],
                            url=target.url,
                            request_method=target.method,
                            raw_request=raw_request,
                            raw_response=raw_response,
                        ))
                        break
        return findings

    async def _check_crlf(
        self, target: "CheckTarget", client: "httpx.AsyncClient"
    ) -> List[AgentFinding]:
        findings = []
        # Fetch baseline with the target's actual method so we can compare
        baseline = await _send(client, target.method, target.url, target.headers, target.body)
        baseline_cookies = baseline.headers.get("set-cookie", "") if baseline else ""

        for param in target.params:
            if param["location"] != "query":
                continue
            url = _inject_query(target.url, param["name"], _CRLF_PAYLOAD)
            resp = await _send(client, target.method, url, target.headers, target.body)
            if resp and _CRLF_MATCH in resp.headers.get("set-cookie", ""):
                # Verify the injected header was NOT already in the baseline
                if _CRLF_MATCH in baseline_cookies:
                    continue
                raw_request, raw_response = _fmt_http_pair(resp)
                findings.append(AgentFinding(
                    title="CRLF Injection / HTTP Response Splitting",
                    severity="medium",
                    cwe="CWE-113",
                    attack_type="crlf",
                    evidence=f"Injected Set-Cookie header appeared in response for param '{param['name']}' — not present in baseline response",
                    payload=_CRLF_PAYLOAD,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                    raw_request=raw_request,
                    raw_response=raw_response,
                ))
        return findings

    async def _check_http_methods(
        self, target: "CheckTarget", client: "httpx.AsyncClient"
    ) -> List[AgentFinding]:
        findings = []
        # Fetch baseline with a normal GET to understand the standard response
        baseline = await _send(client, "GET", target.url, target.headers, None)
        baseline_status = baseline.status_code if baseline else None
        baseline_body_upper = (baseline.text[:500].upper() if baseline else "")

        for method in ("TRACE", "TRACK"):
            resp = await _send(client, method, target.url, target.headers, None)
            if not resp or resp.status_code != 200:
                continue
            # The method name must appear in the response body AND must not have
            # appeared in the baseline response (rules out echo-heavy apps)
            if method not in resp.text[:500].upper():
                continue
            if method in baseline_body_upper:
                continue
            raw_request, raw_response = _fmt_http_pair(resp)
            findings.append(AgentFinding(
                title=f"Dangerous HTTP Method Enabled: {method}",
                severity="low",
                cwe="CWE-16",
                attack_type="method_tamper",
                evidence=(
                    f"{method} request returned 200 and echoed the method name in the response body. "
                    f"Baseline GET returned {baseline_status}."
                ),
                payload=method,
                parameter="",
                url=target.url,
                request_method=method,
                raw_request=raw_request,
                raw_response=raw_response,
            ))
        return findings

    async def _send_probe(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        payload: str,
    ):
        if param["location"] == "query":
            url = _inject_query(target.url, param["name"], payload)
            return await _send(client, target.method, url, target.headers, target.body)
        elif param["location"] in ("body", "body_graphql"):
            body = _inject_body(
                target.body or "", param["name"], payload,
                target.headers.get("content-type", ""),
                location=param["location"],
            )
            return await _send(client, target.method, target.url, target.headers, body)
        elif param["location"].startswith("multipart_"):
            raw = _inject_multipart(target.raw_body or b"", param["name"], payload)
            return await _send(client, target.method, target.url, target.headers, raw)
        return None


from dast.ai.coordinator import Coordinator
Coordinator.register(DiscoveryAgent)
