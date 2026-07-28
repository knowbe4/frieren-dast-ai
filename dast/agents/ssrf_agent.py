"""
SSRF agent — server-side request forgery via OOB callback + inline response detection.
Payloads from ssrf.yaml. {{COLLAB_HOST}}, {{COLLAB_PORT}}, {{TOKEN}} substituted at runtime.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.mutator import build_mutator_context, next_payload
from dast.agents.block_detector import detect_block
from dast.agents.payload_filter import get_filtered_payloads
from dast.payloads.loader import get_payloads, get_value
from dast.scanners.active_checks import _fmt_http_pair, _inject_body, _inject_multipart, _inject_query, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)


_GRAPHQL_ECHO_RE = re.compile(
    r'"errors"\s*:\s*\[.*?"(to be one of|expected type|provided invalid value|'
    r'variable \$|coercion|enum value)',
    re.IGNORECASE | re.DOTALL,
)


def _is_graphql_echo(response_text: str, payload: str) -> bool:
    """
    Returns True when the response is a GraphQL validation error that merely
    echoes the payload back (e.g. 'Expected X to be one of: ...'). In this
    case the server rejected the value at the schema layer and never made any
    outbound request — the payload reflection is not SSRF evidence.
    """
    text_lower = response_text.lower()
    if '"errors"' not in text_lower:
        return False
    if not _GRAPHQL_ECHO_RE.search(response_text):
        return False
    # The payload URL must appear verbatim in the error text (it was echoed)
    return payload.lower() in text_lower


def _resolve(template: str, host: str, port: int, token: str) -> str:
    return (
        template
        .replace("{{COLLAB_HOST}}", host)
        .replace("{{COLLAB_PORT}}", str(port))
        .replace("{{TOKEN}}", token)
    )


class SsrfAgent(VulnAgent):
    name = "SSRF Agent"
    attack_type = "ssrf"
    description = "Tests for SSRF via OOB callbacks and internal response signatures"

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        if collaborator is None:
            return []

        url_keywords = get_value("ssrf", "url_param_keywords") or []
        url_params = [
            p for p in target.params
            if any(kw in p["name"].lower() for kw in url_keywords)
        ]

        # Layer 3: also target params observed carrying URL-like values in call chains
        if target.discovery_context and target.discovery_context.call_edges:
            seen_names = {p["name"] for p in url_params}
            for edge in target.discovery_context.call_edges:
                if edge.target_url == target.url:
                    extra = next(
                        (p for p in target.params if p["name"] == edge.target_param and p["name"] not in seen_names),
                        None,
                    )
                    if extra and ("http" in edge.sample_value.lower() or "/" in edge.sample_value):
                        url_params.append(extra)
                        seen_names.add(extra["name"])
                        logger.debug(
                            "SSRF agent: added param from call chain",
                            param=extra["name"],
                            source=edge.source_url,
                        )

        if not url_params:
            return []

        # Layer 2: add sibling hosts from service graph as additional internal probe targets
        extra_internal: list = []
        if target.service_context and target.service_context.sibling_hosts:
            for sibling in target.service_context.sibling_hosts:
                extra_internal.append(f"http://{sibling}/")
                extra_internal.append(f"https://{sibling}/")
            logger.debug(
                "SSRF agent: probing sibling hosts from service graph",
                url=target.url,
                siblings=target.service_context.sibling_hosts,
            )

        internal_sigs = get_value("ssrf", "internal_response_signatures") or []
        internal_re = re.compile("|".join(re.escape(s) for s in internal_sigs), re.IGNORECASE) if internal_sigs else None

        findings: List[AgentFinding] = []

        for param in url_params:
            finding = await self._probe_param(
                target, client, param, collaborator, internal_re, extra_internal
            )
            if finding:
                findings.append(finding)

        return findings

    async def _probe_param(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        collaborator: "CollaboratorService",
        internal_re: Optional[re.Pattern],
        extra_internal_urls: Optional[list] = None,
    ) -> Optional[AgentFinding]:
        # OOB probes — filtered to groups relevant for this target
        oob_templates = get_filtered_payloads("ssrf", target) or (
            get_payloads("ssrf", "oob_http") + get_payloads("ssrf", "internal_probe")
        )
        payloads_to_try = []
        token_map = {}
        tech_context = build_mutator_context(target, "ssrf")

        for template in oob_templates:
            token = collaborator.issue_token()
            resolved = _resolve(template, collaborator.host, collaborator.port, token)
            # Replace literal decimal-encoded IP (no template vars)
            if "{{" not in resolved:
                payloads_to_try.append((resolved, token))
                token_map[resolved] = token

        for payload, token in payloads_to_try:
            resp = await self._send_probe(target, client, param, payload)
            await asyncio.sleep(1.5)

            if collaborator.was_hit(token):
                raw_request, raw_response = _fmt_http_pair(resp) if resp else ("", "")
                return AgentFinding(
                    title="Server-Side Request Forgery (SSRF)",
                    severity="high",
                    cwe="CWE-918",
                    attack_type="ssrf",
                    evidence=f"OOB callback received for token {token!r} — server fetched attacker-controlled URL",
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=True,
                    raw_request=raw_request,
                    raw_response=raw_response,
                )

            # Inline: check for internal service responses.
            # Guard: GraphQL type/enum validation errors echo the payload back verbatim —
            # the internal URL appears in "Expected X to be one of: ..." and the server
            # never made any outbound request. Discard if the match is inside an errors block.
            if resp and internal_re and internal_re.search(resp.text):
                if _is_graphql_echo(resp.text, payload):
                    continue
                raw_request, raw_response = _fmt_http_pair(resp)
                return AgentFinding(
                    title="Server-Side Request Forgery (SSRF) — Internal Response Detected",
                    severity="critical",
                    cwe="CWE-918",
                    attack_type="ssrf",
                    evidence=f"Internal service response pattern detected in body for payload {payload!r}",
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=False,
                    raw_request=raw_request,
                    raw_response=raw_response,
                )

            # Blocked? Try a mutated bypass
            if resp is not None:
                verdict = detect_block(resp.status_code, resp.text)
                if verdict.is_block:
                    self.observe("waf_block", payload=payload, signal=verdict.signal)
                original_blocked = verdict.is_block
                mutation = await next_payload(
                    attack_type="ssrf",
                    original_payload=payload,
                    parameter=param["name"],
                    response_status=resp.status_code,
                    response_snippet=resp.text[:400],
                    iteration=0,
                    tech_context=tech_context,
                )
                if mutation:
                    mut_token = collaborator.issue_token()
                    mut_payload = _resolve(
                        mutation.payload, collaborator.host, collaborator.port, mut_token
                    )
                    await self._send_probe(target, client, param, mut_payload)
                    await asyncio.sleep(1.5)
                    if collaborator.was_hit(mut_token):
                        # A mutated payload got an OOB callback. Only record it as a
                        # bypass if the original payload was actually blocked —
                        # otherwise this is a normal mutation success, not a bypass,
                        # and would pollute the per-host bypass memory.
                        if original_blocked:
                            self.observe("waf_bypass", payload=mut_payload, signal="OOB callback via mutated bypass payload")
                        return AgentFinding(
                            title="Server-Side Request Forgery (SSRF)",
                            severity="high",
                            cwe="CWE-918",
                            attack_type="ssrf",
                            evidence=f"OOB callback via bypass payload: {mutation.rationale}",
                            payload=mut_payload,
                            parameter=param["name"],
                            url=target.url,
                            request_method=target.method,
                            bypass_validation=True,
                        )

        # Layer 2: probe sibling hosts from service graph
        # These are real services in the same application — SSRF into them is high impact
        if extra_internal_urls:
            # Fetch baseline with the original param value so we can compare response sizes
            baseline_resp = await self._send_probe(target, client, param, param.get("value", ""))
            baseline_len = len(baseline_resp.text) if baseline_resp else 0

            for internal_url in extra_internal_urls:
                resp = await self._send_probe(target, client, param, internal_url)
                if resp is None:
                    continue
                # Only flag when: status < 400 AND response length differs meaningfully from baseline.
                # An endpoint that ignores the param entirely returns the same size regardless —
                # that's not SSRF, it's a parameter being silently dropped.
                if resp.status_code >= 400:
                    continue
                probe_len = len(resp.text)
                size_ratio = probe_len / baseline_len if baseline_len > 0 else 1.0
                if 0.85 <= size_ratio <= 1.15 and baseline_len > 0:
                    # Response is within 15% of baseline — param likely ignored
                    continue
                return AgentFinding(
                    title="Server-Side Request Forgery (SSRF) — Internal Service Reached",
                    severity="critical",
                    cwe="CWE-918",
                    attack_type="ssrf",
                    evidence=(
                        f"Injecting sibling service URL {internal_url!r} returned "
                        f"status {resp.status_code} (baseline: {baseline_resp.status_code if baseline_resp else 'N/A'}, "
                        f"size change: {baseline_len} → {probe_len} bytes) — server fetched the internal URL"
                    ),
                    payload=internal_url,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=False,  # LLM validator confirms — could be coincidental
                )

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
Coordinator.register(SsrfAgent)
