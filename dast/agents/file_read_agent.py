"""
File read agent — path traversal and local file inclusion.
Payloads from lfi.yaml. LLM mutator generates encoding bypasses when WAF strips sequences.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.mutator import build_mutator_context, next_payload
from dast.agents.block_detector import detect_block
from dast.agents.payload_filter import get_filtered_payloads
from dast.payloads.loader import get_payloads, get_signatures
from dast.scanners.active_checks import _fmt_http_pair, _inject_body, _inject_multipart, _inject_query, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)


def _build_match_re() -> re.Pattern:
    sigs = get_signatures("lfi", "match_signatures")
    if not sigs:
        sigs = [r"root:.*:0:0:", r"\[fonts\]", r"\[boot loader\]"]
    return re.compile("|".join(sigs), re.IGNORECASE)




class FileReadAgent(VulnAgent):
    name = "File Read Agent"
    attack_type = "lfi"
    description = "Tests for path traversal and LFI with adaptive encoding bypass"

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        match_re = _build_match_re()

        for param in target.params:
            finding = await self._probe_param(target, client, param, match_re)
            if finding:
                findings.append(finding)

        return findings

    async def _probe_param(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        match_re: re.Pattern,
    ) -> Optional[AgentFinding]:
        seed = get_filtered_payloads("lfi", target) or (
            get_payloads("lfi", "unix") + get_payloads("lfi", "null_byte")
        )
        payloads_to_try = list(seed)
        tried: set = set()
        mutation_iteration = 0
        block_seen = False  # did an earlier probe on this param get blocked?
        tech_context = build_mutator_context(target, "lfi")

        for iteration, payload in enumerate(payloads_to_try):
            if payload in tried:
                continue
            tried.add(payload)

            if param["location"] == "query":
                url = _inject_query(target.url, param["name"], payload)
                resp = await _send(client, "GET", url, target.headers, None)
            elif param["location"] in ("body", "body_graphql"):
                body = _inject_body(
                    target.body or "", param["name"], payload,
                    target.headers.get("content-type", ""),
                    location=param["location"],
                )
                resp = await _send(client, target.method, target.url, target.headers, body)
            elif param["location"].startswith("multipart_"):
                raw = _inject_multipart(target.raw_body or b"", param["name"], payload)
                resp = await _send(client, target.method, target.url, target.headers, raw)
            else:
                continue

            if resp and match_re.search(resp.text):
                if block_seen:
                    self.observe("waf_bypass", payload=payload, signal="payload succeeded after prior block")
                m = match_re.search(resp.text)
                snippet = resp.text[max(0, m.start() - 30):m.end() + 80].strip() if m else ""
                raw_request, raw_response = _fmt_http_pair(resp)
                return AgentFinding(
                    title="Path Traversal / Local File Inclusion",
                    severity="high",
                    cwe="CWE-22",
                    attack_type="lfi",
                    evidence=f"File content pattern detected for payload {payload!r}",
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=True,
                    raw_response_snippet=snippet,
                    raw_request=raw_request,
                    raw_response=raw_response,
                )

            if resp is not None and iteration >= len(seed) - 1:
                verdict = detect_block(resp.status_code, resp.text)
                if verdict.is_block:
                    block_seen = True
                    self.observe("waf_block", payload=payload, signal=verdict.signal)
                mutation = await next_payload(
                    attack_type="lfi",
                    original_payload=payload,
                    parameter=param["name"],
                    response_status=resp.status_code,
                    response_snippet=resp.text[:400],
                    iteration=mutation_iteration,
                    tried_payloads=list(tried),
                    tech_context=tech_context,
                )
                mutation_iteration += 1
                if mutation is None:
                    break
                logger.debug(
                    "LFI mutator", param=param["name"], action=mutation.action,
                    rationale=mutation.rationale,
                )
                payloads_to_try.append(mutation.payload)

        return None


from dast.ai.coordinator import Coordinator
Coordinator.register(FileReadAgent)
