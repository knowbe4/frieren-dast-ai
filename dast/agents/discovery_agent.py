"""
Discovery agent — CRLF injection and TRACE/TRACK method tampering.

4-A de-dup: SSTI and open-redirect moved fully to their specialist agents
(ssti_agent, open_redirect_agent), which have stronger payloads, engine
fingerprinting and response-following. Discovery keeps only the checks no
specialist covers."""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from dast.agents import probe_common
from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.scanners.active_checks import _fmt_http_pair, _inject_query, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_CRLF_PAYLOAD = "foo%0d%0aSet-Cookie:%20crlf=injected"
_CRLF_MATCH = "crlf=injected"


class DiscoveryAgent(VulnAgent):
    name = "Discovery Agent"
    attack_type = "discovery"
    description = "Tests for CRLF injection and TRACE/TRACK method tampering"

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        # 4-A de-dup: the SSTI and open-redirect sub-sweeps are GONE — they
        # duplicated ssti_agent / open_redirect_agent with strictly weaker
        # payloads and detection. Discovery keeps the two checks no specialist
        # covers: CRLF injection and TRACE/TRACK method tampering.
        findings.extend(await self._check_crlf(target, client))
        findings.extend(await self._check_http_methods(target, client))
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
        return await probe_common.send_probe(
            target, client, param, payload, send=_send,
            locations=probe_common.LOCATIONS_NO_PATH,
        )


from dast.ai.coordinator import Coordinator
Coordinator.register(DiscoveryAgent)
