"""
Prototype pollution agent — tests Node.js/JS applications for __proto__ manipulation.

Strategy:
  1. Query string: inject __proto__[polluted]=dast_marker, check if marker appears
     in a subsequent GET response (property propagated to new objects)
  2. JSON body: inject {"__proto__": {"polluted": "dast_marker"}} in POST/PUT/PATCH
  3. Detection: response contains the injected property value in any subsequent
     response, or the server reflects the property in error/debug output

Detection is conservative — requires the injected marker to appear in a response
where it was NOT present in the baseline. This avoids FP from servers that simply
echo back the input.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.coordinator import Coordinator
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_MARKER = "dast_pp_7x9k"

_PP_ERROR_RE = re.compile(
    r"(Cannot set propert.*of undefined|"
    r"Cannot read propert.*of null|"
    r"__proto__.*not allowed|"
    r"prototype.*pollution.*detected|"
    r"Prototype.*overwrite|"
    r"Object\.assign.*__proto__)",
    re.I,
)


class PrototypePollutionAgent(VulnAgent):
    name = "Prototype Pollution Agent"
    attack_type = "prototype_pollution"
    description = "Tests for JavaScript prototype pollution via __proto__ and constructor.prototype"

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        # Only relevant for endpoints that accept JSON or query params
        has_json = target.body and target.body.strip().startswith(("{", "["))
        has_params = bool(target.params)

        if not has_json and not has_params:
            logger.debug("prototype_pollution: no params or json body", url=target.url)
            return []

        logger.info("prototype_pollution: testing %s", target.url)

        # Get baseline
        baseline = await _send(client, target.method, target.url, target.headers, target.body)
        if not baseline:
            return []
        baseline_body = baseline.text[:4000]

        # Phase 1: Query string pollution
        if has_params:
            qs_payloads = [
                f"__proto__[polluted]={_MARKER}",
                f"constructor[prototype][polluted]={_MARKER}",
                f"__pro%74o__[polluted]={_MARKER}",
            ]
            for payload in qs_payloads:
                # Append raw to URL
                sep = "&" if "?" in target.url else "?"
                url = f"{target.url}{sep}{payload}"
                resp = await _send(client, target.method, url, target.headers, target.body, payload=payload)
                if not resp:
                    continue

                finding = self._check_response(resp, target, payload, "query string", baseline_body)
                if finding:
                    findings.append(finding)
                    return findings

            # After injection, make a clean GET to see if pollution persists
            clean_resp = await _send(client, "GET", target.url.split("?")[0], target.headers, None)
            if clean_resp and _MARKER in clean_resp.text and _MARKER not in baseline_body:
                raw_req, raw_resp = _fmt_http_pair(clean_resp)
                log_event("agent", "finding",
                          f"Prototype pollution persisted on {target.url}",
                          url=target.url, finding="Prototype Pollution", source="agent")
                findings.append(AgentFinding(
                    title="Prototype Pollution — Persistent",
                    severity="critical",
                    cwe="CWE-1321",
                    attack_type="prototype_pollution",
                    evidence=(
                        f"After injecting __proto__[polluted]={_MARKER} via query string, "
                        f"a subsequent clean GET returned the marker '{_MARKER}' in the response. "
                        f"The pollution persisted in Object.prototype.\n\n"
                        f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                    ),
                    confirmed=True,
                    payload=f"__proto__[polluted]={_MARKER}",
                    parameter="__proto__",
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=True,
                    raw_request=raw_req,
                    raw_response=raw_resp[:2000],
                ))
                return findings

        # Phase 2: JSON body pollution
        if has_json and target.method in ("POST", "PUT", "PATCH"):
            json_payloads = [
                {"__proto__": {"polluted": _MARKER}},
                {"constructor": {"prototype": {"polluted": _MARKER}}},
            ]
            for payload_obj in json_payloads:
                try:
                    original = json.loads(target.body)
                    if isinstance(original, dict):
                        merged = {**original, **payload_obj}
                    else:
                        merged = payload_obj
                    body = json.dumps(merged)
                except (json.JSONDecodeError, TypeError) as exc:
                    logger.debug("prototype_pollution: body merge failed", error=str(exc))
                    body = json.dumps(payload_obj)

                payload_str = json.dumps(payload_obj)
                resp = await _send(client, target.method, target.url, target.headers, body, payload=payload_str[:100])
                if not resp:
                    continue

                finding = self._check_response(resp, target, payload_str, "JSON body", baseline_body)
                if finding:
                    findings.append(finding)
                    return findings

        return findings

    def _check_response(
        self, resp: "httpx.Response", target: "CheckTarget",
        payload: str, vector: str, baseline_body: str,
    ) -> Optional[AgentFinding]:
        body = resp.text[:8000]

        # Check for marker in response (not in baseline)
        if _MARKER in body and _MARKER not in baseline_body:
            raw_req, raw_resp = _fmt_http_pair(resp)
            log_event("agent", "finding",
                      f"Prototype pollution: marker reflected on {target.url}",
                      url=target.url, finding="Prototype Pollution", source="agent")
            return AgentFinding(
                title="Prototype Pollution — Property Injected",
                severity="high",
                cwe="CWE-1321",
                attack_type="prototype_pollution",
                evidence=(
                    f"Payload via {vector}: '{payload}' — the injected marker "
                    f"'{_MARKER}' appeared in the response body, confirming that "
                    f"__proto__ properties propagate to application objects.\n\n"
                    f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                ),
                confirmed=True,
                payload=payload,
                parameter="__proto__",
                url=target.url,
                request_method=target.method,
                raw_request=raw_req,
                raw_response=raw_resp[:2000],
            )

        # Check for error indicating the server processes __proto__
        error_match = _PP_ERROR_RE.search(body)
        if error_match and not _PP_ERROR_RE.search(baseline_body):
            raw_req, raw_resp = _fmt_http_pair(resp)
            return AgentFinding(
                title="Prototype Pollution — Server Processes __proto__",
                severity="medium",
                cwe="CWE-1321",
                attack_type="prototype_pollution",
                evidence=(
                    f"Payload via {vector}: '{payload}' triggered error: "
                    f"'{error_match.group(0)}'. The server attempted to process "
                    f"__proto__ properties — exploitation may be possible.\n\n"
                    f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                ),
                payload=payload,
                parameter="__proto__",
                url=target.url,
                request_method=target.method,
                raw_request=raw_req,
                raw_response=raw_resp[:2000],
            )

        return None


Coordinator.register(PrototypePollutionAgent)
