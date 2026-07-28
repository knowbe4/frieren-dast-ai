"""
NoSQL injection agent — MongoDB operator injection and $where JavaScript injection.

Strategy:
  1. JSON body params: inject operator objects ({"$gt":""}, {"$ne":null})
  2. URL query params: inject [$gt]= / [$ne]= notation
  3. $where injection: inject JavaScript tautologies
  4. Detection: response diff (more results than baseline), error patterns, time-based

Does NOT use time-based sleep > 5s per safety policy.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.coordinator import Coordinator
from dast.payloads.loader import get_payloads
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _inject_query, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_NOSQL_ERROR_RE = re.compile(
    r"(\$where|operator.*not.*allowed|cast.*failed|bson.*error|"
    r"MongoError|BSONTypeError|CastError|ValidationError.*path|"
    r"Cannot use.*\$.*operator|unknown operator|"
    r"E11000|OperationFailure|WriteConflict|"
    r"unexpected token|SyntaxError.*javascript)",
    re.I,
)

_JSON_ARRAY_RE = re.compile(r'^\s*\[')


def _response_item_count(body: str) -> int:
    """Estimate the number of items/records in a JSON response."""
    body = body.strip()
    try:
        data = json.loads(body)
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            for key in ("data", "results", "items", "records", "users", "entries"):
                val = data.get(key)
                if isinstance(val, list):
                    return len(val)
            return 1
    except (json.JSONDecodeError, TypeError, ValueError):
        return -1
    return -1


class NosqlAgent(VulnAgent):
    name = "NoSQL Injection Agent"
    attack_type = "nosql"
    description = "Tests for MongoDB operator injection and $where JavaScript injection"

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        params = [p for p in target.params if p.get("type") not in ("token", "boolean")]
        if not params:
            return []

        logger.info("nosql: testing %d param(s) on %s", len(params), target.url)

        # Get baseline response for comparison
        baseline_resp = await _send(client, target.method, target.url, target.headers, target.body)
        if not baseline_resp:
            return []
        baseline_body = baseline_resp.text[:8000]
        baseline_count = _response_item_count(baseline_body)
        baseline_len = len(baseline_body)

        operator_payloads = get_payloads("nosql", "mongodb_operator") or []
        where_payloads = get_payloads("nosql", "where_injection") or []

        for param in params[:6]:
            param_name = param.get("name", "")
            if not param_name:
                continue

            # Phase 1: Operator injection (JSON body)
            is_json_body = target.body and target.body.strip().startswith(("{", "["))
            if is_json_body:
                for payload in operator_payloads[:8]:
                    payload_str = str(payload)
                    if payload_str.startswith("{"):
                        finding = await self._probe_json_body(
                            target, client, param_name, payload_str,
                            baseline_count, baseline_len,
                        )
                        if finding:
                            findings.append(finding)
                            return findings

            # Phase 2: Query string operator injection ([$gt]= notation)
            for payload in operator_payloads:
                payload_str = str(payload)
                if payload_str.startswith("["):
                    injected_param = f"{param_name}{payload_str}"
                    url = _inject_query(target.url, injected_param, "")
                    finding = await self._probe_query(
                        target, client, url, param_name, payload_str,
                        baseline_count, baseline_len,
                    )
                    if finding:
                        findings.append(finding)
                        return findings

            # Phase 3: $where JavaScript injection
            for payload in (where_payloads or ['this.a==this.a', '1==1', 'function(){return true}']):
                payload_str = str(payload)
                url = _inject_query(target.url, param_name, payload_str)
                finding = await self._probe_query(
                    target, client, url, param_name, payload_str,
                    baseline_count, baseline_len,
                )
                if finding:
                    findings.append(finding)
                    return findings

        return findings

    async def _probe_json_body(
        self, target: "CheckTarget", client: "httpx.AsyncClient",
        param_name: str, payload: str, baseline_count: int, baseline_len: int,
    ) -> Optional[AgentFinding]:
        try:
            body_dict = json.loads(target.body)
            if not isinstance(body_dict, dict):
                return None
            if param_name not in body_dict:
                return None
            injected = dict(body_dict)
            injected[param_name] = json.loads(payload)
            new_body = json.dumps(injected)
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            logger.debug("nosql: body injection failed", param=param_name, error=str(exc))
            return None

        resp = await _send(client, target.method, target.url, target.headers, new_body, payload=payload)
        if not resp:
            return None

        return self._check_response(resp, target, param_name, payload, baseline_count, baseline_len)

    async def _probe_query(
        self, target: "CheckTarget", client: "httpx.AsyncClient",
        url: str, param_name: str, payload: str,
        baseline_count: int, baseline_len: int,
    ) -> Optional[AgentFinding]:
        resp = await _send(client, target.method, url, target.headers, target.body, payload=payload)
        if not resp:
            return None

        return self._check_response(resp, target, param_name, payload, baseline_count, baseline_len)

    def _check_response(
        self, resp: "httpx.Response", target: "CheckTarget",
        param_name: str, payload: str, baseline_count: int, baseline_len: int,
    ) -> Optional[AgentFinding]:
        body = resp.text[:8000]

        # Check for NoSQL error disclosure
        error_match = _NOSQL_ERROR_RE.search(body)
        if error_match:
            raw_req, raw_resp = _fmt_http_pair(resp)
            log_event("agent", "finding",
                      f"NoSQL error: {param_name} on {target.url}",
                      url=target.url, finding="NoSQL injection error", source="agent")
            return AgentFinding(
                title="NoSQL Injection — Error Disclosure",
                severity="high",
                cwe="CWE-943",
                attack_type="nosql",
                evidence=(
                    f"Parameter '{param_name}' with payload '{payload}' triggered a "
                    f"NoSQL/MongoDB error: '{error_match.group(0)}'. "
                    f"This confirms the parameter is interpolated into a NoSQL query.\n\n"
                    f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                ),
                confirmed=True,
                payload=payload,
                parameter=param_name,
                url=target.url,
                request_method=target.method,
                raw_request=raw_req,
                raw_response=raw_resp[:2000],
            )

        # Check for response diff (more results = bypassed filter)
        resp_count = _response_item_count(body)
        resp_len = len(body)
        if baseline_count >= 0 and resp_count > baseline_count and resp_count > 1:
            raw_req, raw_resp = _fmt_http_pair(resp)
            log_event("agent", "finding",
                      f"NoSQL injection: response count diff on {param_name}",
                      url=target.url, finding="NoSQL injection", source="agent")
            return AgentFinding(
                title="NoSQL Injection — Authentication/Filter Bypass",
                severity="critical",
                cwe="CWE-943",
                attack_type="nosql",
                evidence=(
                    f"Parameter '{param_name}' with operator '{payload}' returned "
                    f"{resp_count} items vs baseline {baseline_count}. "
                    f"The operator bypassed the query filter, returning unauthorized data.\n\n"
                    f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                ),
                confirmed=True,
                payload=payload,
                parameter=param_name,
                url=target.url,
                request_method=target.method,
                bypass_validation=True,
                raw_request=raw_req,
                raw_response=raw_resp[:2000],
            )

        # Significant response length change (>50% larger) can indicate bypass
        if baseline_len > 100 and resp_len > baseline_len * 1.5 and resp.status_code == 200:
            raw_req, raw_resp = _fmt_http_pair(resp)
            return AgentFinding(
                title="NoSQL Injection — Possible Query Manipulation",
                severity="medium",
                cwe="CWE-943",
                attack_type="nosql",
                evidence=(
                    f"Parameter '{param_name}' with payload '{payload}' caused response "
                    f"body to grow from {baseline_len} to {resp_len} bytes (+{resp_len - baseline_len}). "
                    f"This may indicate the operator modified the query behaviour.\n\n"
                    f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                ),
                payload=payload,
                parameter=param_name,
                url=target.url,
                request_method=target.method,
                raw_request=raw_req,
                raw_response=raw_resp[:2000],
            )

        return None


Coordinator.register(NosqlAgent)
