"""GraphQL abuse agent — introspection, alias overload, batching, GET surface.

Round 4-A, techniques from ARTEX api-security (P1 discovery, P2 auth, P4
GraphQL abuse). The sibling ``graphql_agent`` deliberately excludes these
(its docstring lists introspection/depth/batching as out of scope) — this
agent owns exactly that half:

1. **Introspection escalation ladder** (full → reduced → minimal
   ``__schema { types { name } }``): an enabled introspection leaks the whole
   schema; the reduced/minimal levels catch servers that block the canonical
   IntrospectionQuery but still serve ``__schema``.
2. **Field-suggestion disclosure**: an invalid field triggering a
   ``Did you mean …?`` error leaks schema names with introspection disabled.
3. **Alias overload**: dozens of aliases of a zero-cost field (``__typename``)
   in one request — if the answer carries all aliases, the execution layer
   has no alias/batch guard (amplification + authz-bypass enabler).
4. **Batching**: an array-of-operations body answered with an ARRAY —
   operation-level authorization checks are commonly bypassed by batching.
5. **GraphQL over GET**: a query delivered via ``?query=`` — the CSRF surface
   for state-changing operations (mechanism finding, low).
6. **Deep nesting**: the ORIGINAL query's root field nested to a bounded
   depth — a depth/cost/complexity error proves no resource limit.

Every probe is read-only (``__typename`` / ``__schema``); NO mutation is ever
sent. GraphQL always answers HTTP 200 — status is never a signal (same rule
as the sibling agent).
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.payloads.loader import get_payloads
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_DEEP_DEPTH = 30  # bounded — resource-exhaustion probe, not a DoS

_INTROSPECTION_LEVELS = (
    ("introspection_full", "full"),
    ("introspection_reduced", "reduced"),
    ("introspection_minimal", "minimal"),
)


def _is_graphql_target(target: "CheckTarget") -> bool:
    ct = (target.headers or {}).get("content-type", "").lower()
    body_head = (target.body or "")[:200].lstrip().lower()
    if "graphql" in ct:
        return True
    if any(p.get("location") == "body_graphql" for p in (target.params or [])):
        return True
    return body_head.startswith('{"query"') or '"query"' in body_head


def _parse_body(payload: str) -> str:
    """Payload entries are '{"query": ...}' JSON strings — return the raw body
    to send (already JSON)."""
    return str(payload)


def _extract_errors(resp_json: object) -> str:
    errors = ""
    if isinstance(resp_json, dict):
        errors = json.dumps(resp_json.get("errors") or "", default=str)
    elif isinstance(resp_json, list):
        for item in resp_json:
            if isinstance(item, dict) and item.get("errors"):
                errors += json.dumps(item["errors"], default=str)
    return errors


class GraphqlAbuseAgent(VulnAgent):
    name = "GraphQL Abuse Agent"
    attack_type = "graphql_abuse"
    description = (
        "GraphQL abuse: introspection escalation, field-suggestion disclosure, "
        "alias overload, batch acceptance, GraphQL-over-GET and depth limits"
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        if not _is_graphql_target(target):
            return []

        findings: List[AgentFinding] = []
        for probe in (
            self._check_introspection,
            self._check_field_suggestion,
            self._check_alias_overload,
            self._check_batching,
            self._check_get_query,
            self._check_deep_nesting,
        ):
            finding = await probe(target, client)
            if finding:
                findings.append(finding)
        return findings

    async def _post(self, client, target, body: str):
        headers = {**target.headers, "content-type": "application/json"}
        return await _send(client, target.method or "POST", target.url,
                           headers, body, payload=body[:100])

    async def _check_introspection(
        self, target: "CheckTarget", client: "httpx.AsyncClient"
    ) -> Optional[AgentFinding]:
        for group, level in _INTROSPECTION_LEVELS:
            payloads = get_payloads("graphql_abuse", group) or []
            if not payloads:
                continue
            resp = await self._post(client, target, _parse_body(payloads[0]))
            if not resp:
                continue
            try:
                parsed = json.loads(resp.text)
            except (json.JSONDecodeError, ValueError):
                continue
            types = (parsed.get("data", {}) or {}).get("__schema", {}).get("types") \
                if isinstance(parsed, dict) else None
            if not types:
                continue
            raw_req, raw_resp = _fmt_http_pair(resp)
            log_event("agent", "finding",
                      f"GraphQL introspection enabled ({level}) on {target.url}",
                      url=target.url, finding="GraphQL introspection", source="agent")
            return AgentFinding(
                title=f"GraphQL Introspection Enabled ({level} query)",
                severity="medium" if level == "full" else "low",
                cwe="CWE-200",
                attack_type="graphql_abuse",
                evidence=(
                    f"The endpoint answers a {level} introspection query with "
                    f"{len(types)} types — the full operation schema is readable "
                    f"by any unauthenticated client, handing attackers every "
                    f"mutation and hidden field.\n\n"
                    f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                ),
                confirmed=True,
                payload=str(payloads[0])[:200],
                parameter="query",
                url=target.url,
                request_method="POST",
                bypass_validation=True,
                raw_request=raw_req,
                raw_response=raw_resp[:2000],
            )
        return None

    async def _check_field_suggestion(
        self, target: "CheckTarget", client: "httpx.AsyncClient"
    ) -> Optional[AgentFinding]:
        payloads = get_payloads("graphql_abuse", "field_suggestion") or []
        if not payloads:
            return None
        resp = await self._post(client, target, _parse_body(payloads[0]))
        if not resp:
            return None
        errors = _extract_errors(_safe_json(resp.text))
        if 'did you mean' not in errors.lower():
            return None
        raw_req, raw_resp = _fmt_http_pair(resp)
        leaked = errors[errors.lower().index('did you mean') - 1:][:160]
        log_event("agent", "finding",
                  f"GraphQL field-suggestion disclosure on {target.url}",
                  url=target.url, finding="field suggestions", source="agent")
        return AgentFinding(
            title="GraphQL Field-Suggestion Disclosure",
            severity="low",
            cwe="CWE-200",
            attack_type="graphql_abuse",
            evidence=(
                "An invalid field triggered a 'Did you mean …?' suggestion, "
                "disclosing real schema names with (presumably) introspection "
                f"disabled. Leaked: {leaked}\n\n"
                f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
            ),
            confirmed=True,
            payload=str(payloads[0])[:200],
            parameter="query",
            url=target.url,
            request_method="POST",
            bypass_validation=True,
            raw_request=raw_req,
            raw_response=raw_resp[:2000],
        )

    async def _check_alias_overload(
        self, target: "CheckTarget", client: "httpx.AsyncClient"
    ) -> Optional[AgentFinding]:
        aliases = ", ".join(f"a{i}: __typename" for i in range(60))
        resp = await self._post(
            client, target, json.dumps({"query": f"query {{ {aliases} }}"}))
        if not resp:
            return None
        try:
            parsed = json.loads(resp.text)
        except (json.JSONDecodeError, ValueError):
            return None
        data = parsed.get("data") if isinstance(parsed, dict) else None
        if not isinstance(data, dict) or len(data) < 10:
            return None  # server rejected/capped the alias set — good
        raw_req, raw_resp = _fmt_http_pair(resp)
        log_event("agent", "finding",
                  f"GraphQL alias overload accepted on {target.url} ({len(data)} aliases)",
                  url=target.url, finding="alias overload", source="agent")
        return AgentFinding(
            title="GraphQL Alias Overload Accepted (no batch/cost guard)",
            severity="medium",
            cwe="CWE-400",
            attack_type="graphql_abuse",
            evidence=(
                f"A single request with {len(data)} aliases was answered with all "
                f"{len(data)} results — no alias-count or cost guard. The same "
                f"mechanism amplifies computation and batches authz-bound "
                f"operations into one authorized request.\n\n"
                f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
            ),
            confirmed=True,
            payload=f"query {{ {aliases[:80]} … }}",
            parameter="query",
            url=target.url,
            request_method="POST",
            bypass_validation=True,
            raw_request=raw_req,
            raw_response=raw_resp[:2000],
        )

    async def _check_batching(
        self, target: "CheckTarget", client: "httpx.AsyncClient"
    ) -> Optional[AgentFinding]:
        payloads = get_payloads("graphql_abuse", "batching") or []
        if not payloads:
            return None
        resp = await self._post(client, target, str(payloads[0]))
        if not resp:
            return None
        try:
            parsed = json.loads(resp.text)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(parsed, list) or len(parsed) < 2:
            return None
        raw_req, raw_resp = _fmt_http_pair(resp)
        log_event("agent", "finding",
                  f"GraphQL batch acceptance on {target.url}",
                  url=target.url, finding="batching", source="agent")
        return AgentFinding(
            title="GraphQL Batch Operations Accepted",
            severity="medium",
            cwe="CWE-285",
            attack_type="graphql_abuse",
            evidence=(
                f"An array of {len(parsed)} operations was answered with an array "
                f"of results — per-operation authorization checks are commonly "
                f"bypassed by batching an allowed operation with a forbidden one.\n\n"
                f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
            ),
            confirmed=True,
            payload=str(payloads[0])[:200],
            parameter="query[]",
            url=target.url,
            request_method="POST",
            bypass_validation=True,
            raw_request=raw_req,
            raw_response=raw_resp[:2000],
        )

    async def _check_get_query(
        self, target: "CheckTarget", client: "httpx.AsyncClient"
    ) -> Optional[AgentFinding]:
        payloads = get_payloads("graphql_abuse", "get_query") or []
        if not payloads:
            return None
        query = str(payloads[0])
        resp = await _send(client, "GET", f"{target.url}?query={query}",
                           {k: v for k, v in (target.headers or {}).items()
                            if not k.lower().startswith("content-type")},
                           None)
        if not resp:
            return None
        try:
            parsed = json.loads(resp.text)
        except (json.JSONDecodeError, ValueError):
            return None
        if not (isinstance(parsed, dict) and parsed.get("data")):
            return None
        raw_req, raw_resp = _fmt_http_pair(resp)
        log_event("agent", "finding",
                  f"GraphQL over GET accepted on {target.url}",
                  url=target.url, finding="GET query", source="agent")
        return AgentFinding(
            title="GraphQL Operations Accepted via GET",
            severity="low",
            cwe="CWE-352",
            attack_type="graphql_abuse",
            evidence=(
                "A query delivered via the GET query string was executed. State-"
                "changing operations over GET bypass CSRF token enforcement (no "
                "body, no preflight). Only a read-only __typename was sent — "
                "whether mutations are equally accepted needs an authorized "
                "manual check.\n\n"
                f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
            ),
            confirmed=False,
            payload=query,
            parameter="query",
            url=target.url,
            request_method="GET",
            bypass_validation=False,
            raw_request=raw_req,
            raw_response=raw_resp[:2000],
        )

    async def _check_deep_nesting(
        self, target: "CheckTarget", client: "httpx.AsyncClient"
    ) -> Optional[AgentFinding]:
        if not (target.body or ""):
            return None
        m = re.search(r'\{\s*([A-Za-z_][A-Za-z0-9_]*)', str(target.body))
        if not m:
            return None
        root = m.group(1)
        nesting = " { ".join([root] * _DEEP_DEPTH) + " }" * _DEEP_DEPTH
        templates = get_payloads("graphql_abuse", "deep_nesting_template") or []
        query = str(templates[0]).replace("{root_field}", root) \
            .replace("{depth_nesting}", nesting) if templates else \
            f"query {{ {nesting} }}"
        resp = await self._post(client, target, json.dumps({"query": query}))
        if not resp:
            return None
        errors = _extract_errors(_safe_json(resp.text)).lower()
        if not any(k in errors for k in ("depth", "complexity", "cost", "too deep", "max")):
            return None
        raw_req, raw_resp = _fmt_http_pair(resp)
        log_event("agent", "finding",
                  f"GraphQL depth limit reports cost error on {target.url}",
                  url=target.url, finding="depth probing", source="agent")
        return AgentFinding(
            title="GraphQL Depth/Cost Limit Error Details",
            severity="low",
            cwe="CWE-400",
            attack_type="graphql_abuse",
            evidence=(
                f"A depth-{_DEEP_DEPTH} nesting probe over the original query's "
                f"root field ('{root}') returned a limit-related error — the "
                f"server enforces SOME resource limit and discloses its shape. "
                f"Tune below the limit: attackers bisect until they land just "
                f"under it.\n\n"
                f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
            ),
            confirmed=False,
            payload=query[:200],
            parameter="query",
            url=target.url,
            request_method="POST",
            bypass_validation=False,
            raw_request=raw_req,
            raw_response=raw_resp[:2000],
        )


def _safe_json(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


from dast.ai.coordinator import Coordinator  # noqa: E402

Coordinator.register(GraphqlAbuseAgent)
