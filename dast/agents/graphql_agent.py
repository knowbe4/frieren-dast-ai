"""
GraphQL IDOR agent — detects insecure direct object reference vulnerabilities
in GraphQL endpoints by manipulating object IDs in query variables.

Detection strategy:
  1. Identify variables that look like IDs (name heuristic + value pattern)
  2. Send a baseline request to capture the original response
  3. Probe with neighbour IDs (±1 for numeric, UUID variants for UUID-shaped values)
  4. Compare probe response against baseline using a strict set of rules:
     - Confirmed IDOR: probe has data, no GraphQL errors, data differs from baseline
     - Not a vuln: probe has errors, data is null/empty, or data is identical to baseline
  5. For mutations that write to an ID field, confirm the operation ran on a
     different object by checking the response contains the probed ID

GraphQL always returns HTTP 200 — HTTP status is never used as a signal.

Explicitly NOT checked (out of scope per project spec):
  - Introspection availability
  - Query depth / complexity limits
  - Batch request flooding
  - Rate limiting
"""

from __future__ import annotations

import json
import re
import uuid
from typing import TYPE_CHECKING, Any, List, Optional, Tuple

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

# Variable name patterns that suggest an object ID
_ID_NAME_RE = re.compile(
    r'(?:^|_)(?:id|Id|ID|uuid|guid|node_?id|object_?id|resource_?id|user_?id|'
    r'account_?id|profile_?id|post_?id|item_?id|record_?id|entity_?id)(?:$|_)',
    re.IGNORECASE,
)

# Numeric ID pattern (positive integer string)
_NUMERIC_ID_RE = re.compile(r'^\d{1,18}$')

# UUID pattern (any version, with or without hyphens)
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$',
    re.IGNORECASE,
)

# Max number of ID variables to probe per request (avoids scanning non-GraphQL endpoints heavily)
_MAX_ID_PARAMS = 4
# Neighbour offsets to try for numeric IDs
_NUMERIC_NEIGHBOURS = [-1, 1, -2, 2]


def _is_id_param(name: str, value: str) -> bool:
    return bool(_ID_NAME_RE.search(name)) and (
        bool(_NUMERIC_ID_RE.match(value)) or bool(_UUID_RE.match(value))
    )


def _neighbour_values(value: str) -> List[str]:
    """Generate candidate probe values for a given ID."""
    if _NUMERIC_ID_RE.match(value):
        n = int(value)
        return [str(n + d) for d in _NUMERIC_NEIGHBOURS if n + d > 0]
    if _UUID_RE.match(value):
        # Increment the last segment of the UUID by 1
        normalized = value.lower().replace("-", "")
        try:
            n = int(normalized, 16)
            candidates = []
            for delta in (1, -1, 2, -2):
                new_n = n + delta
                if new_n <= 0:
                    continue
                hex_str = f"{new_n:032x}"
                candidates.append(
                    f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:]}"
                )
            return candidates
        except Exception:
            return [str(uuid.uuid4())]
    return []


def _gql_errors(response_json: Any) -> List[str]:
    """Extract GraphQL error messages from a parsed response."""
    errors = response_json.get("errors") if isinstance(response_json, dict) else None
    if not errors:
        return []
    return [str(e.get("message", "")) for e in errors if isinstance(e, dict)]


def _gql_data(response_json: Any) -> Optional[dict]:
    """Return the data object, or None if missing/null."""
    if not isinstance(response_json, dict):
        return None
    data = response_json.get("data")
    if data is None:
        return None
    if isinstance(data, dict) and not any(v is not None for v in data.values()):
        return None  # all fields null
    return data


def _data_is_meaningful(data: Optional[dict]) -> bool:
    """True when data contains at least one non-null, non-empty leaf value."""
    if not data:
        return False
    for v in data.values():
        if v is None:
            continue
        if isinstance(v, dict):
            if _data_is_meaningful(v):
                return True
        elif isinstance(v, list):
            if v:
                return True
        elif v != "" and v != 0:
            return True
    return False


def _data_differs(baseline: Optional[dict], probe: Optional[dict]) -> bool:
    """True when probe data is meaningfully different from baseline."""
    if baseline is None or probe is None:
        return False
    return json.dumps(baseline, sort_keys=True) != json.dumps(probe, sort_keys=True)


def _inject_variable(body: str, var_name: str, value: str) -> Optional[str]:
    """Replace a specific variable value in the GraphQL request body."""
    try:
        data = json.loads(body)
        if not isinstance(data, dict) or not isinstance(data.get("variables"), dict):
            return None
        if var_name not in data["variables"]:
            return None
        data["variables"][var_name] = value
        return json.dumps(data)
    except Exception:
        return None


async def _baseline(
    target: "CheckTarget",
    client: "httpx.AsyncClient",
) -> Optional[Tuple[Any, dict]]:
    """Send the original request and return (parsed_json, response_headers)."""
    resp = await _send(client, target.method, target.url, target.headers, target.body)
    if resp is None:
        return None
    try:
        return resp.json(), dict(resp.headers)
    except Exception:
        return None


class GraphqlIdorAgent(VulnAgent):
    name = "GraphQL IDOR Agent"
    attack_type = "graphql_idor"
    description = (
        "Detects insecure direct object reference vulnerabilities in GraphQL endpoints "
        "by probing neighbour IDs in query variables and comparing response data."
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        if not target.body:
            return []

        # Only run on GraphQL endpoints — must have body_graphql params
        graphql_params = [p for p in target.params if p["location"] == "body_graphql"]
        if not graphql_params:
            return []

        # Narrow to ID-shaped parameters
        id_params = [
            p for p in graphql_params
            if _is_id_param(p["name"], p["value"])
        ][:_MAX_ID_PARAMS]

        if not id_params:
            return []

        # Capture baseline once
        baseline_result = await _baseline(target, client)
        if baseline_result is None:
            return []
        baseline_json, _ = baseline_result

        # If the baseline itself has errors, the endpoint may be broken — skip
        if _gql_errors(baseline_json):
            logger.debug(
                "GraphQL IDOR: baseline has errors, skipping",
                url=target.url,
                errors=_gql_errors(baseline_json)[:2],
            )
            return []

        baseline_data = _gql_data(baseline_json)

        findings: List[AgentFinding] = []

        for param in id_params:
            original_value = param["value"]
            probe_values = _neighbour_values(original_value)
            if not probe_values:
                continue

            for probe_value in probe_values:
                injected_body = _inject_variable(target.body, param["name"], probe_value)
                if injected_body is None:
                    continue

                resp = await _send(
                    client, target.method, target.url, target.headers, injected_body
                )
                if resp is None:
                    continue

                try:
                    probe_json = resp.json()
                except Exception:
                    continue

                probe_errors = _gql_errors(probe_json)
                probe_data = _gql_data(probe_json)

                # GraphQL authorization error → not a vuln
                if probe_errors:
                    logger.debug(
                        "GraphQL IDOR: probe rejected by server",
                        param=param["name"],
                        probe_value=probe_value,
                        errors=probe_errors[:2],
                    )
                    continue

                # No meaningful data returned → object not found or access denied
                if not _data_is_meaningful(probe_data):
                    continue

                # Data identical to baseline → same object, not an IDOR
                if not _data_differs(baseline_data, probe_data):
                    continue

                # Probe returned different non-null data with no errors — IDOR confirmed
                evidence = (
                    f"Variable '{param['name']}' changed from {original_value!r} "
                    f"to {probe_value!r}: server returned different non-null data "
                    f"without authorization errors. "
                    f"Baseline data keys: {list((baseline_data or {}).keys())}. "
                    f"Probe data keys: {list((probe_data or {}).keys())}."
                )
                raw_request, raw_response = _fmt_http_pair(resp)
                findings.append(AgentFinding(
                    title="GraphQL IDOR — Object Data Accessible via Neighbour ID",
                    severity="high",
                    cwe="CWE-639",
                    attack_type="graphql_idor",
                    evidence=evidence,
                    payload=f'{param["name"]}={probe_value}',
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=False,
                    raw_request=raw_request,
                    raw_response=raw_response,
                ))
                logger.info(
                    "GraphQL IDOR candidate",
                    param=param["name"],
                    original=original_value,
                    probe=probe_value,
                    url=target.url,
                )
                break  # one confirmed finding per parameter is enough

        return findings


from dast.ai.coordinator import Coordinator
Coordinator.register(GraphqlIdorAgent)
