"""Shared probe plumbing for the VulnAgents — the single home for the injection
dispatch, the time oracle, and the OOB confirmation.

Before this module, every agent carried its own copy of the param-location
dispatch (query/body/body_graphql/multipart/path/header/cookie) and its own copy
of the sqlmap-style time differential. The copies had already drifted (cmdi lost
header/cookie/multipart injection entirely; the XXE agent's OOB phase died on a
nonexistent API) — drift here is how real bugs are born, so new agents MUST use
these helpers instead of re-implementing.

Transport injection: ``send_probe`` takes the transport callable as an argument
(``send=``), defaulting to ``active_checks._send``. Agents pass their own
module-level ``_send`` so per-module test patches keep working unchanged.

Deliberately NOT migrated (diverging semantics, documented):
- ``business_logic_agent._send_probe`` — own body/GraphQL injectors + explicit
  source tagging ("scan" vs "agent");
- ``llm_injection_agent._send_probe`` — adds a ``body_raw`` JSON prompt-key
  location;
- the per-agent response-similarity helpers (the ratio bands are intentional
  per-agent decisions, not drift);
- JWT tooling (consolidates with the JWT VulnAgent, roadmap round 3-E).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Awaitable, Callable, Optional, Tuple

from dast.scanners.active_checks import (
    _inject_body,
    _inject_cookie,
    _inject_header,
    _inject_multipart,
    _inject_path,
    _inject_query,
    response_elapsed_ms,
    scaled_delay_variant,
    _send as _default_send,
)

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

# The transport callable: (client, method, url, headers, body, **kwargs) -> resp.
Send = Callable[..., Awaitable[Optional["httpx.Response"]]]

# Which param locations each caller's dispatch honors. ``None`` = the full
# superset (query, body, body_graphql, multipart_*, path, header, cookie).
LOCATIONS_ALL = None
# The historical surface of xss/discovery/ssrf/file_read — no path injection.
LOCATIONS_NO_PATH = frozenset({"query", "body", "body_graphql", "multipart",
                               "header", "cookie"})
# cmdi's historical surface — body-first plus path, with query as the fallback
# for every other location (header/cookie/multipart fall through to query).
LOCATIONS_CMDI = frozenset({"query", "body", "body_graphql", "path"})


def _location_family(location: str) -> str:
    """Collapse the multipart_* variants (multipart_filename/multipart_body/
    multipart_ct) into the single "multipart" family."""
    return "multipart" if location.startswith("multipart_") else location


def build_probe_request(
    target: "CheckTarget",
    param: dict,
    payload: str,
    *,
    locations: Optional[frozenset] = None,
    query_fallback: bool = False,
) -> Optional[Tuple[str, dict, object]]:
    """Build the (url, headers, body) for injecting ``payload`` into ``param`` at
    its recorded location — the shared superset dispatch (formerly re-implemented
    per agent). Returns None when the location is not injectable (or not in
    ``locations``), unless ``query_fallback`` routes unknown locations to a query
    injection instead (cmdi's documented behavior)."""
    loc = param.get("location", "query")
    family = _location_family(loc)
    allowed = locations if locations is not None else {
        "query", "body", "body_graphql", "multipart", "path", "header", "cookie"}

    if family in allowed:
        if family == "query":
            url = _inject_query(target.url, param["name"], payload)
            return url, target.headers, target.body
        if family in ("body", "body_graphql"):
            body = _inject_body(
                target.body or "", param["name"], payload,
                target.headers.get("content-type", ""),
                location=loc,
            )
            return target.url, target.headers, body
        if family == "multipart":
            raw = _inject_multipart(target.raw_body or b"", param["name"], payload)
            return target.url, target.headers, raw
        if family == "path":
            url = _inject_path(target.url, param.get("path_index", 0), payload)
            return url, target.headers, target.body
        if family == "header":
            headers = _inject_header(target.headers, param["name"], payload)
            return target.url, headers, target.body
        if family == "cookie":
            headers = _inject_cookie(target.headers, param["name"], payload)
            return target.url, headers, target.body

    if query_fallback:
        url = _inject_query(target.url, param["name"], payload)
        return url, target.headers, target.body
    return None


async def send_probe(
    target: "CheckTarget",
    client: "httpx.AsyncClient",
    param: dict,
    payload: str,
    *,
    timeout: Optional[float] = None,
    send: Optional[Send] = None,
    locations: Optional[frozenset] = None,
    query_fallback: bool = False,
    forward_payload: bool = False,
) -> Optional["httpx.Response"]:
    """Inject ``payload`` into ``param`` at its recorded location and send it
    through ``send`` (defaulting to the shared ``active_checks._send``; agents
    pass their module-level ``_send`` so per-module test patches keep working).

    Transport-kwarg forwarding mirrors each migrating agent's historical behavior:
    ``timeout`` is forwarded when given (sqli/cmdi time probes), ``payload`` only
    when ``forward_payload=True`` (cmdi's x-dast-payload history tagging)."""
    transport = send if send is not None else _default_send
    request = build_probe_request(target, param, payload,
                                  locations=locations, query_fallback=query_fallback)
    if request is None:
        return None
    url, headers, body = request
    kwargs = {}
    if timeout is not None:
        kwargs["timeout"] = timeout
    if forward_payload:
        kwargs["payload"] = payload
    return await transport(client, target.method, url, headers, body, **kwargs)


async def timed_probe_ms(
    send_probe_fn: Callable[..., Awaitable[Optional["httpx.Response"]]],
    target: "CheckTarget",
    client: "httpx.AsyncClient",
    param: dict,
    payload: str,
    timeout_s: float,
) -> Tuple[float, Optional["httpx.Response"]]:
    """One timed send: (elapsed_ms, response). The shared core of both agents'
    ``_timed_send`` — elapsed is the server round-trip measured by httpx inside
    the probe semaphore, not wall-clock."""
    resp = await send_probe_fn(target, client, param, payload, timeout=timeout_s)
    return (response_elapsed_ms(resp) if resp is not None else 0.0), resp


async def time_candidate_pair(
    send_probe_fn: Callable[..., Awaitable[Optional["httpx.Response"]]],
    target: "CheckTarget",
    client: "httpx.AsyncClient",
    param: dict,
    payload: str,
    control_value: str,
    timeout_s: float,
) -> Tuple[float, float, Optional["httpx.Response"]]:
    """Candidate measurement (MUST be called while holding
    ``serialize_time_probe()``): the SLEEP payload vs its zero-delay control sent
    immediately before it — sqlmap's true/false differential. Identical
    query-parsing path, same ambient-load epoch, so the delta isolates the
    server-side sleep. Returns (control_ms, probe_ms, probe_response)."""
    control_ms, _ = await timed_probe_ms(send_probe_fn, target, client, param,
                                         control_value, timeout_s)
    probe_ms, resp = await timed_probe_ms(send_probe_fn, target, client, param,
                                          payload, timeout_s)
    return control_ms, probe_ms, resp


async def time_confirm_scaling(
    send_probe_fn: Callable[..., Awaitable[Optional["httpx.Response"]]],
    target: "CheckTarget",
    client: "httpx.AsyncClient",
    param: dict,
    payload: str,
    control_value: str,
    primary_delta_ms: float,
    *,
    confirm_delay_s: int,
    confirm_floor_ms: float,
    scaling_margin_ms: float,
    timeout_s: float,
) -> Tuple[bool, float, Optional["httpx.Response"]]:
    """Delay-scaling confirmation (sqlmap's method; MUST be called while holding
    ``serialize_time_probe()`` so it cannot starve re-acquiring the contended
    lock): re-probe with a distinct shorter sleep and require (a) the shorter
    sleep to clearly delay the response (floor) and (b) the primary (longer)
    sleep to have added measurably MORE than the shorter one (margin) — ambient
    spikes are uncorrelated with the requested delay and cannot satisfy the
    scaling relation. Returns (confirmed, confirm_delta_ms, resp). The caller
    owns the reproduce-fallback for payloads with no rewritable sleep construct
    (``scaled_delay_variant`` returning None => (False, 0.0, None) here)."""
    confirm_payload = scaled_delay_variant(payload, confirm_delay_s)
    if confirm_payload is None:
        return False, 0.0, None
    control_ms, _ = await timed_probe_ms(send_probe_fn, target, client, param,
                                         control_value, timeout_s)
    confirm_ms, resp = await timed_probe_ms(send_probe_fn, target, client, param,
                                            confirm_payload, timeout_s)
    confirm_delta_ms = confirm_ms - control_ms
    confirmed = (
        resp is not None
        and confirm_delta_ms >= confirm_floor_ms     # shorter sleep clearly delayed
        and confirm_ms >= confirm_floor_ms
        and (primary_delta_ms - confirm_delta_ms) >= scaling_margin_ms  # longer added more
    )
    return confirmed, confirm_delta_ms, resp


async def oob_confirm(
    collaborator: "CollaboratorService",
    token: str,
    settle_seconds: float = 1.5,
) -> bool:
    """Settle, then token-scoped hit check. The one OOB confirmation path —
    agents issue a token per payload and check THAT token (never a global
    poll), so concurrent agents cannot attribute each other's callbacks."""
    if collaborator is None:
        return False
    await asyncio.sleep(settle_seconds)
    return bool(collaborator.was_hit(token))
