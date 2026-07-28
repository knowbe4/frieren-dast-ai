"""
GraphQL variable extraction and type-aware payload fuzzing engine.

Given a captured GraphQL request (JSON body shaped like
{"query": "...", "variables": {...}}), extracts each top-level variable,
cross-products it against a payload list (one variable perturbed per request,
others held at their original values — the same single-injection-point model
already used by Repeater/Intruder in this project), and records a per-attempt
hit signal: 5xx status, a GraphQL `errors` array appearing where the baseline
had none, or a large response-length delta from the baseline.

v1 scope: variables are extracted from the JSON `variables` object only —
inline query-literal argument extraction (regex-scanning the query string
itself) is NOT implemented. The Java reference tool's version of that was
regex-based and brittle; if needed later, add it as a separate extraction
path rather than complicating this one.

No vulnerability classification happens here — dast/plugins/graphql_analyzer.py
already owns pattern-based detection (SQL errors, stack traces, debug-info
leakage) on every proxied GraphQL response. This module only measures the
raw signal for a targeted, user-triggered fuzzing run.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Length-delta threshold (fraction of baseline length) beyond which a response
# is considered meaningfully different from the baseline.
_LENGTH_DELTA_THRESHOLD = 0.5

# Generated programmatically rather than stored as a literal payload string.
OVERSIZED_STRING_LENGTH = 10000


@dataclass
class ExtractedVariable:
    name: str
    original_value: Any
    inferred_type: str  # "string" | "int" | "float" | "bool" | "list" | "object" | "null"


def _infer_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "object"
    return "string"


def extract_variables(body: str) -> List[ExtractedVariable]:
    """
    Parse a captured GraphQL request body's `variables` JSON object.

    Raises ValueError if the body has no parseable `variables` object.
    """
    try:
        data = json.loads(body)
    except Exception as exc:
        raise ValueError(f"request body is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("request body is not a JSON object")

    variables = data.get("variables")
    if not isinstance(variables, dict) or not variables:
        raise ValueError("no non-empty 'variables' object found in request body")

    return [
        ExtractedVariable(name=name, original_value=value, inferred_type=_infer_type(value))
        for name, value in variables.items()
    ]


def coerce_payload(payload: str, inferred_type: str) -> Any:
    """
    Convert a payload string into a value appropriate for injecting into a
    variable of the given inferred type — favouring type-confusion tests over
    faithful type preservation, since type confusion is often the point.
    """
    if payload == "null":
        return None
    if payload in ("{}", "[]"):
        try:
            return json.loads(payload)
        except Exception:
            return payload

    if inferred_type == "bool":
        # Inject int/string forms instead of a real bool, to test confusion.
        if payload in ("0", "1"):
            return int(payload)
        return payload

    if inferred_type in ("int", "float"):
        # Try numeric coercion first (covers edge_case_numbers); fall back to
        # the raw string so non-numeric payloads (sqli/nosql/cmdi style) still
        # get sent as-is, deliberately mismatched against the declared type.
        try:
            if "." in payload or "e" in payload.lower():
                return float(payload)
            return int(payload)
        except ValueError:
            return payload

    if inferred_type == "list":
        return [payload]

    if inferred_type == "object":
        try:
            parsed = json.loads(payload)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        return payload

    return payload


@dataclass
class FuzzAttempt:
    variable: str
    payload: str
    coerced_value: Any


def build_fuzz_matrix(
    variables: List[ExtractedVariable],
    payloads: List[str],
) -> List[FuzzAttempt]:
    """Cross-product: for each variable, for each payload, one attempt —
    other variables are left untouched by the caller when injecting."""
    attempts: List[FuzzAttempt] = []
    for var in variables:
        for payload in payloads:
            attempts.append(FuzzAttempt(
                variable=var.name,
                payload=payload,
                coerced_value=coerce_payload(payload, var.inferred_type),
            ))
    return attempts


def _inject(body: dict, variable: str, value: Any) -> dict:
    injected = dict(body)
    injected_vars = dict(injected.get("variables") or {})
    injected_vars[variable] = value
    injected["variables"] = injected_vars
    return injected


def _has_graphql_errors(resp_text: str) -> bool:
    try:
        data = json.loads(resp_text)
    except Exception:
        return False
    return isinstance(data, dict) and bool(data.get("errors"))


async def run_fuzz_job(
    job: dict,
    method: str,
    url: str,
    headers: Dict[str, str],
    body_template: str,
    attempts: List[FuzzAttempt],
    baseline_length: int,
    baseline_had_errors: bool,
) -> None:
    """
    Run each fuzz attempt against the target, mutating `job` in place —
    mirrors the job-dict contract used by dast/proxy/api/intruder_routes.py
    (`job["cancel"]`, `job["progress"]`, `job["results"]`, `job["status"]`).
    """
    try:
        base_body = json.loads(body_template)
    except Exception as exc:
        job["status"] = "error"
        job["error"] = f"body_template is not valid JSON: {exc}"
        return

    job["status"] = "running"
    job["progress"] = {"done": 0, "total": len(attempts)}

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(30.0),
        verify=False,
    ) as client:
        for i, attempt in enumerate(attempts):
            if job.get("cancel"):
                job["status"] = "stopped"
                return

            injected_body = _inject(base_body, attempt.variable, attempt.coerced_value)
            body_bytes = json.dumps(injected_body).encode("utf-8")

            t0 = time.monotonic()
            status_code = 0
            length_bytes = 0
            errors_present = False
            hit = False

            try:
                resp = await client.request(method, url, headers=headers, content=body_bytes)
                duration_ms = int((time.monotonic() - t0) * 1000)
                status_code = resp.status_code
                length_bytes = len(resp.content)
                resp_text = resp.text[:8000]

                errors_present = _has_graphql_errors(resp_text)

                if status_code >= 500:
                    hit = True
                elif errors_present and not baseline_had_errors:
                    hit = True
                elif baseline_length > 0 and abs(length_bytes - baseline_length) > baseline_length * _LENGTH_DELTA_THRESHOLD:
                    hit = True
            except Exception as exc:
                duration_ms = int((time.monotonic() - t0) * 1000)
                logger.debug("GraphQL fuzz attempt failed", variable=attempt.variable, error=str(exc))

            job["results"].append({
                "n": i + 1,
                "variable": attempt.variable,
                "payload": attempt.payload,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "length_bytes": length_bytes,
                "errors_present": errors_present,
                "hit": hit,
            })
            job["progress"]["done"] = i + 1

    job["status"] = "done"
    logger.info("GraphQL fuzz job done", attempts=len(attempts), url=url)
