"""
Attack-chain executor.

Runs a :class:`Chain` step by step, threading variables and cookies from one
response into the next request. Every step is scope-gated and payload-safety
gated exactly like ``tools.http_tools.send_request`` — the chain is not a way
around Frieren's safety model, it composes it.

The sender is injected (``sender`` argument) so the engine is fully testable
offline; the default sender routes through the running proxy with httpx.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

from dast.chains.models import (
    Assertion,
    Chain,
    ChainResult,
    ChainStep,
    Extractor,
    StepResult,
)
from dast.hackerone import payload_safety
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# sender(method, url, headers, body) -> (status, response_headers, response_text)
Sender = Callable[[str, str, Dict[str, str], str], Awaitable[Tuple[int, Dict[str, str], str]]]

_MAX_BODY_CAPTURE = 16000
_TEMPLATE = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")
_SENSITIVE = re.compile(r"(jwt|token|cookie|signature|policy|secret|key|bearer|auth)", re.I)


def _redact(var: str, value: str) -> str:
    """Redact a bound value for reporting: never emit a full token/cookie."""
    text = value if isinstance(value, str) else json.dumps(value)
    if _SENSITIVE.search(var) or len(text) > 40:
        preview = text[:8]
        return f"{var}=<{len(text)} chars, starts {preview!r}>"
    return f"{var}={text}"


def _b64json(raw: str) -> object:
    """base64url-decode (padding-tolerant) and JSON-parse."""
    s = raw.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return json.loads(base64.b64decode(s))


def _json_path(obj: object, expr: str) -> List[object]:
    """Resolve a dotted path with ``key``, ``key[0]`` and ``key[*]`` support.

    Returns a flat list of every match (empty when nothing matches).
    """
    current: List[object] = [obj]
    if not expr:
        return current
    for token in expr.split("."):
        key, indices = token, []
        # Peel trailing [..] selectors off the token.
        for m in re.finditer(r"\[([0-9*]+)\]", token):
            indices.append(m.group(1))
        key = re.sub(r"\[[0-9*]+\]", "", token)
        nxt: List[object] = []
        for node in current:
            value = node
            if key:
                if isinstance(node, dict) and key in node:
                    value = node[key]
                else:
                    continue
            for sel in indices:
                if sel == "*":
                    if isinstance(value, list):
                        nxt.extend(value)
                    value = _CONSUMED
                    break
                else:
                    idx = int(sel)
                    if isinstance(value, list) and -len(value) <= idx < len(value):
                        value = value[idx]
                    else:
                        value = _CONSUMED
                        break
            if value is not _CONSUMED:
                nxt.append(value)
        current = nxt
    return current


_CONSUMED = object()


def _parse_set_cookies(headers: Dict[str, str]) -> Dict[str, str]:
    """Harvest name=value pairs from a response's Set-Cookie header(s).

    httpx joins repeated Set-Cookie headers with commas; split conservatively on
    the ``name=`` boundary that follows a ``; `` so cookie values (which may
    contain commas) survive.
    """
    raw = ""
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            raw = v
            break
    if not raw:
        return {}
    jar: Dict[str, str] = {}
    # Split into individual cookies: a new cookie starts after ", <token>=".
    parts = re.split(r",\s*(?=[A-Za-z0-9!#$%&'*+\-.^_`|~]+=)", raw)
    for part in parts:
        first = part.split(";", 1)[0].strip()
        if "=" in first:
            name, _, value = first.partition("=")
            jar[name.strip()] = value.strip()
    return jar


def _render(text: str, variables: Dict[str, str]) -> str:
    return _TEMPLATE.sub(lambda m: str(variables.get(m.group(1), m.group(0))), text)


def _resolve_source(source: str, body: str, headers: Dict[str, str],
                    variables: Dict[str, str]) -> str:
    if source == "body":
        return body
    if source.startswith("header:"):
        want = source.split(":", 1)[1].strip().lower()
        for k, v in headers.items():
            if k.lower() == want:
                return v
        return ""
    if source.startswith("var:"):
        return variables.get(source.split(":", 1)[1].strip(), "")
    return body


def _apply_extractor(ext: Extractor, body: str, headers: Dict[str, str],
                     variables: Dict[str, str], jar: Dict[str, str]) -> Optional[str]:
    """Run one extractor; return the bound value (also written into ``variables``)."""
    try:
        if ext.kind == "set_cookie":
            value = jar.get(ext.expr, "")
        else:
            source_text = _resolve_source(ext.source, body, headers, variables)
            if ext.kind == "regex":
                m = re.search(ext.expr, source_text)
                value = (m.group(1) if m and m.groups() else (m.group(0) if m else "")) or ""
            elif ext.kind == "json":
                matches = _json_path(json.loads(source_text), ext.expr)
                value = matches[0] if matches else ""
                variables[f"{ext.var}__count"] = str(len(matches))
            elif ext.kind == "b64json":
                matches = _json_path(_b64json(source_text), ext.expr)
                value = matches[0] if matches else ""
            elif ext.kind == "jwt_claim":
                payload = source_text.split(".")[1] if source_text.count(".") >= 2 else source_text
                matches = _json_path(_b64json(payload), ext.expr)
                value = matches[0] if matches else ""
            else:
                logger.warning("unknown extractor kind", kind=ext.kind, var=ext.var)
                return None
        if not isinstance(value, str):
            value = json.dumps(value)
        variables[ext.var] = value
        return value
    except (ValueError, KeyError, IndexError, json.JSONDecodeError, binascii.Error) as exc:
        logger.debug("extractor failed", kind=ext.kind, var=ext.var, error=str(exc))
        return None


def _check_assertion(a: Assertion, status: Optional[int], body: str,
                     headers: Dict[str, str], variables: Dict[str, str]) -> Tuple[bool, str]:
    """Evaluate one assertion; return (passed, human-readable result)."""
    label = a.kind
    try:
        if a.kind == "status_eq":
            ok = status == int(a.value)
            return ok, f"status_eq {a.value}: got {status}"
        if a.kind == "status_in":
            wanted = [int(v) for v in a.values]
            return status in wanted, f"status_in {wanted}: got {status}"
        if a.kind == "header_contains":
            got = next((v for k, v in headers.items() if k.lower() == a.name.lower()), "")
            return a.needle.lower() in got.lower(), f"header {a.name!r} contains {a.needle!r}: {a.needle.lower() in got.lower()}"
        if a.kind == "body_contains":
            return a.needle in body, f"body contains {a.needle!r}: {a.needle in body}"
        if a.kind == "body_not_contains":
            return a.needle not in body, f"body NOT contains {a.needle!r}: {a.needle not in body}"
        if a.kind == "var_present":
            v = variables.get(a.var, "")
            return bool(v), f"var {a.var!r} present: {bool(v)}"
        if a.kind == "var_contains":
            v = variables.get(a.var, "")
            return a.needle in v, f"var {a.var!r} contains {a.needle!r}: {a.needle in v}"
        if a.kind == "var_equals":
            v = variables.get(a.var, "")
            return v == str(a.value), f"var {a.var!r} equals {a.value!r}: {v == str(a.value)}"
        return False, f"unknown assertion kind: {a.kind}"
    except (ValueError, TypeError) as exc:
        return False, f"{label} error: {exc}"


class ChainEngine:
    """Executes a :class:`Chain`, scope- and safety-gated, sender-injected."""

    def __init__(
        self,
        sender: Sender,
        is_in_scope: Callable[[str], bool],
        initial_cookies: Optional[Dict[str, str]] = None,
    ):
        self._sender = sender
        self._is_in_scope = is_in_scope
        self._jar: Dict[str, str] = dict(initial_cookies or {})
        self._vars: Dict[str, str] = {}

    async def run(self, chain: Chain) -> ChainResult:
        result = ChainResult(name=chain.name, status="confirmed", vuln_type=chain.vuln_type)
        for step in chain.steps:
            step_result = await self._run_step(step)
            result.steps.append(step_result)
            if step_result.note in ("out_of_scope", "destructive_refused"):
                result.status = "blocked"
                break
            if step_result.status is None:
                result.status = "error"
                break
            if _looks_like_auth_wall(step_result.status):
                result.status = "needs_auth"
                break
            if not step_result.passed:
                result.status = "refuted"
                break
        result.evidence = _build_evidence(chain, result)
        logger.info("chain executed", name=chain.name, status=result.status,
                    steps=len(result.steps))
        return result

    async def _run_step(self, step: ChainStep) -> StepResult:
        url = _render(step.url, self._vars)
        sr = StepResult(name=step.name, method=step.method, url=url)

        # Scope gate BEFORE anything is sent.
        if not self._is_in_scope(url):
            sr.note = "out_of_scope"
            sr.assertion_results.append(f"refused: {url} is out of scope")
            return sr

        headers = {k: _render(v, self._vars) for k, v in step.headers.items()}
        body = _render(step.body, self._vars)

        # Payload-safety gate: refuse destructive URL/body.
        for where, text in (("url", url), ("body", body)):
            verdict = payload_safety.classify(text)
            if verdict.is_destructive:
                sr.note = "destructive_refused"
                sr.assertion_results.append(f"refused: destructive payload in {where} ({verdict.reason})")
                return sr

        # Cookie jar → Cookie header (filtered per step).
        cookie_header = self._cookie_header(step)
        if cookie_header:
            headers.setdefault("Cookie", cookie_header)
        # Safety: cap content pulls so a media/content check never mirrors an asset.
        if step.max_range_bytes:
            headers.setdefault("Range", f"bytes=0-{max(0, step.max_range_bytes - 1)}")

        try:
            status, resp_headers, resp_body = await self._sender(step.method, url, headers, body)
        except Exception as exc:  # sender failure is not fatal to reporting
            logger.warning("chain step send failed", step=step.name, url=url[:120], error=str(exc))
            sr.note = f"send_error: {str(exc)[:120]}"
            return sr

        resp_body = resp_body[:_MAX_BODY_CAPTURE]
        sr.status = status

        # Always harvest Set-Cookie so credentials flow to later steps.
        harvested = _parse_set_cookies(resp_headers)
        if harvested:
            self._jar.update(harvested)

        for ext in step.extract:
            value = _apply_extractor(ext, resp_body, resp_headers, self._vars, harvested or self._jar)
            if value is not None:
                sr.extracted.append(_redact(ext.var, value))

        passed = True
        for a in step.assertions:
            ok, detail = _check_assertion(a, status, resp_body, resp_headers, self._vars)
            sr.assertion_results.append(detail)
            passed = passed and ok
        # A step with no assertions is a setup step: it passes if it was sent.
        sr.passed = passed
        return sr

    def _cookie_header(self, step: ChainStep) -> str:
        if step.send_cookies is None:
            items = self._jar.items()
        elif not step.send_cookies:
            return ""  # control step: send nothing
        else:
            wanted = set(step.send_cookies)
            items = [(k, v) for k, v in self._jar.items() if k in wanted]
        return "; ".join(f"{k}={v}" for k, v in items)


def _looks_like_auth_wall(status: int) -> bool:
    return status in (401, 407)


def _build_evidence(chain: Chain, result: ChainResult) -> str:
    lines = [f"Chain '{chain.name}' -> {result.status.upper()}"]
    if chain.description:
        lines.append(chain.description)
    lines.append("")
    for i, s in enumerate(result.steps, 1):
        mark = "PASS" if s.passed else ("--" if s.note else "FAIL")
        lines.append(f"{i}. [{mark}] {s.method} {s.url}  -> {s.status}")
        for a in s.assertion_results:
            lines.append(f"      assert: {a}")
        for e in s.extracted:
            lines.append(f"      bound:  {e}")
        if s.note:
            lines.append(f"      note:   {s.note}")
    return "\n".join(lines)
