"""
GraphQL Analyzer plugin.

Passive analysis of every GraphQL request/response pair:
  - Introspection enabled (field suggestions, __schema leak)
  - Batching allowed (array of operations)
  - Debug info in errors (stack traces, internal paths)
  - Field suggestions in error messages (schema enumeration)
  - Verbose error objects (extensions.exception, locations, path)
  - Mutation without CSRF protection

Deterministic findings (introspection, batching, stack traces) are stored directly.
Ambiguous findings (CSRF, field suggestions) are routed through the LLM validator
for a second opinion before reaching the dashboard.

All analysis is passive — no additional requests are made.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, List, Optional

from dast.proxy.plugin_base import ProxyPlugin
from dast.proxy.plugin_manager import log_event
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

logger = get_logger(__name__)

# Patterns for field suggestion leakage in error messages
_SUGGESTION_RE = re.compile(
    r'did you mean["\s:]+(["\w, ]+)',
    re.IGNORECASE,
)
_STACK_TRACE_RE = re.compile(
    r"(at \w+.*:\d+:\d+|Error: .+\n\s+at |Traceback \(most recent call last\))",
    re.DOTALL,
)
_INTERNAL_PATH_RE = re.compile(
    r"(/home/|/usr/local/|/var/www/|C:\\|node_modules/|site-packages/|dist/server)",
    re.IGNORECASE,
)


def _is_graphql(entry: "ProxyEntry") -> bool:
    if entry.method != "POST":
        return False
    path = (entry.path or "").lower()
    if "/graphql" in path:
        return True
    if entry.request_body:
        try:
            body = entry.request_body[:4096].decode("utf-8", errors="replace")
            if '"query"' in body:
                data = json.loads(body)
                if isinstance(data, (dict, list)):
                    items = data if isinstance(data, list) else [data]
                    return any(
                        isinstance(item, dict) and isinstance(item.get("query"), str)
                        for item in items
                    )
        except Exception:
            pass
    return False


def _parse_body(raw: Optional[bytes]) -> Optional[object]:
    if not raw:
        return None
    try:
        return json.loads(raw[:65536].decode("utf-8", errors="replace"))
    except Exception:
        return None


def _response_text(entry: "ProxyEntry") -> str:
    if not entry.response_body:
        return ""
    return entry.response_body[:65536].decode("utf-8", errors="replace")


def _analyze(entry: "ProxyEntry") -> List[dict]:
    findings: List[dict] = []
    req_body = _parse_body(entry.request_body)
    resp_text = _response_text(entry)

    try:
        resp_data = json.loads(resp_text) if resp_text else {}
    except Exception:
        resp_data = {}

    # ── 1. Introspection enabled ─────────────────────────────────────────
    is_introspection = False
    if isinstance(req_body, dict):
        q = req_body.get("query", "")
        if isinstance(q, str) and "__schema" in q:
            is_introspection = True
    if is_introspection and entry.status_code == 200:
        schema = (resp_data.get("data") or {}).get("__schema") if isinstance(resp_data, dict) else None
        if schema:
            type_count = len(schema.get("types") or [])
            findings.append({
                "title": "GraphQL Introspection Enabled",
                "severity": "medium",
                "cwe": "CWE-200",
                "attack_type": "graphql",
                "evidence": (
                    f"Introspection query succeeded — full schema exposed "
                    f"({type_count} types). Attackers can enumerate all operations, "
                    f"fields, and argument types without any authentication."
                ),
                "confirmed": True,
                "validated_by": ["passive"],
            })

    # ── 2. Batching allowed ──────────────────────────────────────────────
    if isinstance(req_body, list) and len(req_body) > 1:
        all_gql = all(isinstance(op, dict) and "query" in op for op in req_body)
        if all_gql and entry.status_code == 200:
            findings.append({
                "title": "GraphQL Batching Enabled",
                "severity": "low",
                "cwe": "CWE-770",
                "attack_type": "graphql",
                "evidence": (
                    f"Server accepted a batch of {len(req_body)} GraphQL operations in a single "
                    f"request. Batching can be abused to bypass rate limiting and amplify "
                    f"brute-force attacks (e.g. credential stuffing via batched login mutations)."
                ),
                "confirmed": True,
                "validated_by": ["passive"],
            })

    # ── 3. Field suggestions / schema enumeration in errors ──────────────
    if isinstance(resp_data, dict):
        errors = resp_data.get("errors") or []
        if isinstance(errors, list):
            for err in errors:
                msg = (err.get("message") or "") if isinstance(err, dict) else ""
                m = _SUGGESTION_RE.search(msg)
                if m:
                    findings.append({
                        "title": "GraphQL Field Suggestion Leakage",
                        "severity": "low",
                        "cwe": "CWE-209",
                        "attack_type": "graphql",
                        "evidence": (
                            f"Error message reveals valid field names via suggestion: "
                            f"\"{msg[:200]}\". Attackers can enumerate the schema without "
                            f"introspection by deliberately sending typo'd field names."
                        ),
                        "confirmed": True,
                        "validated_by": ["passive"],
                    })
                    break

    # ── 4. Stack traces / internal paths in errors ───────────────────────
    if _STACK_TRACE_RE.search(resp_text) or _INTERNAL_PATH_RE.search(resp_text):
        snippet = resp_text[:300]
        findings.append({
            "title": "GraphQL Debug Information Disclosed",
            "severity": "medium",
            "cwe": "CWE-209",
            "attack_type": "graphql",
            "evidence": (
                f"GraphQL error response contains stack traces or internal file paths. "
                f"First 300 chars of response: {snippet!r}"
            ),
            "confirmed": True,
            "validated_by": ["passive"],
        })

    # ── 5. Verbose error extensions ──────────────────────────────────────
    if isinstance(resp_data, dict):
        errors = resp_data.get("errors") or []
        for err in (errors if isinstance(errors, list) else []):
            ext = (err.get("extensions") or {}) if isinstance(err, dict) else {}
            if isinstance(ext, dict) and "exception" in ext:
                findings.append({
                    "title": "GraphQL Verbose Error Extensions",
                    "severity": "low",
                    "cwe": "CWE-209",
                    "attack_type": "graphql",
                    "evidence": (
                        f"Error response includes extensions.exception with internal details: "
                        f"{json.dumps(ext.get('exception', {}))[:200]}"
                    ),
                    "confirmed": True,
                    "validated_by": ["passive"],
                })
                break

    # ── 6. Mutation without CSRF protection ─────────────────────────────
    if isinstance(req_body, dict):
        q = (req_body.get("query") or "").strip()
        is_mutation = q.startswith("mutation")
        csrf_headers = {k.lower() for k in entry.request_headers}
        has_csrf = bool(
            csrf_headers & {"x-csrf-token", "x-xsrf-token", "x-requested-with"}
        )
        origin = entry.request_headers.get("origin", "")
        has_content_type_json = "application/json" in entry.request_headers.get(
            "content-type", ""
        ).lower()
        if is_mutation and not has_csrf and entry.status_code == 200:
            # Simple requests with content-type: application/json are not CSRF-safe by default
            findings.append({
                "title": "GraphQL Mutation Without CSRF Token",
                "severity": "medium",
                "cwe": "CWE-352",
                "attack_type": "graphql",
                "evidence": (
                    f"GraphQL mutation submitted without a CSRF token header "
                    f"(no X-CSRF-Token / X-XSRF-Token / X-Requested-With). "
                    f"If the endpoint accepts cookies for auth, cross-origin mutation "
                    f"may be possible from an attacker-controlled page."
                ),
                "confirmed": False,
                "validated_by": ["passive"],
            })

    return findings


_SYSTEM_GQL_VALIDATE = """\
You are a senior web application security researcher with deep GraphQL expertise.
You have been given evidence of a potential GraphQL security issue detected passively
from an intercepted request/response pair.

Your job: decide whether this is a REAL, exploitable vulnerability given the evidence.
Be skeptical — only confirm when the evidence is clear and exploitable.

Respond ONLY with JSON:
{
  "confirmed": <true|false>,
  "confidence": <0.0-1.0>,
  "reasoning": "<one paragraph explaining why this is or is not a real finding>",
  "exploit_scenario": "<if confirmed, describe a realistic attack scenario in 1-2 sentences>"
}

Rules:
- GraphQL introspection: confirm only if __schema data is actually present in the response.
- Batching: confirm only if server returned an array of results for an array input.
- Field suggestions: confirm only if the error message clearly says "Did you mean" with a field name.
- Debug info: confirm only if stack trace lines or internal paths are visible in the response.
- Mutation CSRF: confirm only if no CSRF token AND no Origin header AND the endpoint uses cookies
  for authentication. If Bearer token is used, this is NOT a finding.
- Verbose errors: confirm only if extensions.exception contains internal details (not just a code).
"""


async def _llm_validate_finding(
    finding: dict,
    entry: "ProxyEntry",
    req_body_text: str,
    resp_text: str,
) -> dict:
    """Run the finding through an LLM to confirm or reject. Returns updated finding dict."""
    try:
        from dast.ai.bedrock_client import invoke_json, get_fast_model
        from dast.ai.payload_generator import _sanitize_for_prompt
    except ImportError:
        return finding

    safe_req = _sanitize_for_prompt(req_body_text[:1500], 1500) if req_body_text else "(none)"
    safe_resp = _sanitize_for_prompt(resp_text[:1500], 1500) if resp_text else "(none)"

    user_msg = (
        f"Finding title: {finding['title']}\n"
        f"Severity: {finding['severity']}\n"
        f"CWE: {finding.get('cwe', 'unknown')}\n"
        f"Evidence summary: {finding.get('evidence', '')[:500]}\n\n"
        f"Request body (first 1500 chars):\n{safe_req}\n\n"
        f"Response body (first 1500 chars):\n{safe_resp}\n\n"
        f"Request method: {entry.method}\n"
        f"URL: {entry.url}\n"
        f"Status: {entry.status_code}\n"
        f"Auth headers present: {bool({'authorization', 'cookie'} & {k.lower() for k in entry.request_headers})}\n"
    )

    try:
        result = await invoke_json(
            system=_SYSTEM_GQL_VALIDATE,
            user=user_msg,
            model_id=get_fast_model(),
            required_keys=["confirmed", "confidence", "reasoning"],
        )
        updated = dict(finding)
        updated["confirmed"] = bool(result.get("confirmed"))
        updated["confidence"] = float(result.get("confidence", 0.5))
        updated["reasoning"] = result.get("reasoning", "")
        if result.get("exploit_scenario"):
            updated["evidence"] = (
                finding.get("evidence", "") + "\n\nExploit scenario: " + result["exploit_scenario"]
            )
        if updated["confirmed"]:
            updated["validated_by"] = ["passive+ai"]
        else:
            updated["validated_by"] = ["passive"]
        return updated
    except Exception as exc:
        logger.warning("GraphQL LLM validation failed", error=str(exc), title=finding["title"])
        return finding


# Findings that require LLM validation (ambiguous — context-dependent)
_NEEDS_AI_TITLES = frozenset({
    "GraphQL Mutation Without CSRF Token",
    "GraphQL Field Suggestion Leakage",
    "GraphQL Verbose Error Extensions",
})


class GraphQLAnalyzerPlugin(ProxyPlugin):
    name = "GraphQL Analyzer"
    description = (
        "Passive analysis of GraphQL requests and responses: introspection, "
        "batching, field suggestion leakage, debug error disclosure, "
        "verbose error extensions, and mutation CSRF exposure. "
        "Ambiguous findings are validated by the LLM before reaching the dashboard."
    )
    version = "1.1.0"
    author = "dast-ai"
    enabled = True

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        if entry.source == "agent":
            return
        if not _is_graphql(entry):
            return

        req_body_text = (
            entry.request_body[:65536].decode("utf-8", errors="replace")
            if entry.request_body else ""
        )
        resp_text = _response_text(entry)

        findings = _analyze(entry)
        for f in findings:
            # Deduplicate: skip if this title already recorded for this host
            existing_titles = {ef.get("title") for ef in entry.findings}
            all_host_findings = {
                ef.get("title")
                for e in store.all_entries()
                if e.host == entry.host
                for ef in e.findings
                if ef.get("attack_type") == "graphql"
            }
            if f["title"] in existing_titles or f["title"] in all_host_findings:
                continue

            # Route ambiguous findings through LLM validation — but only in AI
            # mode. LLM validation is an AI feature and must stay OFF unless the
            # user has explicitly enabled AI mode. In manual mode (the default)
            # no AI config runs: the finding is surfaced as plain "Passive" with
            # its deterministic verdict, never routed through an LLM.
            if f["title"] in _NEEDS_AI_TITLES and getattr(store, "ai_mode", False):
                logger.debug(
                    "GraphQL: routing finding to LLM validator",
                    title=f["title"], url=entry.url,
                )
                f = await _llm_validate_finding(f, entry, req_body_text, resp_text)
                if not f.get("confirmed"):
                    logger.debug(
                        "GraphQL: LLM rejected finding",
                        title=f["title"], url=entry.url,
                        reasoning=f.get("reasoning", "")[:200],
                    )
                    continue
            elif f["title"] in _NEEDS_AI_TITLES:
                logger.debug(
                    "GraphQL: AI validation skipped — manual mode (AI disabled)",
                    title=f["title"], url=entry.url,
                )

            store.add_finding(entry.id, f, "vulnerable" if f.get("confirmed") else "safe")
            log_event(
                self.name, "finding",
                f"{f['severity'].upper()}: {f['title']}",
                url=entry.url,
                source="plugin",
            )
            logger.info(
                "GraphQL finding",
                title=f["title"],
                severity=f["severity"],
                confirmed=f.get("confirmed"),
                url=entry.url,
            )
