"""
JSON Schemas for structured LLM output.

These schemas back the forced tool-use path in ``bedrock_client.invoke_json``:
when a schema is passed, the model is forced to call a single tool whose
``input_schema`` is one of these, so the response is guaranteed to match the
shape by construction (no markdown-fence stripping, no ``json.loads`` failure).

Each schema mirrors the JSON contract already described in the corresponding
system prompt, so the migration is behaviour-preserving — the model produces the
same fields it did before, only now validated at the API layer.
"""

from __future__ import annotations

from typing import Any, Dict

# Coordinator planner — dast/ai/coordinator.py _SYSTEM_PLAN / _plan()
PLANNER_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "agents": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Attack-type identifiers of the agents worth running for this endpoint.",
        },
        "reason": {
            "type": "string",
            "description": "One concrete sentence describing what the endpoint does and why these agents follow from that understanding.",
        },
        "mine_params": {
            "type": "boolean",
            "description": (
                "True only if this endpoint likely accepts hidden/undocumented parameters "
                "worth brute-forcing (e.g. a debug/admin toggle, a filter or feature flag, "
                "an ID or callback the UI does not expose). Discovering them yields fresh "
                "attack surface. Set False for endpoints whose parameters are fully "
                "determined by the request already (static assets, pure auth relays, "
                "well-formed JSON APIs with an obvious complete schema)."
            ),
        },
    },
    "required": ["agents", "reason"],
}

# Coordinator baseline classifier — dast/ai/coordinator.py _SYSTEM_BASELINE / _baseline_check()
BASELINE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "status": {
            "type": "string",
            "enum": ["ok", "abort", "adapt"],
            "description": "ok = proceed with agents; abort = request fundamentally broken; adapt = fixable problem.",
        },
        "reason": {"type": "string", "description": "One sentence."},
        "structural_error": {
            "type": "string",
            "description": "Exact error message if the request body/schema is wrong, else empty.",
        },
        "auth_issue": {
            "type": "boolean",
            "description": "True if the response indicates auth failure (401/403/session expired).",
        },
        "endpoint_hint": {
            "type": "string",
            "description": "Correct endpoint path or operation name if the error reveals it, else empty.",
        },
    },
    "required": ["status", "reason", "structural_error", "auth_issue", "endpoint_hint"],
}

# Adaptive mutator — dast/ai/mutator.py _SYSTEM_MUTATOR / next_payload()
MUTATOR_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["mutate", "obfuscate", "stop"],
            "description": "mutate = new variant for the observed defence; obfuscate = encoding/casing/splitting; stop = strategies exhausted.",
        },
        "payload": {
            "type": "string",
            "description": "New payload string; empty when action=stop.",
        },
        "rationale": {
            "type": "string",
            "description": "One sentence: the exact defence substring observed and how this payload bypasses it.",
        },
    },
    "required": ["action", "payload", "rationale"],
}

# Red-team exploit validator — dast/ai/red_team.py _SYSTEM / validate()
RED_TEAM_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "confirmed": {
            "type": "boolean",
            "description": "True only with unambiguous evidence of real exploitation impact.",
        },
        "confidence": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
            "description": "Actual certainty of exploitability.",
        },
        "exploit_scenario": {
            "type": "string",
            "description": "One sentence: how an attacker would exploit this.",
        },
        "reasoning": {
            "type": "string",
            "description": "One sentence: why confirmed or rejected, referencing code if relevant.",
        },
    },
    "required": ["confirmed", "confidence", "exploit_scenario", "reasoning"],
}

# HackerOne report parser — dast/hackerone/parser.py _llm_enrich()
# Structured extraction from free-form report text. Extends the legacy field set
# with the full HTTP request (method/headers/body) so POST/PUT/JSON PoCs can be
# reproduced faithfully, not just GET proof URLs.
H1_PARSE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "vuln_type": {
            "type": "string",
            "description": "One of: xss, sqli, ssrf, idor, csrf, open_redirect, ssti, rce, lfi, xxe, auth_bypass, business_logic, privilege_escalation, info_disclosure, dns_takeover, other.",
        },
        "proof_url": {
            "type": "string",
            "description": "Vulnerable TARGET URL (the org's own host). NEVER an attacker/OOB listener (oastify/interactsh/ngrok) or a reference/doc URL (medium/owasp/github). Empty if unknown.",
        },
        "payload": {
            "type": "string",
            "description": "Exact attack string injected, URL-decoded. For SSRF: the OOB/callback URL used as input. Empty if none.",
        },
        "target_url": {
            "type": "string",
            "description": "Base URL of the vulnerable endpoint with no query params, else empty.",
        },
        "http_method": {
            "type": "string",
            "description": "HTTP method of the reproducing request (GET/POST/PUT/PATCH/DELETE). Default GET if the report shows no explicit method.",
        },
        "request_headers": {
            "type": "object",
            "additionalProperties": {"type": "string"},
            "description": "Request headers required to reproduce (e.g. Content-Type). Exclude Authorization/Cookie — those come from the active session. Empty object if none.",
        },
        "request_body": {
            "type": "string",
            "description": "Raw request body for POST/PUT/PATCH PoCs (JSON or form-encoded), verbatim from the report. Empty for GET or when absent.",
        },
        "summary": {
            "type": "string",
            "description": "One sentence: what is vulnerable, on which host, and the impact.",
        },
    },
    "required": ["vuln_type", "proof_url", "payload", "target_url", "summary"],
}

# HackerOne reproduction verdict — dast/hackerone/validator.py schema-forced verdict.
H1_VERDICT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "reproduced": {
            "type": "boolean",
            "description": "True only if the reproduced evidence shows the vulnerability is real and exploitable on the target.",
        },
        "confidence": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
            "description": "Actual certainty the report reproduces, from the observed evidence alone.",
        },
        "severity": {
            "type": "string",
            "enum": ["info", "low", "medium", "high", "critical"],
            "description": "Severity of the confirmed issue; 'info' if not reproduced.",
        },
        "exploit_scenario": {
            "type": "string",
            "description": "One sentence: how an attacker exploits this given the reproduced evidence.",
        },
        "reasoning": {
            "type": "string",
            "description": "One sentence: why the report was reproduced or rejected, referencing the observed response evidence.",
        },
    },
    "required": ["reproduced", "confidence", "severity", "exploit_scenario", "reasoning"],
}

# Agentic triage loop — dast/ai/triage_agent.py run_triage_agent()
# One turn of the loop. JSON Schema cannot express discriminated-union required
# fields (a "call_tool" step needs tool_name; an "ask_human" step needs question;
# a "finish" step needs verdict), so only the two always-present fields are
# required here and the per-action fields are validated in Python (a malformed
# step is re-prompted, never crashes the loop).
TRIAGE_AGENT_STEP_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "thought": {
            "type": "string",
            "description": "One or two sentences: what the last observation showed and what you will do next and why.",
        },
        "action": {
            "type": "string",
            "enum": ["call_tool", "ask_human", "finish"],
            "description": "call_tool = run a Frieren tool; ask_human = block for a typed operator answer; finish = end with a verdict.",
        },
        "tool_name": {
            "type": "string",
            "description": "Required when action=call_tool: the exact registered tool name (e.g. send_request, get_history, triage_report).",
        },
        "tool_args": {
            "type": "object",
            "description": "Required when action=call_tool: the tool's arguments, matching that tool's input schema.",
            "additionalProperties": True,
        },
        "question": {
            "type": "string",
            "description": "Required when action=ask_human: a single concrete question for the operator (a value you cannot derive, or an authorization).",
        },
        "verdict": {
            "type": "string",
            "enum": ["confirmed", "not_confirmed", "needs_manual"],
            "description": "Required when action=finish: the reproduction verdict.",
        },
        "severity": {
            "type": "string",
            "enum": ["info", "low", "medium", "high", "critical"],
            "description": "When action=finish and verdict=confirmed: severity of the confirmed issue.",
        },
        "evidence": {
            "type": "string",
            "description": "When action=finish: the concrete observed evidence supporting the verdict (response snippets, status codes, diffs).",
        },
        "reasoning": {
            "type": "string",
            "description": "When action=finish: one sentence tying the observed evidence to the verdict.",
        },
    },
    "required": ["thought", "action"],
}

# Probe-diff classifier — dast/ai/probe_classifier.py _SYSTEM / classify()
PROBE_CLASSIFIER_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "injection_class": {
            "type": "string",
            "description": "Most likely injection class implied by the transformation signature, e.g. sqli, ssti, xss, cmdi, or 'none' if the divergence is not injection-related.",
        },
        "context": {
            "type": "string",
            "description": "The parsing context the parameter flows into, e.g. 'single-quoted SQL string', 'server-side template', 'HTML attribute', 'inert/reflected-only'.",
        },
        "confidence": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
            "description": "Certainty that this parameter is injectable in the stated class, from the diff evidence alone.",
        },
        "recommended_agents": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Attack-type identifiers worth dispatching with a high prior, ordered most-likely first. Empty if the parameter appears inert.",
        },
        "reasoning": {
            "type": "string",
            "description": "One sentence tying the observed break-vs-repair divergence to the injection-class hypothesis.",
        },
    },
    "required": ["injection_class", "context", "confidence", "recommended_agents", "reasoning"],
}

# Attack-chain planner — dast/chains/planner.py plan_chain().
# Turns a free-text multi-step report into an executable chain spec. The step
# fields mirror dast/chains/models.py (ChainStep/Extractor/Assertion) so the
# planner output feeds ChainEngine.run() directly.
ATTACK_CHAIN_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Short slug for the chain, e.g. 'guest-token-cdn-access'."},
        "description": {"type": "string", "description": "One sentence: what the chain proves and why it is a vulnerability."},
        "vuln_type": {
            "type": "string",
            "description": "Best-fit category: broken_access_control, business_logic, auth_bypass, idor, info_disclosure, or attack_chain if none fit.",
        },
        "steps": {
            "type": "array",
            "description": "Ordered requests. Earlier steps bind variables/cookies that later steps consume via {{var}} templates. Include a final CONTROL step (send_cookies:[] or without the key credential) that is expected to FAIL, proving the credential is what defeats the check.",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Human label for the step, e.g. 'bootstrap' or 'control-no-cookies'."},
                    "method": {"type": "string", "description": "HTTP method. Default GET."},
                    "url": {"type": "string", "description": "Absolute URL on the target host. May contain {{var}} placeholders bound by earlier steps."},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Request headers; may use {{var}} (e.g. Authorization: Bearer {{jwt}})."},
                    "body": {"type": "string", "description": "Request body for POST/PUT (e.g. a GraphQL query). May use {{var}}. Empty otherwise."},
                    "send_cookies": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Cookie names to send. Omit to send all harvested cookies; use an EMPTY array for a control step that must send none.",
                    },
                    "max_range_bytes": {"type": "integer", "description": "When fetching content, cap the response to this many bytes (adds a Range header) so validation never pulls a full asset. Use a small value like 64."},
                    "extract": {
                        "type": "array",
                        "description": "Bind data out of this step's response for later steps.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "kind": {"type": "string", "description": "json | regex | set_cookie | b64json | jwt_claim."},
                                "var": {"type": "string", "description": "Variable name to bind."},
                                "expr": {"type": "string", "description": "json/b64json/jwt_claim: dotted path (key, key[0], key[*]). regex: pattern (group 1 wins). set_cookie: cookie name."},
                                "from": {"type": "string", "description": "Source: body (default), header:<Name>, or var:<name>."},
                            },
                            "required": ["kind", "var"],
                        },
                    },
                    "assertions": {
                        "type": "array",
                        "description": "Conditions that must hold for the step to pass.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "kind": {"type": "string", "description": "status_eq | status_in | header_contains | body_contains | body_not_contains | var_present | var_contains | var_equals."},
                                "value": {"description": "Operand for status_eq / var_equals."},
                                "values": {"type": "array", "description": "Operand for status_in."},
                                "name": {"type": "string", "description": "Header name for header_contains."},
                                "needle": {"type": "string", "description": "Substring for *_contains."},
                                "var": {"type": "string", "description": "Variable name for var_* assertions."},
                            },
                            "required": ["kind"],
                        },
                    },
                },
                "required": ["name", "url"],
            },
        },
    },
    "required": ["name", "vuln_type", "steps"],
}
