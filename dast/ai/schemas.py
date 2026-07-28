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
