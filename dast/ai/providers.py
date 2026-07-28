"""
Non-Bedrock LLM providers for the AI gateway.

The gateway (`dast.ai.bedrock_client`) builds every request as an Anthropic-style
body — ``{system, messages, max_tokens, temperature?, tools?, tool_choice?}`` —
and reads the response as an Anthropic-style envelope (``{"content": [{type,
...}]}``). To keep every caller and the whole schema-forced tool-use machinery
unchanged, each provider here accepts that same body and returns that same
envelope shape, regardless of the wire format it actually speaks.

Two providers live here:
  - Anthropic Messages API — the body is already Anthropic-shaped, so this is a
    thin pass-through (drop the Bedrock-only ``anthropic_version`` key, move the
    model into the body, send over HTTPS with the API-key header).
  - OpenAI (or any OpenAI-compatible endpoint) — the body is translated to chat
    completions on the way out and the response is translated back to an
    Anthropic envelope on the way in, including forced tool calls.

All HTTP goes through httpx (already a project dependency). Network and HTTP
errors are raised to the gateway, which handles retry/backoff uniformly.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

import httpx

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Shared with the gateway: the name of the synthetic tool used to force
# structured output. Kept identical so _extract_tool_input() matches.
_STRUCTURED_TOOL_NAME = "emit_result"

_HTTP_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=60.0, pool=60.0)


class ProviderError(RuntimeError):
    """Raised when an external provider returns a non-success HTTP response."""


def _system_to_text(system: Any) -> str:
    """
    Flatten the gateway's ``system`` field to a plain string.

    The gateway emits a string normally, or a list of content blocks (each with
    a ``text`` key) when prompt caching is requested. OpenAI has no system-side
    cache-control concept, so we collapse blocks back to their text.
    """
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        return "".join(block.get("text", "") for block in system if isinstance(block, dict))
    return str(system or "")


# ── Anthropic Messages API ───────────────────────────────────────────────────

def invoke_anthropic(
    body: Dict[str, Any],
    model_id: str,
    api_key: str,
    base_url: str,
) -> Dict[str, Any]:
    """
    Send an Anthropic-style body to the Anthropic Messages API and return the
    response envelope verbatim (it is already the shape the gateway expects).

    The gateway's body carries ``anthropic_version: bedrock-2023-05-31`` for the
    Bedrock wire protocol; the direct API rejects that key and instead wants the
    version in the ``anthropic-version`` header, so we swap it here.
    """
    if not api_key:
        raise ProviderError("Anthropic provider selected but no API key is configured")

    payload = {key: value for key, value in body.items() if key != "anthropic_version"}
    payload["model"] = model_id

    url = base_url.rstrip("/") + "/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    with httpx.Client(timeout=_HTTP_TIMEOUT) as client:
        response = client.post(url, headers=headers, json=payload)
    if response.status_code >= 400:
        raise ProviderError(
            f"Anthropic API {response.status_code}: {response.text[:500]}"
        )
    # The Messages API response is already {"content": [...], "usage": {...}} —
    # exactly what _extract_text/_extract_tool_input read.
    return response.json()


# ── OpenAI (and OpenAI-compatible) chat completions ──────────────────────────

def _to_openai_request(body: Dict[str, Any], model_id: str) -> Dict[str, Any]:
    """Translate the gateway's Anthropic-style body into a chat-completions request."""
    messages: List[Dict[str, Any]] = []
    system_text = _system_to_text(body.get("system", ""))
    if system_text:
        messages.append({"role": "system", "content": system_text})
    for message in body.get("messages", []):
        # The gateway only ever sends string content on the user turn.
        messages.append({"role": message["role"], "content": message["content"]})

    request: Dict[str, Any] = {
        "model": model_id,
        "messages": messages,
        "max_tokens": body.get("max_tokens", 2048),
    }
    if "temperature" in body:
        request["temperature"] = body["temperature"]

    # Schema-forced output → a single required function call.
    tools = body.get("tools")
    if tools:
        request["tools"] = [
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool["input_schema"],
                },
            }
            for tool in tools
        ]
        forced = body.get("tool_choice", {})
        if forced.get("type") == "tool":
            request["tool_choice"] = {
                "type": "function",
                "function": {"name": forced["name"]},
            }
    return request


def _from_openai_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Translate a chat-completions response back into an Anthropic-style envelope
    so the gateway's block extractors work without special-casing the provider.
    """
    choices = data.get("choices") or []
    if not choices:
        raise ProviderError("OpenAI response contained no choices")
    message = choices[0].get("message", {})

    content_blocks: List[Dict[str, Any]] = []

    # Forced/structured tool call → tool_use block with parsed arguments.
    tool_calls = message.get("tool_calls") or []
    for call in tool_calls:
        function = call.get("function", {})
        raw_arguments = function.get("arguments", "{}")
        try:
            parsed = json.loads(raw_arguments) if isinstance(raw_arguments, str) else raw_arguments
        except json.JSONDecodeError:
            logger.warning("OpenAI tool_call arguments were not valid JSON", raw=raw_arguments[:200])
            parsed = {}
        content_blocks.append({
            "type": "tool_use",
            # Report the gateway's synthetic tool name so _extract_tool_input matches,
            # even if a compatible endpoint echoes a different name.
            "name": _STRUCTURED_TOOL_NAME,
            "input": parsed,
        })

    text = message.get("content")
    if text:
        content_blocks.append({"type": "text", "text": text})

    if not content_blocks:
        content_blocks.append({"type": "text", "text": ""})

    envelope: Dict[str, Any] = {"content": content_blocks}
    usage = data.get("usage")
    if usage:
        # Surface token counts under the keys the gateway's cache logger reads.
        envelope["usage"] = usage
    return envelope


def invoke_openai(
    body: Dict[str, Any],
    model_id: str,
    api_key: str,
    base_url: str,
) -> Dict[str, Any]:
    """
    Send an Anthropic-style body to an OpenAI-compatible chat-completions
    endpoint and return an Anthropic-style response envelope.
    """
    if not api_key:
        raise ProviderError("OpenAI provider selected but no API key is configured")

    request = _to_openai_request(body, model_id)
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "content-type": "application/json",
    }
    with httpx.Client(timeout=_HTTP_TIMEOUT) as client:
        response = client.post(url, headers=headers, json=request)
    if response.status_code >= 400:
        raise ProviderError(
            f"OpenAI API {response.status_code}: {response.text[:500]}"
        )
    return _from_openai_response(response.json())
