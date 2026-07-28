"""
AWS Bedrock Claude client for AI-driven attack analysis.

All LLM calls in the pipeline go through this module.
Handles credential refresh (SSO token expiry), throttling backoff, and
structured output.

Credential priority (matches orchestrator-ai):
  1. AWS_PROFILE — SSO or named profile; run 'aws sso login --profile <name>'
     before scanning. Token refresh happens automatically on ExpiredTokenException.
  2. AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY — static keys
  3. Default boto3 chain (instance profile, env vars, ~/.aws/credentials)
"""

import json
import threading
import time
from typing import Any, Dict, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_client = None
_lock = threading.Lock()

# Name of the synthetic tool used to force structured (schema-constrained) output.
# When a caller passes a schema, the model is forced to call this tool, so the
# response is guaranteed to match the schema instead of relying on the model to
# emit clean JSON as free text.
_STRUCTURED_TOOL_NAME = "emit_result"

# Runtime model override — set by the proxy runner at startup and updated
# when the user changes the model in the dashboard Settings.
# Falls back to settings.ai_model_id (from .env / default) when empty.
_active_model_id: str = ""

# Tiered model IDs — set at runtime via set_tiered_models() when the user
# configures tier overrides. Empty string means "use active model".
_fast_model_id: str = ""        # Haiku: planning, baseline, low-stakes decisions
_validation_model_id: str = ""  # Opus: red-team validation, complex exploitation proof

# Active provider — which backend serves LLM calls. One of "bedrock",
# "anthropic", "openai". Empty string means "use settings.ai_provider".
# Set at runtime via set_provider() when the user changes it in the dashboard.
_active_provider: str = ""

# Per-provider credentials/endpoints, set at runtime via set_provider().
# Empty string means "fall back to settings.*".
_anthropic_api_key: str = ""
_anthropic_base_url: str = ""
_openai_api_key: str = ""
_openai_base_url: str = ""

# Set when all retry attempts fail with ExpiredTokenException.
# Causes the scan queue to pause until credentials are refreshed.
_ai_unavailable: bool = False


class AiUnavailableError(RuntimeError):
    """Raised when AWS credentials are expired and cannot be refreshed."""


def is_ai_available() -> bool:
    return not _ai_unavailable


def mark_ai_available() -> None:
    global _ai_unavailable
    _ai_unavailable = False


def mark_ai_unavailable() -> None:
    global _ai_unavailable
    _ai_unavailable = True


def set_active_model(model_id: str) -> None:
    global _active_model_id
    _active_model_id = model_id or ""


def set_tiered_models(fast: str = "", validation: str = "") -> None:
    """Configure model tiers. Empty string falls back to active model."""
    global _fast_model_id, _validation_model_id
    _fast_model_id = fast or ""
    _validation_model_id = validation or ""


def set_provider(
    provider: str = "",
    anthropic_api_key: str = "",
    anthropic_base_url: str = "",
    openai_api_key: str = "",
    openai_base_url: str = "",
) -> None:
    """
    Select the active LLM provider and its credentials/endpoint at runtime.

    provider — "bedrock" (default), "anthropic", or "openai". Empty falls back
    to settings.ai_provider. Only the fields relevant to the chosen provider are
    used; each empty argument falls back to the corresponding settings value.
    Switching provider clears the cached Bedrock client so a later switch back to
    bedrock rebuilds cleanly, and re-enables AI (a prior provider may have been
    marked unavailable on expired AWS creds).
    """
    global _active_provider, _anthropic_api_key, _anthropic_base_url
    global _openai_api_key, _openai_base_url
    _active_provider = (provider or "").strip().lower()
    _anthropic_api_key = anthropic_api_key or ""
    _anthropic_base_url = anthropic_base_url or ""
    _openai_api_key = openai_api_key or ""
    _openai_base_url = openai_base_url or ""
    _reset_client()
    mark_ai_available()
    logger.info("AI provider configured", provider=get_active_provider())


def get_active_provider() -> str:
    from dast.config import settings
    return (_active_provider or settings.ai_provider or "bedrock").strip().lower()


def provider_api_key_present() -> bool:
    """
    Whether the active non-Bedrock provider has an API key configured (runtime
    override or settings/env fallback). Meaningless for the bedrock provider,
    which authenticates via AWS credentials — callers should branch on
    get_active_provider() first. Used by the status endpoint so the dashboard
    reports AI reachability for the provider that actually serves LLM calls,
    instead of always probing AWS STS.
    """
    from dast.config import settings
    provider = get_active_provider()
    if provider == "anthropic":
        return bool(_anthropic_api_key or settings.anthropic_api_key)
    if provider == "openai":
        return bool(_openai_api_key or settings.openai_api_key)
    return False


def get_active_model() -> str:
    from dast.config import settings
    return _active_model_id or settings.ai_model_id


def get_fast_model() -> str:
    """Return the model to use for fast, low-stakes decisions (planning, baseline).
    Falls back to active model if no fast model configured."""
    return _fast_model_id or get_active_model()


def get_validation_model() -> str:
    """Return the model to use for high-stakes validation (red-team exploit proof).
    Falls back to active model if no validation model configured."""
    return _validation_model_id or get_active_model()


def get_client():
    global _client
    if _client is not None:
        return _client
    with _lock:
        if _client is not None:
            return _client
        _client = _build_client()
        return _client


def _reset_client():
    """Discard the cached client so the next call rebuilds with fresh credentials."""
    global _client
    with _lock:
        _client = None


def _build_client():
    from botocore.config import Config
    from dast.config import settings

    session = settings.build_boto3_session()
    cfg = Config(
        read_timeout=60,
        connect_timeout=10,
        retries={"max_attempts": 3, "mode": "adaptive"},
        max_pool_connections=25,  # default 10 is too low when AI mode runs many parallel scans
    )
    return session.client("bedrock-runtime", region_name=settings.aws_region, config=cfg)


def _build_system_block(system: str, cache_system: bool) -> Any:
    """
    Shape the ``system`` field for the Bedrock request body.

    Plain string by default (unchanged behaviour). When ``cache_system`` is set,
    the system prompt is emitted as a single content block carrying an ephemeral
    ``cache_control`` breakpoint — so large static system prompts are cached and
    every subsequent call is a cache read instead of re-priced from scratch.
    """
    if not cache_system:
        return system
    return [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]


def _build_body(
    system: str,
    user: str,
    max_tokens: int,
    temperature: Optional[float],
    cache_system: bool,
    schema: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Construct the Bedrock InvokeModel request body shared by invoke()/invoke_json().

    Optional params are only added to the body when set, so callers that pass
    nothing get byte-for-byte the previous request shape.
    """
    body: Dict[str, Any] = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "system": _build_system_block(system, cache_system),
        "messages": [{"role": "user", "content": user}],
    }
    if temperature is not None:
        body["temperature"] = temperature
    if schema is not None:
        # Force the model through a single tool call whose input_schema is the
        # caller's schema. The response arrives as a structured tool_use block,
        # so malformed JSON is impossible by construction.
        body["tools"] = [{
            "name": _STRUCTURED_TOOL_NAME,
            "description": "Return the result as a structured object matching the schema.",
            "input_schema": schema,
        }]
        body["tool_choice"] = {"type": "tool", "name": _STRUCTURED_TOOL_NAME}
    return body


def _log_cache_usage(result: Dict[str, Any]) -> None:
    """Emit cache read/creation token counts (if present) at debug level."""
    usage = result.get("usage") or {}
    read = usage.get("cache_read_input_tokens")
    created = usage.get("cache_creation_input_tokens")
    if read or created:
        logger.debug("Bedrock cache usage", cache_read=read, cache_creation=created)


def _invoke_external(
    provider: str,
    body: Dict[str, Any],
    model: str,
) -> Dict[str, Any]:
    """
    Route a request to a non-Bedrock provider (Anthropic direct / OpenAI) and
    return an Anthropic-style envelope. Retries transient HTTP errors with the
    same backoff schedule as the Bedrock path.
    """
    from dast.config import settings
    from dast.ai import providers

    delay = 2
    for attempt in range(3):
        try:
            if provider == "anthropic":
                return providers.invoke_anthropic(
                    body=body,
                    model_id=model,
                    api_key=_anthropic_api_key or (settings.anthropic_api_key or ""),
                    base_url=_anthropic_base_url or settings.anthropic_base_url,
                )
            if provider == "openai":
                return providers.invoke_openai(
                    body=body,
                    model_id=model,
                    api_key=_openai_api_key or (settings.openai_api_key or ""),
                    base_url=_openai_base_url or settings.openai_base_url,
                )
            raise providers.ProviderError(f"Unknown AI provider: {provider}")

        except providers.ProviderError as exc:
            # A 429 (rate limit) is worth retrying; other 4xx/5xx and config
            # errors are not — surface them immediately.
            if "429" in str(exc) and attempt < 2:
                logger.warning("Provider rate-limited, backing off", provider=provider, attempt=attempt)
                time.sleep(delay)
                delay *= 2
                continue
            logger.error("AI provider call failed", provider=provider, error=str(exc))
            raise
        except Exception as exc:  # network/timeout errors from httpx
            if attempt < 2:
                logger.warning("Provider call errored, retrying", provider=provider, error=str(exc))
                time.sleep(delay)
                delay *= 2
                continue
            logger.error("AI provider call failed", provider=provider, error=str(exc))
            raise


def _invoke_raw(
    system: str,
    user: str,
    model_id: Optional[str],
    max_tokens: int,
    temperature: Optional[float],
    cache_system: bool,
    schema: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Send one request to the active provider and return the parsed response
    envelope (always Anthropic-shaped, regardless of provider). Handles
    throttling and credential expiry automatically.
    """
    from botocore.exceptions import ClientError

    model = model_id or get_active_model()
    body = _build_body(system, user, max_tokens, temperature, cache_system, schema)

    provider = get_active_provider()
    if provider != "bedrock":
        result = _invoke_external(provider, body, model)
        _log_cache_usage(result)
        return result

    delay = 2
    for attempt in range(3):
        try:
            client = get_client()
            response = client.invoke_model(modelId=model, body=json.dumps(body))
            result = json.loads(response["body"].read())
            _log_cache_usage(result)
            return result

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "ExpiredTokenException":
                # SSO token expired — drop the cached client so the next attempt
                # builds a fresh boto3 session that reads the renewed token from
                # ~/.aws/sso/cache (populated by 'aws sso login --profile <name>').
                _reset_client()
                continue
            if code in ("ThrottlingException", "TooManyRequestsException") and attempt < 2:
                time.sleep(delay)
                delay *= 2
                continue
            raise

    # All retries exhausted — likely means the SSO token cannot be refreshed
    # (user needs to run 'aws sso login' again). Signal the scan queue to pause.
    mark_ai_unavailable()
    raise AiUnavailableError("AWS credentials expired — run 'aws sso login' then click Resume")


def _extract_text(result: Dict[str, Any]) -> str:
    """Pull the first text block from a Bedrock response envelope."""
    for block in result.get("content", []):
        if block.get("type") == "text":
            return block.get("text", "")
    # Fall back to legacy positional access for non-typed responses.
    return result["content"][0]["text"]


def _extract_tool_input(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Pull the structured input from a forced tool_use block, if present."""
    for block in result.get("content", []):
        if block.get("type") == "tool_use" and block.get("name") == _STRUCTURED_TOOL_NAME:
            return block.get("input")
    return None


def invoke(
    system: str,
    user: str,
    model_id: Optional[str] = None,
    max_tokens: int = 2048,
    temperature: Optional[float] = None,
    cache_system: bool = False,
) -> str:
    """
    Send a system+user message to Claude and return the text response.
    Handles throttling and credential expiry automatically.

    temperature   — sampling temperature; omitted from the request when None
                    (model default). Set 0 for deterministic decisions.
    cache_system  — cache the system prompt with an ephemeral breakpoint; use for
                    large static system prompts re-sent across many calls.
    """
    result = _invoke_raw(
        system=system, user=user, model_id=model_id, max_tokens=max_tokens,
        temperature=temperature, cache_system=cache_system, schema=None,
    )
    return _extract_text(result)


def _strip_json_fence(raw: str) -> str:
    """Strip a surrounding markdown code fence (```json ... ``` or ``` ... ```)."""
    raw = raw.strip()
    if raw.startswith("```"):
        # Drop the opening fence line (```json, ```JSON, ``` etc.)
        raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
        # Drop the closing fence (may have trailing whitespace/newline)
        raw = raw.rstrip()
        if raw.endswith("```"):
            raw = raw[:-3]
    return raw.strip()


def invoke_json(
    system: str,
    user: str,
    model_id: Optional[str] = None,
    max_tokens: int = 2048,
    temperature: Optional[float] = None,
    cache_system: bool = False,
    schema: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Like invoke() but returns parsed JSON.

    schema — when provided, force structured output via a tool call whose
             input_schema is this schema. The result is validated at the API
             layer and returned directly (no text parsing). This is the robust
             path — malformed JSON cannot occur.

    When no schema is given, fall back to the legacy "ask for JSON + strip
    fence + json.loads" path, hardened with a one-shot repair-retry: if the
    model returns text that isn't valid JSON, it is re-invoked once with an
    explicit instruction to return only the JSON object.
    """
    # Structured path: the model is forced to call the tool, so we read the
    # validated object straight from the tool_use block.
    if schema is not None:
        result = _invoke_raw(
            system=system, user=user, model_id=model_id, max_tokens=max_tokens,
            temperature=temperature, cache_system=cache_system, schema=schema,
        )
        tool_input = _extract_tool_input(result)
        if tool_input is not None:
            return tool_input
        # Model returned text despite tool_choice (rare) — fall through to
        # parsing the text so the caller still gets a dict rather than an error.
        logger.warning("Structured output requested but no tool_use block returned; parsing text")
        return json.loads(_strip_json_fence(_extract_text(result)))

    # Legacy path: instruct JSON, parse text, repair once on failure.
    if "json" not in system.lower():
        system += "\n\nRespond ONLY with valid JSON. No markdown, no explanation."

    raw = invoke(
        system=system, user=user, model_id=model_id, max_tokens=max_tokens,
        temperature=temperature, cache_system=cache_system,
    )
    try:
        return json.loads(_strip_json_fence(raw))
    except json.JSONDecodeError as exc:
        logger.warning("invoke_json got malformed JSON — retrying once", error=str(exc))
        repair_user = (
            f"{user}\n\nYour previous reply was not valid JSON:\n{raw[:500]}\n\n"
            "Reply with ONLY the JSON object. No markdown, no prose, no code fence."
        )
        raw2 = invoke(
            system=system, user=repair_user, model_id=model_id, max_tokens=max_tokens,
            temperature=temperature, cache_system=cache_system,
        )
        return json.loads(_strip_json_fence(raw2))
