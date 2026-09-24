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
# "anthropic", "openai", "gateway". Empty string means "use settings.ai_provider".
# Set at runtime via set_provider() when the user changes it in the dashboard.
_active_provider: str = ""

# Per-provider credentials/endpoints, set at runtime via set_provider().
# Empty string means "fall back to settings.*".
_anthropic_api_key: str = ""
_anthropic_base_url: str = ""
_openai_api_key: str = ""
_openai_base_url: str = ""
# The gateway authenticates via an OAuth JWT reused from the Claude Code CLI
# session (macOS Keychain / GATEWAY_JWT), not an API key. Only its base URL is
# configurable here; it is internal, so it lives in .env, never in config.py.
_gateway_base_url: str = ""

# Set when all retry attempts fail with ExpiredTokenException.
# Causes the scan queue to pause until credentials are refreshed.
_ai_unavailable: bool = False

# Per-provider auto-resolved default model NAME, used when a non-Bedrock provider
# is active but no provider-appropriate model is configured (the model is empty or
# a Bedrock ARN carried over from the Bedrock defaults). Resolved once from the
# provider's live catalogue (preferring a Sonnet tier) and cached here; cleared on
# any provider switch or explicit model change so it re-resolves. Keyed by provider.
_default_model_cache: Dict[str, str] = {}


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


def _preferred_default_model(models: list) -> str:
    """Pick a provider-appropriate default model NAME from a catalogue, preferring
    a Sonnet tier (the balanced default) over Haiku/Opus. Bedrock ARNs are skipped
    — they are only valid for the Bedrock provider. Among Sonnet options a plain
    variant is preferred over context-window variants (e.g. ``claude-sonnet-5``
    over ``claude-sonnet-5[1m]``). Returns "" when the catalogue has no usable name.
    """
    ids = [
        str(m.get("id"))
        for m in models
        if m.get("id") and not _is_bedrock_arn(str(m.get("id")))
    ]
    if not ids:
        return ""
    plain_sonnet = [i for i in ids if "sonnet" in i.lower() and "[" not in i]
    if plain_sonnet:
        return plain_sonnet[0]
    any_sonnet = [i for i in ids if "sonnet" in i.lower()]
    if any_sonnet:
        return any_sonnet[0]
    return ids[0]


def _resolve_default_model(provider: str) -> str:
    """Resolve (and cache) the default model NAME for a non-Bedrock provider from
    its live catalogue, preferring Sonnet. Cached per provider so the catalogue is
    fetched at most once per provider between switches. Never raises — a catalogue
    failure caches "" so callers can fall back to their own error handling."""
    if provider == "bedrock":
        return ""
    if provider in _default_model_cache:
        return _default_model_cache[provider]
    chosen = ""
    try:
        catalogue = list_models()
        chosen = _preferred_default_model(catalogue.get("models", []))
    except Exception as exc:  # never let model listing crash an LLM call
        logger.warning("Default-model resolution failed", provider=provider, error=str(exc))
    if chosen:
        logger.info("Auto-selected default model for provider", provider=provider, model=chosen)
    _default_model_cache[provider] = chosen
    return chosen


def set_active_model(model_id: str) -> None:
    global _active_model_id
    _active_model_id = model_id or ""
    _default_model_cache.clear()


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
    gateway_base_url: str = "",
) -> None:
    """
    Select the active LLM provider and its credentials/endpoint at runtime.

    provider — "bedrock" (default), "anthropic", "openai", or "gateway". Empty
    falls back to settings.ai_provider. Only the fields relevant to the chosen
    provider are used; each empty argument falls back to the corresponding
    settings value. The gateway takes no API key (it reuses the Claude Code CLI
    OAuth session); only its base URL is configurable, and it stays in .env.
    Switching provider clears the cached Bedrock client so a later switch back to
    bedrock rebuilds cleanly, and re-enables AI (a prior provider may have been
    marked unavailable on expired AWS creds).
    """
    global _active_provider, _anthropic_api_key, _anthropic_base_url
    global _openai_api_key, _openai_base_url, _gateway_base_url, _active_model_id
    _active_provider = (provider or "").strip().lower()
    _anthropic_api_key = anthropic_api_key or ""
    _anthropic_base_url = anthropic_base_url or ""
    _openai_api_key = openai_api_key or ""
    _openai_base_url = openai_base_url or ""
    _gateway_base_url = gateway_base_url or ""
    _reset_client()
    _default_model_cache.clear()
    mark_ai_available()
    active_provider = get_active_provider()
    logger.info("AI provider configured", provider=active_provider)

    # Auto-heal the active model on switch: a Bedrock ARN (the Bedrock default,
    # often carried over) is meaningless to a non-Bedrock provider and would make
    # every LLM call fail. Eagerly resolve a provider-appropriate default NAME
    # (preferring Sonnet) from the provider's live catalogue so the model badge,
    # scans, and copilot all work without the operator re-picking a model.
    if active_provider != "bedrock":
        from dast.config import settings
        current = _active_model_id or settings.ai_model_id
        if not current or _is_bedrock_arn(current):
            healed = _resolve_default_model(active_provider)
            if healed:
                _active_model_id = healed
                logger.info(
                    "Reset active model to provider default (was empty or a Bedrock ARN)",
                    provider=active_provider, model=healed,
                )


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
        if _openai_api_key or settings.openai_api_key:
            return True
        # Local / self-hosted OpenAI-compatible servers ignore the key, so a
        # non-public base_url is reachable without one (see providers.py).
        from dast.ai import providers
        base_url = _openai_base_url or settings.openai_base_url
        return not providers.is_public_openai(base_url)
    if provider == "gateway":
        # The gateway has no API key — reachability means a usable CLI OAuth
        # session (Keychain) or an explicit GATEWAY_JWT is available.
        from dast.ai import gateway_auth
        return gateway_auth.credentials_available()
    return False


def list_models() -> Dict[str, Any]:
    """
    List the models available for the active provider, for the UI dropdowns.

    Returns ``{"provider", "models": [{"id", "label"}], "source", "error"}``.
    ``source`` is "live" when fetched from the provider's models API, or "preset"
    when we fell back to the static named tiers (Bedrock always uses presets —
    ARNs can't be enumerated without extra IAM perms and don't map to tiers; the
    gateway falls back to presets when it exposes no models endpoint). Never
    raises — a provider failure degrades to presets with an ``error`` message.
    """
    from dast.config import settings
    from dast.ai import providers

    provider = get_active_provider()
    presets = settings.model_presets

    if provider == "bedrock":
        return {"provider": provider, "models": presets, "source": "preset", "error": ""}

    try:
        if provider == "anthropic":
            models = providers.list_anthropic_models(
                api_key=_anthropic_api_key or (settings.anthropic_api_key or ""),
                base_url=_anthropic_base_url or settings.anthropic_base_url,
            )
        elif provider == "openai":
            models = providers.list_openai_models(
                api_key=_openai_api_key or (settings.openai_api_key or ""),
                base_url=_openai_base_url or settings.openai_base_url,
            )
        elif provider == "gateway":
            models = providers.list_gateway_models(
                base_url=_gateway_base_url or settings.gateway_base_url,
            )
        else:
            return {"provider": provider, "models": presets, "source": "preset",
                    "error": f"Unknown provider: {provider}"}
        if models:
            return {"provider": provider, "models": models, "source": "live", "error": ""}
        # Empty list — treat as no live catalogue; fall back to presets.
        return {"provider": provider, "models": presets, "source": "preset", "error": ""}
    except Exception as exc:
        logger.warning("Model listing failed; using presets", provider=provider, error=str(exc))
        return {"provider": provider, "models": presets, "source": "preset", "error": str(exc)[:200]}


def get_active_model() -> str:
    from dast.config import settings
    model = _active_model_id or settings.ai_model_id
    # A Bedrock ARN (or empty) under a non-Bedrock provider is not usable — this
    # happens when AI_PROVIDER is set to gateway/anthropic/openai via env at boot
    # (no provider switch runs). Lazily resolve a provider-appropriate default
    # NAME so the badge and every LLM call reflect a model the provider accepts.
    provider = get_active_provider()
    if provider != "bedrock" and (not model or _is_bedrock_arn(model)):
        return _resolve_default_model(provider) or model
    return model


def _is_bedrock_arn(model_id: str) -> bool:
    """True if ``model_id`` is an AWS Bedrock model / inference-profile ARN.

    A Bedrock ARN is only meaningful to the ``bedrock`` provider; every other
    provider (gateway/anthropic/openai and any future local backend such as
    Ollama) expects a plain model *name*.
    """
    return bool(model_id) and model_id.startswith("arn:aws:")


def _usable_tier_model(tier_model_id: str, tier_name: str) -> str:
    """Return ``tier_model_id`` only if it is valid for the active provider.

    The tiered model IDs (fast/validation) default to Bedrock ARNs (from
    ``settings.anthropic_default_*_model``) and are applied at startup regardless
    of provider. When the active provider is NOT Bedrock (gateway/anthropic/
    openai), a Bedrock ARN is not a model that provider accepts — the gateway
    rejects it with ``HTTP 400: ... not in your role's availableModels
    allowlist``, which silently degrades every planner/canary/baseline/red-team
    call that uses a tier helper. That produces flaky detection (a vuln is found
    only when the code path happens to use the active model). Guard against it:
    when a tier holds a Bedrock ARN but the provider is non-Bedrock, ignore it and
    fall back to the active model (a provider-appropriate name).
    """
    if not tier_model_id:
        return ""
    provider = get_active_provider()
    if provider != "bedrock" and _is_bedrock_arn(tier_model_id):
        logger.warning(
            "Ignoring Bedrock ARN configured for tier under non-Bedrock provider",
            tier=tier_name, provider=provider,
        )
        return ""
    return tier_model_id


def _resolve_model(model_id: Optional[str]) -> str:
    """Resolve the model id to send to the active provider, guarding a mismatch.

    The AI connection (bedrock/anthropic/openai/gateway, and future local
    backends like Ollama) is a pluggable layer, not part of the scanner core: a
    model id is only valid for the provider it was configured for. The default
    ``settings.ai_model_id`` is a Bedrock ARN, so a non-Bedrock provider can end
    up handed an ARN through either the tier fallback or an explicit ``model_id``
    (the coordinator planner passes one directly). The gateway rejects that with
    ``HTTP 400: ... not in your role's availableModels allowlist``, which would
    otherwise silently degrade every LLM call and produce flaky detection.

    Rather than ship a wrong model and let detection quietly fail, fail loud: when
    the active provider is non-Bedrock and no provider-appropriate model resolves
    (empty, or a Bedrock ARN), pause AI and raise an actionable error so the
    operator sets a model *name* (e.g. ``claude-haiku-4-5``) in the dashboard AI
    settings / ``/api/scan-config``.
    """
    provider = get_active_provider()
    model = model_id or get_active_model()
    if provider != "bedrock" and (not model or _is_bedrock_arn(model)):
        # An explicit Bedrock ARN (e.g. the coordinator planner passing model_id
        # directly) still reaches here even though get_active_model() self-heals.
        # Prefer a provider-appropriate default over failing the call outright.
        healed = _resolve_default_model(provider)
        if healed and not _is_bedrock_arn(healed):
            logger.warning(
                "Substituting provider default for a Bedrock ARN under non-Bedrock provider",
                provider=provider, model=healed,
            )
            return healed
        mark_ai_unavailable()
        raise AiUnavailableError(
            f"No model configured for AI provider '{provider}'. A Bedrock ARN "
            f"cannot be used with '{provider}' — set a provider-appropriate model "
            f"name (for example claude-haiku-4-5) in the dashboard AI settings, "
            f"then click Resume."
        )
    return model


def get_fast_model() -> str:
    """Return the model to use for fast, low-stakes decisions (planning, baseline).
    Falls back to active model if no fast model configured (or the configured one
    is not valid for the active provider)."""
    return _usable_tier_model(_fast_model_id, "fast") or get_active_model()


def get_validation_model() -> str:
    """Return the model to use for high-stakes validation (red-team exploit proof).
    Falls back to active model if no validation model configured (or the configured
    one is not valid for the active provider)."""
    return _usable_tier_model(_validation_model_id, "validation") or get_active_model()


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
            if provider == "gateway":
                return providers.invoke_gateway(
                    body=body,
                    model_id=model,
                    # No API key: the gateway reuses the CLI OAuth session.
                    api_key="",
                    base_url=_gateway_base_url or settings.gateway_base_url,
                )
            raise providers.ProviderError(f"Unknown AI provider: {provider}")

        except providers.ProviderError as exc:
            # Transient errors — a 429 (rate limit) or any 5xx (server-side) — are
            # worth retrying with backoff, matching the Bedrock throttling path.
            # Other 4xx and config errors are permanent — surface immediately.
            status = getattr(exc, "status_code", None)
            transient = status == 429 or (status is not None and 500 <= status < 600)
            if transient and attempt < 2:
                logger.warning("Provider transient error, backing off",
                               provider=provider, status=status, attempt=attempt)
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

    model = _resolve_model(model_id)
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
