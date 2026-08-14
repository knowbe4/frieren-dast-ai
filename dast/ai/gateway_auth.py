"""
Claude apps gateway authentication (OAuth bearer JWT over the Anthropic Messages API).

This is the "gateway" AI provider's auth layer. It reuses the OAuth session that
the Claude Code CLI obtains via a Backstage-backed device flow and caches (with a
refresh token) in the macOS Keychain. We never write back to the Keychain — the
CLI owns that store — so refresh happens in-memory only.

Flow:
  1. Load the CLI-cached gateway credentials (macOS Keychain, or an explicit JWT
     supplied via configuration for headless/CI hosts).
  2. If the access token is expired, renew it via the OAuth refresh_token grant.
  3. POST Anthropic Messages requests to ``{base_url}/v1/messages`` with the JWT.

Stdlib-only (urllib) and thread-safe, ported from report-secreview's
gateway_client.py. The internal gateway hostname is deliberately NOT hardcoded
here (this repo is public) — the base URL comes from configuration (.env) or from
the ``url`` field the CLI stored in the Keychain on the operator's own machine.

Non-macOS hosts have no Keychain: unless an explicit JWT is configured,
``credentials_available()`` returns False so callers degrade gracefully.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# The macOS Keychain "generic password" service the Claude Code CLI writes its
# session under. Overridable via env for non-default CLI builds; the value here
# is the CLI's public default, not an internal secret.
_DEFAULT_KEYCHAIN_SERVICE = "Claude Code-credentials"
ANTHROPIC_VERSION = "2023-06-01"
EXPIRY_SKEW_SECONDS = 120


class GatewayError(RuntimeError):
    """Raised when the gateway is unreachable or authentication fails."""


def _keychain_service() -> str:
    return os.environ.get("GATEWAY_KEYCHAIN_SERVICE", _DEFAULT_KEYCHAIN_SERVICE)


def _explicit_jwt() -> str:
    """An operator-supplied JWT for hosts without the CLI Keychain (Linux/CI)."""
    return (os.environ.get("GATEWAY_JWT") or "").strip()


def load_gateway_credentials() -> Dict[str, Any]:
    """Read the CLI-cached gateway credentials.

    On macOS this reads the Keychain entry the CLI stored. On any host, an
    explicit ``GATEWAY_JWT`` env var short-circuits the Keychain (headless/CI).

    Raises GatewayError with an actionable message when no session is available.
    """
    explicit = _explicit_jwt()
    if explicit:
        return {"jwt": explicit, "url": (os.environ.get("GATEWAY_BASE_URL") or "").strip()}

    if sys.platform != "darwin":
        raise GatewayError(
            "Gateway credentials are read from the macOS Keychain. On Linux/CI, "
            "set GATEWAY_JWT (and GATEWAY_BASE_URL) to supply the token directly."
        )
    service = _keychain_service()
    try:
        raw = subprocess.check_output(
            ["security", "find-generic-password", "-s", service, "-w"],
            stderr=subprocess.DEVNULL,
        ).decode()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise GatewayError(
            f"No '{service}' entry in the Keychain. "
            "Run `claude` and `/login` (Cloud gateway) first."
        ) from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GatewayError("Keychain gateway entry is not valid JSON.") from exc
    gateway = payload.get("enterpriseGateway")
    if not gateway or "jwt" not in gateway:
        raise GatewayError(
            "Keychain entry has no 'enterpriseGateway' session. "
            "Log in through the gateway with `/login`."
        )
    return gateway


def credentials_available() -> bool:
    """True if a usable gateway session can be loaded (never raises)."""
    try:
        load_gateway_credentials()
        return True
    except GatewayError:
        return False


class GatewayTransport:
    """Thread-safe Anthropic Messages client backed by the Claude apps gateway.

    The gateway JWT and base URL come from the CLI Keychain session (or an
    explicit env-supplied JWT). ``base_url`` may be passed in from configuration
    (.env) to override the Keychain's stored URL; nothing internal is baked into
    this module.
    """

    def __init__(self, base_url: str = "") -> None:
        self._lock = threading.Lock()
        self._creds = load_gateway_credentials()
        self._token: str = self._creds.get("jwt", "")
        resolved = (base_url or self._creds.get("url") or "").strip().rstrip("/")
        if not resolved:
            raise GatewayError(
                "No gateway base URL configured. Set GATEWAY_BASE_URL in .env, or "
                "log in through the CLI so the Keychain session carries the URL."
            )
        self._base_url = resolved

    @property
    def base_url(self) -> str:
        return self._base_url

    def _token_expired(self, skew: int = EXPIRY_SKEW_SECONDS) -> bool:
        expires_at_ms = self._creds.get("expiresAt")
        if not expires_at_ms:
            # No expiry metadata (e.g. explicit JWT): assume valid; a 401 will
            # trigger a refresh attempt on the next call.
            return False
        return time.time() >= (expires_at_ms / 1000.0) - skew

    def _refresh_token(self) -> None:
        """Exchange the stored refresh token for a fresh access token (in-memory)."""
        token_endpoint = (
            self._creds.get("tokenEndpoint") or f"{self._base_url}/oauth/token"
        )
        refresh_token = self._creds.get("idpRefreshToken")
        if not refresh_token:
            raise GatewayError("No refresh token cached; a fresh `/login` is required.")
        data = urllib.parse.urlencode(
            {"grant_type": "refresh_token", "refresh_token": refresh_token}
        ).encode()
        req = urllib.request.Request(
            token_endpoint,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                refreshed = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise GatewayError(
                f"Token refresh failed ({exc.code}): {exc.read().decode()[:200]}. "
                "Run `/login` again to re-establish the session."
            ) from exc
        except urllib.error.URLError as exc:
            raise GatewayError(
                f"Token refresh connection error: {exc.reason} (are you on VPN?)"
            ) from exc
        self._token = refreshed.get("access_token") or refreshed.get("jwt") or self._token
        expires_in = refreshed.get("expires_in")
        if expires_in:
            self._creds["expiresAt"] = (time.time() + float(expires_in)) * 1000.0
        if "refresh_token" in refreshed:
            self._creds["idpRefreshToken"] = refreshed["refresh_token"]
        logger.info("Gateway access token refreshed", expires_in=expires_in)

    def _valid_token(self, force: bool = False) -> str:
        """Return a non-expired access token, refreshing under lock if needed."""
        with self._lock:
            if force or self._token_expired():
                self._refresh_token()
            return self._token

    def send(self, body: Dict[str, Any], timeout: int = 300) -> Dict[str, Any]:
        """POST a pre-built Anthropic Messages body and return the parsed response.

        The body must already be Anthropic-shaped (``model``, ``messages``,
        ``max_tokens``, optional ``system``/``tools``/``tool_choice``/``thinking``).
        Handles token refresh on 401 and exponential backoff on throttling/5xx.
        """
        encoded = json.dumps(body).encode()
        max_retries = 4
        retry_delay = 2.0
        force_refresh = False

        for attempt in range(max_retries):
            token = self._valid_token(force=force_refresh)
            force_refresh = False
            req = urllib.request.Request(
                f"{self._base_url}/v1/messages",
                data=encoded,
                headers={
                    "Authorization": f"Bearer {token}",
                    "anthropic-version": ANTHROPIC_VERSION,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode()[:300]
                if exc.code == 401 and attempt < max_retries - 1:
                    logger.warning("Gateway 401 — refreshing token and retrying")
                    force_refresh = True
                    continue
                if exc.code in (429, 500, 502, 503, 529) and attempt < max_retries - 1:
                    logger.warning(
                        "Gateway throttled/5xx — backing off",
                        status=exc.code, attempt=attempt + 1, delay=retry_delay,
                    )
                    time.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                raise GatewayError(f"Gateway HTTP {exc.code}: {detail}") from exc
            except urllib.error.URLError as exc:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                raise GatewayError(
                    f"Gateway connection error: {exc.reason} (are you on VPN / on-network?)"
                ) from exc
        raise GatewayError("Gateway request failed after retries")


_shared_transport: Optional[GatewayTransport] = None
_shared_base_url: str = ""
_shared_lock = threading.Lock()


def get_shared_transport(base_url: str = "") -> GatewayTransport:
    """Return a process-wide GatewayTransport, creating it on first use.

    Rebuilds when the configured base URL changes (the operator switched the
    gateway endpoint at runtime). A single instance means one token and one
    refresh shared across all callers.
    """
    global _shared_transport, _shared_base_url
    resolved = (base_url or "").strip()
    if _shared_transport is not None and resolved == _shared_base_url:
        return _shared_transport
    with _shared_lock:
        if _shared_transport is None or resolved != _shared_base_url:
            _shared_transport = GatewayTransport(base_url=resolved)
            _shared_base_url = resolved
        return _shared_transport
