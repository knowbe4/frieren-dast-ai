"""
Out-of-band (OOB) callback client used by the HackerOne SSRF validator.

interactsh is an open-source OOB interaction server by ProjectDiscovery. It
provides a public HTTP API to register a unique subdomain and poll for
callbacks — no local listener, no ngrok, no AWS infra needed.
API docs: https://github.com/projectdiscovery/interactsh

NOTE: this is intentionally NOT ``dast.utils.interactsh.InteractshSession``.
The two clients are not behaviorally equivalent, so swapping one for the other
would change what the H1 SSRF validator does on the wire:

  - registration: this client sends a random hex string as ``public-key`` (not
    an RSA-2048 PEM), a hex correlation-id, and requires the server to return a
    ``domain`` field; the utils client sends a real RSA public key, a zbase32
    correlation-id, derives the domain from the server hostname, races four
    public servers plus the configured ``interactsh_server`` and sends
    ``interactsh_token``.
  - callback URL: ``http://<correlation-id>.<domain>`` here versus
    ``http://<correlation-id><nonce>.<domain>`` in the utils client.
  - polling: this client counts raw ``data`` entries; the utils client decrypts
    them (RSA-OAEP + AES-CTR) and also honours ``extra``.
  - timeouts: register 10s here versus 8s per server in the utils client.

Against current interactsh servers the registration here is expected to fail
(no valid RSA key, no ``domain`` in the response), which routes the validator
to its "interactsh unreachable" manual-review path. Migrating to the utils
client is a deliberate behavior change and should be done (and tested) as such.
"""

from __future__ import annotations

import asyncio
import secrets

from dast.utils.logger import get_logger

logger = get_logger(__name__)

INTERACTSH_SERVER = "oast.pro"
INTERACTSH_API = "https://oast.pro"

_REGISTER_TIMEOUT_SECONDS = 10
_POLL_TIMEOUT_SECONDS = 10
_DEREGISTER_TIMEOUT_SECONDS = 5


class H1InteractshSession:
    """Thin async wrapper around the interactsh HTTP API."""

    def __init__(self, server: str = INTERACTSH_API) -> None:
        self._server = server.rstrip("/")
        self._correlation_id: str = ""
        self._secret_key: str = ""
        self._domain: str = ""

    async def register(self) -> bool:
        """Register a new interaction subdomain. Returns True on success."""
        try:
            import httpx

            self._secret_key = secrets.token_hex(16)
            self._correlation_id = secrets.token_hex(10)  # 20 hex chars
            registration_payload = {
                "public-key": self._secret_key,
                "secret-key": self._secret_key,
                "correlation-id": self._correlation_id,
            }
            async with httpx.AsyncClient(timeout=_REGISTER_TIMEOUT_SECONDS, verify=False) as client:
                response = await client.post(f"{self._server}/register", json=registration_payload)
                if response.status_code == 200:
                    self._domain = response.json().get("domain", "")
                    return bool(self._domain)
        except Exception as exc:
            logger.debug("H1 interactsh registration failed", server=self._server, error=str(exc))
        return False

    @property
    def url(self) -> str:
        """Returns the unique OOB URL to use as SSRF payload."""
        if not self._domain:
            return ""
        return f"http://{self._correlation_id}.{self._domain}"

    async def poll(self) -> bool:
        """Poll once for interactions. Returns True if any callback was received."""
        try:
            import httpx

            async with httpx.AsyncClient(timeout=_POLL_TIMEOUT_SECONDS, verify=False) as client:
                response = await client.get(
                    f"{self._server}/poll",
                    params={"id": self._correlation_id, "secret": self._secret_key},
                )
                if response.status_code == 200:
                    interactions = response.json().get("data") or []
                    return len(interactions) > 0
        except Exception as exc:
            logger.debug("H1 interactsh poll failed", server=self._server, error=str(exc))
        return False

    async def poll_for(self, seconds: int, interval: int = 5) -> bool:
        """Poll every ``interval`` seconds for up to ``seconds``; True on the first hit."""
        for _ in range(max(1, seconds // interval)):
            await asyncio.sleep(interval)
            if await self.poll():
                return True
        return False

    async def deregister(self) -> None:
        """Release the correlation id on the server (best effort)."""
        try:
            import httpx

            async with httpx.AsyncClient(timeout=_DEREGISTER_TIMEOUT_SECONDS, verify=False) as client:
                await client.post(
                    f"{self._server}/deregister",
                    json={"correlation-id": self._correlation_id, "secret-key": self._secret_key},
                )
        except Exception as exc:
            logger.debug("H1 interactsh deregister failed", server=self._server, error=str(exc))
