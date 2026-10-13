"""
interactsh client — OOB callback server for SSRF/XXE/blind injection confirmation.

Uses the ProjectDiscovery public servers (oast.pro, oast.live, oast.site, oast.me).
No installation required. Token configured via INTERACTSH_TOKEN in .env.

Protocol:
  POST /register  { public-key (RSA-2048 PEM base64), secret-key (UUID), correlation-id (20 hex) }
  → 200 { "message": "registration successful" }   (domain = server hostname)
  GET  /poll?id=<correlation-id>&secret=<secret-key>
  → 200 { data: [<base64 AES-CTR>], aes_key: <RSA-OAEP encrypted>, extra: [...] }
  POST /deregister { correlation-id, secret-key }

Decrypt flow:
  RSA-OAEP(private_key, aes_key_b64) → 32-byte AES key
  AES-256-CTR(iv=first_16_bytes, ciphertext=rest) → plaintext interaction JSON
"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_PUBLIC_SERVERS = ["https://oast.pro", "https://oast.live", "https://oast.site", "https://oast.me"]

# zbase32 alphabet used by xid / interactsh for correlation IDs and nonces.
_ZBASE32 = "0123456789abcdefghijklmnopqrstuv"


def _xid_token(length: int) -> str:
    """Generate a random string of `length` chars from the zbase32 alphabet."""
    return "".join(secrets.choice(_ZBASE32) for _ in range(length))


def _decrypt_entries(private_key: Any, aes_key_b64: str, encrypted_entries: List[str]) -> List[str]:
    """Decrypt polled interactions: RSA-OAEP(aes_key) then AES-256-CTR per entry."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    aes_key = private_key.decrypt(
        base64.b64decode(aes_key_b64),
        _pad.OAEP(mgf=_pad.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    texts: List[str] = []
    for entry_b64 in encrypted_entries:
        raw = base64.b64decode(entry_b64)
        iv, ciphertext = raw[:16], raw[16:]
        decryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        if plaintext:
            texts.append(plaintext.decode("utf-8", errors="replace"))
    return texts


def _parse_interaction(text: Any) -> Dict[str, Any]:
    """Parse one interaction (JSON text, or already a dict); keep unparseable text raw."""
    if isinstance(text, dict):
        return text
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        logger.debug("interactsh interaction is not JSON", error=str(exc))
    return {"protocol": "unknown", "raw-request": str(text)}


class InteractshSession:
    """
    Async interactsh OOB session.

    Usage:
        session = InteractshSession()
        registered = await session.register()
        if registered:
            # inject session.url into the target as the callback URL
            hit = await session.poll()
            await session.deregister()
    """

    def __init__(self) -> None:
        self._server: str = ""
        self._correlation_id: str = ""
        self._secret_key: str = ""
        self._domain: str = ""
        self._private_key = None
        self._headers: dict = {}
        # Set by the Interactions store when a callback is received.
        # External callers (H1 validator, SSRF agent) wait on this instead of
        # polling themselves, avoiding two pollers racing for the same data.
        self.hit_event: asyncio.Event = asyncio.Event()
        self._url: str = ""  # fixed after register(), never regenerated

    async def register(self) -> bool:
        """
        Register a unique OOB subdomain. Tries public servers in order.
        Returns True on success.
        """
        import httpx
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_b64 = base64.b64encode(pub_pem).decode()
        self._secret_key = str(uuid.uuid4())
        # interactsh expects a 20-char xid-style correlation-id using the
        # zbase32 alphabet [0-9a-v]. token_hex produces only [0-9a-f] which
        # fails the server's isCorrelationID() check — use the full alphabet.
        self._correlation_id = _xid_token(20)

        payload = {
            "public-key": pub_b64,
            "secret-key": self._secret_key,
            "correlation-id": self._correlation_id,
        }

        from dast.config import settings as _cfg
        token = _cfg.interactsh_token or ""
        headers = {"Authorization": token} if token else {}

        custom = getattr(_cfg, "interactsh_server", None)
        servers = ([custom.rstrip("/")] if custom else []) + _PUBLIC_SERVERS

        async def _try_register(server: str) -> Optional[str]:
            """Return the resolved domain on success, else None."""
            async with httpx.AsyncClient(timeout=8, verify=False, headers=headers) as client:
                r = await client.post(f"{server}/register", json=payload)
                if r.status_code != 200:
                    return None
                data = r.json()
                # Newer API returns only {"message": "registration successful"} —
                # domain is derived from the server hostname.
                return data.get("domain", "") or urlparse(server).hostname or ""

        # Probe every server concurrently and take the FIRST that registers.
        # Sequential probing wasted up to ~8s per unreachable public server
        # (DNS timeout) before reaching a live one; racing them keeps
        # registration bounded by the fastest reachable server.
        tasks = {asyncio.ensure_future(_try_register(s)): s for s in servers}
        winner_server = ""
        winner_domain = ""
        try:
            pending = set(tasks)
            while pending and not winner_domain:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    server = tasks[task]
                    try:
                        domain = task.result()
                    except Exception as exc:
                        logger.debug("interactsh register failed", server=server, error=str(exc))
                        continue
                    if domain:
                        winner_server, winner_domain = server, domain
                        break
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

        if winner_domain:
            self._domain = winner_domain
            self._server = winner_server
            self._headers = headers
            # Generate URL once and fix it — nonce must not change between calls
            nonce = _xid_token(13)
            self._url = f"http://{self._correlation_id}{nonce}.{winner_domain}"
            logger.info("interactsh registered", server=winner_server,
                        domain=winner_domain, url=self._url)
            return True

        logger.warning("interactsh unavailable — all servers failed")
        return False

    @property
    def url(self) -> str:
        """Fixed OOB callback URL — generated once in register(), never changes."""
        return self._url

    def marker_host(self, marker: str) -> str:
        """A hostname that routes to this session and carries ``marker`` as its own label.

        interactsh matches the correlation-id label anywhere in the queried name
        and reports the whole subdomain as the interaction's ``full-id``, so
        ``<marker>.<correlation-id><nonce>.<domain>`` lets a caller inject many
        distinct values through one session and attribute every callback to the
        exact injection that produced it. Returns "" before register().
        """
        host = urlparse(self._url).hostname if self._url else ""
        return f"{marker}.{host}" if host else ""

    async def fetch_interactions(self) -> List[Dict[str, Any]]:
        """Poll once and return the interactions received since the last poll.

        Each item is interactsh's interaction object: ``protocol`` ("dns",
        "http", "smtp", ...), ``unique-id``, ``full-id`` (the full subdomain that
        was queried), ``q-type``, ``raw-request``, ``remote-address`` and
        ``timestamp``. The server deletes interactions once polled, so only one
        poller may own a session. Returns [] on any error — polling is periodic
        and best-effort, so a failed round is retried by the caller's loop.
        """
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10, verify=False, headers=self._headers) as client:
                response = await client.get(
                    f"{self._server}/poll",
                    params={"id": self._correlation_id, "secret": self._secret_key},
                )
            if response.status_code != 200:
                logger.debug("interactsh poll non-200", status=response.status_code)
                return []
            data = response.json()
        except Exception as exc:
            logger.debug("interactsh poll error", error=str(exc))
            return []

        interactions = [_parse_interaction(text) for text in (data.get("extra") or [])]
        encrypted_entries = data.get("data") or []
        aes_key_b64 = data.get("aes_key", "")
        if encrypted_entries and aes_key_b64 and self._private_key:
            try:
                for text in _decrypt_entries(self._private_key, aes_key_b64, encrypted_entries):
                    interactions.append(_parse_interaction(text))
            except Exception as exc:
                logger.warning("interactsh poll decrypt failed", error=str(exc))
        return interactions

    async def poll(self) -> bool:
        """
        Poll once for interactions. Returns True if any callback was received.
        For long-running polls use poll_for(seconds).
        """
        return bool(await self.fetch_interactions())

    async def poll_for(self, seconds: int, interval: int = 5) -> bool:
        """
        Poll repeatedly for up to `seconds`. Returns True as soon as a hit is received.
        """
        for _ in range(max(1, seconds // interval)):
            await asyncio.sleep(interval)
            if await self.poll():
                return True
        return False

    async def deregister(self) -> None:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5, verify=False, headers=self._headers) as client:
                await client.post(
                    f"{self._server}/deregister",
                    json={"correlation-id": self._correlation_id, "secret-key": self._secret_key},
                )
        except Exception as exc:
            logger.debug("interactsh deregister failed", server=self._server, error=str(exc))
