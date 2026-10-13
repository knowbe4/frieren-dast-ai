"""
Out-of-band (OOB) injection correlator for deterministic, no-AI checks.

One interactsh session is shared by every injection a component makes. Each
injection gets a unique marker label, so the OOB hostname it carries is
``<marker>.<correlation-id><nonce>.<oob-domain>``. interactsh reports the full
queried subdomain of every DNS / HTTP interaction, which names the marker — so a
callback is attributed to the exact request + location (header, param) that
produced it, with no guessing and no LLM. That attribution is what lets a plugin
confirm a blind vulnerability deterministically.

The correlator owns its session and is its only poller (interactsh deletes
interactions once polled). Received interactions are mirrored to a display-only
session in the Interactions tab so the operator can inspect the raw DNS / HTTP
callbacks.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Lowercase alphanumerics: DNS labels are case-insensitive, so a marker must be
# matched case-insensitively and cannot rely on case to be unique.
_MARKER_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_MARKER_LENGTH = 12
_MARKER_PREFIX = "fr"

# Keep polling this long after the newest injection: log pipelines, analytics
# and queued workers often resolve a header value minutes after the request.
DEFAULT_LINGER_SECONDS = 600
DEFAULT_POLL_INTERVAL_SECONDS = 5
# Injections older than this are forgotten (bounds memory on long sessions).
_INJECTION_TTL_SECONDS = 6 * 3600


@dataclass
class OobInjection:
    """One value carrying a unique OOB marker, sent in one place of one request."""

    marker: str
    entry_id: str
    url: str
    method: str
    location: str      # "header", "query", "body", ...
    name: str          # header / parameter name
    value: str         # the exact value sent
    sent_at: float
    reflected: bool = False  # the value came back in the probe response body


@dataclass
class OobHit:
    """An interaction attributed to an injection by its marker."""

    injection: OobInjection
    protocol: str                  # "dns", "http", "smtp", ... (lowercase)
    interaction: Dict[str, Any]    # interactsh's interaction object


HitHandler = Callable[[OobHit], Awaitable[None]]


def _new_marker() -> str:
    return _MARKER_PREFIX + "".join(secrets.choice(_MARKER_ALPHABET) for _ in range(_MARKER_LENGTH))


def interaction_labels(interaction: Dict[str, Any]) -> List[str]:
    """Lowercase DNS labels of the subdomain an interaction was received on."""
    labels: List[str] = []
    for key in ("full-id", "unique-id"):
        value = interaction.get(key)
        if isinstance(value, str) and value:
            labels.extend(label for label in value.lower().split(".") if label)
    return labels


def _default_session_factory() -> Any:
    from dast.utils.interactsh import InteractshSession
    return InteractshSession()


class OobCorrelator:
    """Shared OOB session + marker registry + poll loop for one component."""

    def __init__(
        self,
        label: str,
        on_hit: HitHandler,
        poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
        linger_seconds: float = DEFAULT_LINGER_SECONDS,
        session_factory: Optional[Callable[[], Any]] = None,
    ) -> None:
        self._label = label
        self._on_hit = on_hit
        self._poll_interval = poll_interval
        self._linger_seconds = linger_seconds
        self._session_factory = session_factory or _default_session_factory
        self._session: Any = None
        self._display_session_id: Optional[str] = None
        self._injections: Dict[str, OobInjection] = {}
        self._reported: Set[Tuple[str, str]] = set()   # (marker, protocol) already handled
        self._last_injection_at = 0.0
        self._poll_task: Optional[asyncio.Task] = None
        self._start_lock = asyncio.Lock()
        self._unavailable = False

    @property
    def available(self) -> bool:
        """False once registration has failed (no OOB server reachable)."""
        return not self._unavailable

    async def start(self) -> bool:
        """Register the OOB session once; return True when it is usable."""
        if self._session is not None:
            return True
        if self._unavailable:
            return False
        async with self._start_lock:
            if self._session is not None:
                return True
            session = self._session_factory()
            try:
                registered = await session.register()
            except Exception as exc:
                logger.warning("OOB session registration failed", label=self._label, error=str(exc))
                registered = False
            if not registered:
                self._unavailable = True
                logger.warning("OOB server unreachable; OOB checks disabled", label=self._label)
                return False
            self._session = session
            self._display_session_id = self._register_display(session.url)
            logger.info("OOB correlator ready", label=self._label, url=session.url)
            return True

    def _register_display(self, oob_url: str) -> Optional[str]:
        """Show this session's callbacks in the Interactions tab (best effort)."""
        try:
            from dast.proxy.api import interactions_routes
            return interactions_routes.register_display_session(oob_url, label=self._label)
        except Exception as exc:
            logger.warning("OOB display session not registered", label=self._label, error=str(exc))
            return None

    def new_injection(
        self, entry_id: str, url: str, method: str, location: str, name: str, template: str,
    ) -> Optional[OobInjection]:
        """Mint a unique marker and render ``template`` ({{OOB_HOST}} placeholder).

        Returns None until start() has succeeded. The caller sends ``value`` and
        then calls track() so the poll loop keeps running for it.
        """
        if self._session is None:
            return None
        marker = _new_marker()
        value = template.replace("{{OOB_HOST}}", self._session.marker_host(marker))
        injection = OobInjection(
            marker=marker, entry_id=entry_id, url=url, method=method.upper(),
            location=location, name=name, value=value, sent_at=time.time(),
        )
        self._injections[marker] = injection
        return injection

    def track(self) -> None:
        """Record that injections were just sent; (re)start the poll loop if idle."""
        self._last_injection_at = time.time()
        self._forget_expired()
        if self._poll_task is None or self._poll_task.done():
            from dast.utils.tasks import spawn_tracked
            self._poll_task = spawn_tracked(self._poll_loop(), name=f"oob-poll-{self._label}")

    def _forget_expired(self) -> None:
        cutoff = time.time() - _INJECTION_TTL_SECONDS
        for marker in [m for m, inj in self._injections.items() if inj.sent_at < cutoff]:
            self._injections.pop(marker, None)

    def match(self, interaction: Dict[str, Any]) -> Optional[OobInjection]:
        """The injection whose marker labels the subdomain this interaction hit."""
        for label in interaction_labels(interaction):
            injection = self._injections.get(label)
            if injection is not None:
                return injection
        return None

    async def poll_once(self) -> int:
        """Fetch interactions, attribute them, notify the handler. Returns hits handled."""
        if self._session is None:
            return 0
        interactions = await self._session.fetch_interactions()
        if not interactions:
            return 0
        await self._publish(interactions)
        handled = 0
        for interaction in interactions:
            injection = self.match(interaction)
            if injection is None:
                logger.debug("OOB interaction without a known marker", label=self._label)
                continue
            protocol = str(interaction.get("protocol") or "unknown").lower()
            key = (injection.marker, protocol)
            if key in self._reported:
                continue
            self._reported.add(key)
            try:
                await self._on_hit(OobHit(injection=injection, protocol=protocol, interaction=interaction))
                handled += 1
            except Exception as exc:
                logger.warning("OOB hit handler failed", label=self._label,
                               marker=injection.marker, error=str(exc))
        return handled

    async def _publish(self, interactions: List[Dict[str, Any]]) -> None:
        if not self._display_session_id:
            return
        try:
            from dast.proxy.api import interactions_routes
            await interactions_routes.publish_callbacks(self._display_session_id, interactions)
        except Exception as exc:
            logger.warning("OOB callbacks not published", label=self._label, error=str(exc))

    async def _poll_loop(self) -> None:
        """Poll until linger_seconds have passed since the newest injection."""
        while time.time() - self._last_injection_at < self._linger_seconds:
            await asyncio.sleep(self._poll_interval)
            try:
                await self.poll_once()
            except Exception as exc:
                logger.warning("OOB poll round failed", label=self._label, error=str(exc))
        logger.debug("OOB poll loop idle", label=self._label)

    async def stop(self) -> None:
        """Final poll, stop the loop and release the OOB session."""
        if self._poll_task is not None and not self._poll_task.done():
            self._poll_task.cancel()
        if self._session is None:
            return
        try:
            await self.poll_once()
        except Exception as exc:
            logger.warning("OOB final poll failed", label=self._label, error=str(exc))
        try:
            await self._session.deregister()
        except Exception as exc:
            logger.warning("OOB deregister failed", label=self._label, error=str(exc))
        self._session = None