"""
Login-profile data model.

In memory, secrets live in the clear (a profile that has been loaded is ready to
use). Serialization to disk encrypts the sensitive fields via dast.profiles.crypto;
the public API view (to_public_dict) never exposes secrets — only ``*_set`` booleans,
mirroring the key-masking convention of GET /api/scan-config.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from dast.profiles import crypto
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def slugify(name: str) -> str:
    """Filesystem-safe slug from a profile name."""
    slug = re.sub(r"[^\w\-]", "-", (name or "").lower().strip())
    slug = re.sub(r"-+", "-", slug).strip("-")[:60]
    return slug or "profile"


@dataclass
class Credential:
    """A single username + secret pair. ``secret`` is plaintext in memory only."""
    label: str = "default"
    username: str = ""
    secret: str = ""

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "username": self.username,
            "secret_set": bool(self.secret),
        }

    def to_storage_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "username": self.username,
            "secret_enc": crypto.encrypt(self.secret) if self.secret else "",
        }

    @classmethod
    def from_storage_dict(cls, d: Dict[str, Any]) -> "Credential":
        return cls(
            label=str(d.get("label", "default")),
            username=str(d.get("username", "")),
            secret=crypto.decrypt(d.get("secret_enc", "")),
        )


@dataclass
class LoginProfile:
    """How Frieren authenticates to one target site."""
    slug: str = ""
    name: str = ""
    host_pattern: str = ""          # regex OR plain host/suffix (e.g. "*.example.com")
    auth_url: str = ""
    credentials: List[Credential] = field(default_factory=list)
    selector_overrides: Dict[str, str] = field(default_factory=dict)
    login_flow_id: Optional[str] = None       # reserved for external flow linking
    login_flow: Optional[Dict[str, Any]] = None  # Phase 2: inline recorded LoginFlow dict
    saved_session: Optional[Dict[str, Any]] = None  # Playwright storage_state
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    # ── Host matching ──────────────────────────────────────────────────────
    def matches_host(self, host: str) -> bool:
        """True if ``host`` is governed by this profile.

        ``host_pattern`` is matched flexibly: as a wildcard suffix ("*.foo.com"),
        an exact host, a dotted-suffix, or — as a last resort — a regex search.
        """
        if not host or not self.host_pattern:
            return False
        host = host.lower().strip()
        pat = self.host_pattern.lower().strip()
        if pat.startswith("*."):
            base = pat[2:]
            return host == base or host.endswith("." + base)
        if pat == host or host.endswith("." + pat):
            return True
        try:
            return re.search(pat, host) is not None
        except re.error:
            return False

    # ── Serialization ────────────────────────────────────────────────────────
    def to_public_dict(self) -> Dict[str, Any]:
        """Redacted view for the API/UI — no secrets, only ``*_set`` booleans."""
        return {
            "slug": self.slug,
            "name": self.name,
            "host_pattern": self.host_pattern,
            "auth_url": self.auth_url,
            "credentials": [c.to_public_dict() for c in self.credentials],
            "selector_overrides": dict(self.selector_overrides),
            "login_flow_id": self.login_flow_id,
            "flow_set": bool(self.login_flow and self.login_flow.get("steps")),
            "flow_step_count": len((self.login_flow or {}).get("steps", [])),
            "session_set": bool(self.saved_session),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def to_storage_dict(self) -> Dict[str, Any]:
        """On-disk form: metadata plaintext, secrets + saved_session encrypted."""
        session_enc = ""
        if self.saved_session:
            try:
                session_enc = crypto.encrypt(json.dumps(self.saved_session))
            except Exception as exc:  # never let a bad session block the save
                logger.error("could not encrypt saved session", error=str(exc))
        return {
            "slug": self.slug,
            "name": self.name,
            "host_pattern": self.host_pattern,
            "auth_url": self.auth_url,
            "credentials": [c.to_storage_dict() for c in self.credentials],
            "selector_overrides": dict(self.selector_overrides),
            "login_flow_id": self.login_flow_id,
            "login_flow": self.login_flow,
            "saved_session_enc": session_enc,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_storage_dict(cls, d: Dict[str, Any]) -> "LoginProfile":
        saved_session: Optional[Dict[str, Any]] = None
        enc = d.get("saved_session_enc", "")
        if enc:
            raw = crypto.decrypt(enc)
            if raw:
                try:
                    saved_session = json.loads(raw)
                except json.JSONDecodeError as exc:
                    logger.error("saved session not valid JSON", error=str(exc))
        return cls(
            slug=str(d.get("slug", "")),
            name=str(d.get("name", "")),
            host_pattern=str(d.get("host_pattern", "")),
            auth_url=str(d.get("auth_url", "")),
            credentials=[Credential.from_storage_dict(c) for c in d.get("credentials", [])],
            selector_overrides=dict(d.get("selector_overrides", {})),
            login_flow_id=d.get("login_flow_id"),
            login_flow=d.get("login_flow"),
            saved_session=saved_session,
            created_at=float(d.get("created_at", time.time())),
            updated_at=float(d.get("updated_at", time.time())),
        )


def host_from_url(url: str) -> str:
    """Best-effort host extraction from a URL or bare host string."""
    try:
        parsed = urlparse(url if "://" in url else f"//{url}")
        return (parsed.hostname or "").lower()
    except Exception:
        return ""
