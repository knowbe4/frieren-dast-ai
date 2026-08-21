"""
Bring-your-own-session import.

Turns an operator-supplied active session into a normalized form Frieren can use
WITHOUT performing a login. Three input shapes are accepted, in priority order:

  1. storage_state JSON  — a full Playwright storage_state ({"cookies": [...], ...})
  2. cookie header       — a raw "k=v; k2=v2" Cookie-header string
  3. auth token          — an Authorization header value (e.g. "Bearer eyJ...")

Output: an ImportedSession with Playwright-shaped cookie dicts, auth_headers, and a
storage_state dict suitable for LoginProfile.saved_session and for
SessionStore.save_named_session_from_playwright / import_playwright_cookies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any, Dict, List, Optional

from dast.profiles.models import host_from_url
from dast.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ImportedSession:
    cookies: List[Dict[str, Any]] = field(default_factory=list)   # Playwright cookie dicts
    auth_headers: Dict[str, str] = field(default_factory=dict)
    storage_state: Dict[str, Any] = field(default_factory=lambda: {"cookies": [], "origins": []})

    @property
    def is_empty(self) -> bool:
        return not self.cookies and not self.auth_headers


def _cookie_header_to_cookies(cookie_str: str, domain: str) -> List[Dict[str, Any]]:
    """Parse a raw Cookie-header string into Playwright cookie dicts."""
    jar = SimpleCookie()
    cookies: List[Dict[str, Any]] = []
    try:
        jar.load(cookie_str)
    except Exception as exc:
        logger.warning("could not parse cookie header", error=str(exc))
        return cookies
    for name, morsel in jar.items():
        cookies.append({
            "name": name,
            "value": morsel.value,
            "domain": domain,
            "path": "/",
            "secure": True,
            "httpOnly": False,
        })
    return cookies


def _validate_storage_state(raw: str) -> Optional[Dict[str, Any]]:
    """Parse and lightly validate a Playwright storage_state JSON string."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("storage_state not valid JSON", error=str(exc))
        return None
    if not isinstance(data, dict) or "cookies" not in data:
        logger.warning("storage_state missing 'cookies' key")
        return None
    return data


def build_session(
    *,
    target_url: str = "",
    storage_state_json: str = "",
    cookie_header: str = "",
    auth_token: str = "",
) -> ImportedSession:
    """Normalize whichever session inputs were supplied into an ImportedSession."""
    domain = host_from_url(target_url)
    result = ImportedSession()

    if storage_state_json.strip():
        ss = _validate_storage_state(storage_state_json)
        if ss is not None:
            result.storage_state = ss
            result.cookies = list(ss.get("cookies", []))

    if not result.cookies and cookie_header.strip():
        result.cookies = _cookie_header_to_cookies(cookie_header, domain)
        result.storage_state = {"cookies": result.cookies, "origins": []}

    token = auth_token.strip()
    if token:
        if token.lower().startswith(("bearer ", "basic ", "token ")):
            result.auth_headers["Authorization"] = token
        else:
            result.auth_headers["Authorization"] = f"Bearer {token}"

    if result.is_empty:
        logger.warning("session import produced no cookies or auth headers")
    else:
        logger.info(
            "session imported",
            cookies=len(result.cookies),
            has_auth=bool(result.auth_headers),
            domain=domain,
        )
    return result
