"""
Login profiles — encrypted per-site login configuration.

A LoginProfile binds a target host to how Frieren should authenticate to it:
  - one or more credential sets (username + secret),
  - an optional recorded login flow (Phase 2),
  - an optional saved browser session (Playwright storage_state).

Sensitive fields (credential secrets, saved-session cookies/tokens) are encrypted
at rest with a random key held in a 0600 key file under ~/.dast-ai/profiles/.key.
Non-sensitive metadata (name, host pattern, auth URL) is stored in the clear so the
profile list can be rendered without decryption.

This package is intentionally self-contained: it owns its own on-disk format and
crypto, and exposes a thin CRUD surface consumed by dast/proxy/api/profiles_routes.py.
"""

from dast.profiles.models import Credential, LoginProfile
from dast.profiles.store import (
    delete_profile,
    list_profiles,
    load_profile,
    resolve_for_host,
    save_profile,
)

__all__ = [
    "Credential",
    "LoginProfile",
    "save_profile",
    "load_profile",
    "list_profiles",
    "delete_profile",
    "resolve_for_host",
]
