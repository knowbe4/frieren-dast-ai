"""
Login-profile persistence — one JSON file per profile under ~/.dast-ai/profiles/.

File name: <slug>.json (see profiles/crypto.profiles_dir()). Secrets inside are
encrypted; everything here is plain file IO plus (de)serialization via the model.
CRUD never raises to the caller — failures are logged and surfaced as None/False.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import List, Optional

from dast.profiles.crypto import profiles_dir
from dast.profiles.models import LoginProfile, host_from_url, slugify
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def _path_for(slug: str) -> Path:
    return profiles_dir() / f"{slug}.json"


def save_profile(profile: LoginProfile) -> LoginProfile:
    """Persist a profile (assigning a slug if missing) and return it."""
    if not profile.slug:
        profile.slug = slugify(profile.name)
    profile.updated_at = time.time()
    path = _path_for(profile.slug)
    path.write_text(json.dumps(profile.to_storage_dict(), indent=2))
    logger.info("login profile saved", slug=profile.slug, host_pattern=profile.host_pattern)
    return profile


def load_profile(slug: str) -> Optional[LoginProfile]:
    path = _path_for(slug)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return LoginProfile.from_storage_dict(data)
    except Exception as exc:
        logger.error("could not load login profile", slug=slug, error=str(exc))
        return None


def list_profiles() -> List[LoginProfile]:
    """Return all profiles, newest first. Skips unreadable files with a log."""
    result: List[LoginProfile] = []
    for f in profiles_dir().glob("*.json"):
        try:
            result.append(LoginProfile.from_storage_dict(json.loads(f.read_text())))
        except Exception as exc:
            logger.warning("skipping unreadable login profile", file=f.name, error=str(exc))
    return sorted(result, key=lambda p: p.updated_at, reverse=True)


def delete_profile(slug: str) -> bool:
    path = _path_for(slug)
    if path.exists():
        path.unlink()
        logger.info("login profile deleted", slug=slug)
        return True
    return False


def resolve_for_host(host_or_url: str) -> Optional[LoginProfile]:
    """Find the profile governing a host (or URL). Returns None if none matches.

    On multiple matches, prefer the most specific host_pattern (longest wins),
    so "*.stg.example.com" beats a broad "example.com".
    """
    host = host_from_url(host_or_url) or (host_or_url or "").lower().strip()
    if not host:
        return None
    matches = [p for p in list_profiles() if p.matches_host(host)]
    if not matches:
        return None
    return max(matches, key=lambda p: len(p.host_pattern))
