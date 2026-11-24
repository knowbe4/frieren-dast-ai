"""OAuth client-credentials vault — client_id/secret pairs per IDP host.

Round 4-G: the oauth_agent's code-reuse check redeems authorization codes at
the token endpoint, but confidential clients require client authentication
(client_id + client_secret) — without them the check silently can't confirm
reuse on the most common deployments. This store keeps those pairs, one file
per IDP host under ``~/.dast-ai/oauth_clients/`` (0700), with the secret
Fernet-encrypted at rest using the same key material as the login profiles
(``dast.profiles.crypto`` — ``DAST_PROFILES_KEY``).

Trust note: these credentials let a holder redeem intercepted codes — they
are operator-provided TEST credentials by the same policy as the login
profiles' TOTP seeds. The plaintext secret NEVER leaves this module except
through ``credentials_for_host`` (used only by the agent's exchange request)
and is excluded from every dict/read API (masked as ``client_secret_set``).
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from dast.profiles.crypto import decrypt, encrypt
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_OAUTH_DIR = Path.home() / ".dast-ai" / "oauth_clients"
_lock = threading.Lock()


@dataclass
class OAuthClient:
    host: str
    client_id: str
    client_secret: str = ""


def _host_of(host_or_url: str) -> str:
    if "://" in (host_or_url or ""):
        return urlparse(host_or_url).hostname or ""
    return host_or_url or ""


def _slug(host_or_url: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]", "_", _host_of(host_or_url).strip().lower())
    return slug or "unknown"


def _path_for(slug: str) -> Path:
    _OAUTH_DIR.mkdir(parents=True, exist_ok=True)
    try:
        _OAUTH_DIR.chmod(0o700)
    except OSError as exc:
        logger.warning("could not chmod oauth_clients dir", error=str(exc))
    return _OAUTH_DIR / f"{slug}.json"


def set_for_host(host_or_url: str, client_id: str, client_secret: str) -> None:
    """Store (or replace) the client credentials for one IDP host."""
    host = (_host_of(host_or_url) or host_or_url).strip().lower()
    slug = _slug(host)
    data = {
        "host": host,
        "client_id": client_id.strip(),
        "client_secret_enc": encrypt(client_secret.strip()),
    }
    with _lock:
        path = _path_for(slug)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError as exc:
            logger.warning("could not chmod oauth client file", path=str(path), error=str(exc))
    logger.info("OAuth client credentials stored", host=host)


def _urlparse_host(host_or_url: str) -> str:
    from urllib.parse import urlparse
    if "://" in (host_or_url or ""):
        return urlparse(host_or_url).hostname or ""
    return host_or_url


def remove_for_host(host_or_url: str) -> None:
    slug = _slug(host_or_url)
    with _lock:
        path = _path_for(slug)
        if path.exists():
            path.unlink()


def credentials_for_host(host_or_url: str) -> Optional[OAuthClient]:
    """The stored client credentials for a host (plaintext secret — the ONLY
    consumer is the agent's token-exchange request). None when absent."""
    slug = _slug(host_or_url)
    path = _path_for(slug)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        client_id = str(data.get("client_id", ""))
        secret = decrypt(str(data.get("client_secret_enc", "")))
        if not client_id or not secret:
            return None
        return OAuthClient(host=str(data.get("host", slug)),
                           client_id=client_id, client_secret=secret)
    except Exception as exc:
        logger.warning("oauth client credentials unreadable", slug=slug, error=str(exc))
        return None


def list_hosts() -> List[Dict[str, object]]:
    """All stored hosts with masked secrets (client_id visible, secret only as
    a *_set boolean) — safe for the dashboard."""
    out: List[Dict[str, object]] = []
    with _lock:
        slugs = [p.stem for p in _OAUTH_DIR.glob("*.json")]
    for slug in sorted(slugs):
        path = _path_for(slug)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        out.append({"host": data.get("host", slug),
                    "client_id": data.get("client_id", ""),
                    "client_secret_set": bool(data.get("client_secret_enc", ""))})
    return out


def reset() -> None:
    """Remove every stored client (test isolation)."""
    with _lock:
        for p in _OAUTH_DIR.glob("*.json"):
            try:
                p.unlink()
            except OSError:
                pass
