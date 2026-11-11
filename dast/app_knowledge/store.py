"""Local, per-host "app knowledge" store.

A plain-markdown note file per target host under ``~/.dast-ai/app_knowledge/`` — OUTSIDE the
repository (never committed, not even gitignored) — holding what Frieren has learned about an
application (auth model, where tokens live, endpoints, entitlements) so the copilot can reuse it
instead of re-discovering it every run. Mirrors the local-file-store pattern of
``dast/profiles/`` (``profiles_dir`` 0700 + a host resolver).

The content is operator/copilot-authored from observations of the target, so consumers MUST treat
it as untrusted when injecting it into a prompt (the context brief wraps it with
``prompt_safety.wrap_untrusted``).
"""

from __future__ import annotations

import stat
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_KNOWLEDGE_DIR = Path.home() / ".dast-ai" / "app_knowledge"
_MAX_LOAD_CHARS = 3000  # keep a single host's block well under the context-brief budget


def knowledge_dir() -> Path:
    """Return the app-knowledge directory, creating it 0700 if missing."""
    _KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        _KNOWLEDGE_DIR.chmod(stat.S_IRWXU)  # 0700
    except OSError as exc:
        logger.warning("could not chmod app_knowledge dir", error=str(exc))
    return _KNOWLEDGE_DIR


def _normalise_host(host_or_url: str) -> str:
    """Bare lowercase hostname from a host or URL (no scheme, no port)."""
    value = (host_or_url or "").strip()
    if not value:
        return ""
    if "://" in value:
        value = urlparse(value).hostname or ""
    else:
        value = value.split("/", 1)[0]
    return value.split(":", 1)[0].lower().strip()


def _path_for(host: str) -> Path:
    return knowledge_dir() / f"{host}.md"


def load_for_host(host_or_url: str) -> str:
    """Return the knowledge note for a host, or "" if none.

    Tries the exact host first, then each parent domain (longest match wins), so a note filed
    under ``app.example.com`` also serves ``api.app.example.com``."""
    host = _normalise_host(host_or_url)
    if not host:
        return ""
    labels = host.split(".")
    # exact host, then progressively broader parent domains (but not a bare TLD)
    candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    for candidate in candidates:
        path = _path_for(candidate)
        if path.is_file():
            try:
                return path.read_text(encoding="utf-8")[:_MAX_LOAD_CHARS]
            except OSError as exc:
                logger.warning("could not read app-knowledge file",
                               host=candidate, error=str(exc))
                return ""
    return ""


def append_note(host_or_url: str, note: str) -> Optional[str]:
    """Append a timestamped bullet to a host's note file (created if missing).

    Returns the host key written to, or None on invalid input / error."""
    host = _normalise_host(host_or_url)
    text = (note or "").strip()
    if not host or not text:
        return None
    path = _path_for(host)
    stamp = time.strftime("%Y-%m-%d")
    try:
        if not path.exists():
            path.write_text(f"# App knowledge — {host}\n\n", encoding="utf-8")
        with path.open("a", encoding="utf-8") as fh:
            fh.write(f"- ({stamp}) {text}\n")
        return host
    except OSError as exc:
        logger.warning("could not append app-knowledge note", host=host, error=str(exc))
        return None
