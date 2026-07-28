"""
Wordlist loader for content discovery.

Wordlists are plain-text assets under dast/wordlists/*.txt — one entry per
line, with blank lines and '#'-comment lines ignored. This is deliberately
separate from dast/payloads/loader.py (which is YAML-only): content-discovery
wordlists are flat frequency-ordered lists, not grouped payload categories.

Add a new wordlist by dropping a <name>.txt file in this directory — no code
changes needed. Load it with load_wordlist("<name>").
"""

from functools import lru_cache
from pathlib import Path
from typing import List

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_WORDLIST_DIR = Path(__file__).parent


@lru_cache(maxsize=None)
def load_wordlist(name: str) -> List[str]:
    """
    Return the entries of dast/wordlists/{name}.txt as a list of strings.

    Strips whitespace, drops blank lines and lines beginning with '#'.
    Returns an empty list (and logs a warning) if the file is missing or
    unreadable — a missing wordlist must never crash a discovery run.
    """
    path = _WORDLIST_DIR / f"{name}.txt"
    if not path.exists():
        logger.warning("Wordlist not found", name=name, path=str(path))
        return []
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as exc:
        logger.error("Failed to read wordlist", name=name, path=str(path), error=str(exc))
        return []

    entries: List[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        entries.append(stripped)
    logger.debug("Wordlist loaded", name=name, count=len(entries))
    return entries


def known_wordlists() -> List[str]:
    """Return the names (without .txt) of all available wordlists."""
    return sorted(p.stem for p in _WORDLIST_DIR.glob("*.txt"))
