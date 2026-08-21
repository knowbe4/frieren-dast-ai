"""
At-rest encryption for login-profile secrets.

Secrets (credential passwords/tokens, saved-session cookies) are encrypted with a
symmetric Fernet key stored in a 0600 key file at ~/.dast-ai/profiles/.key. The key
is generated on first use. This is deliberately a local key file (not the OS
keychain): it is portable across platforms and lives next to the data, protecting
against casual inspection / accidental commit of plaintext secrets, not against an
attacker who already has read access to the user's home directory.

The public surface is intentionally tiny:
  - encrypt(plaintext: str) -> str   (opaque token, safe to store as JSON string)
  - decrypt(token: str) -> str
  - is_available() -> bool           (False if the key cannot be created/read)
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_PROFILES_DIR = Path.home() / ".dast-ai" / "profiles"
_KEY_PATH = _PROFILES_DIR / ".key"

# Cached Fernet instance — the key never changes within a process lifetime.
_fernet: Optional[Fernet] = None


def profiles_dir() -> Path:
    """Return the profiles directory, creating it 0700 if missing."""
    _PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    try:
        _PROFILES_DIR.chmod(stat.S_IRWXU)  # 0700
    except OSError as exc:
        logger.warning("could not chmod profiles dir", error=str(exc))
    return _PROFILES_DIR


def get_or_create_key() -> bytes:
    """Load the Fernet key, generating and persisting one (0600) on first use."""
    profiles_dir()
    if _KEY_PATH.exists():
        return _KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    # Write with restrictive perms from the start: create with O_CREAT|O_EXCL, 0600.
    fd = os.open(str(_KEY_PATH), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    logger.info("generated login-profile encryption key", path=str(_KEY_PATH))
    return key


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(get_or_create_key())
    return _fernet


def is_available() -> bool:
    """True if secrets can be encrypted/decrypted (key file usable). Never raises."""
    try:
        _get_fernet()
        return True
    except Exception as exc:
        logger.error("login-profile crypto unavailable", error=str(exc))
        return False


def encrypt(plaintext: str) -> str:
    """Encrypt a UTF-8 string into an opaque token string safe to store as JSON."""
    if plaintext is None:
        plaintext = ""
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    """Decrypt a token produced by encrypt(). Returns "" on tamper/failure."""
    if not token:
        return ""
    try:
        return _get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        logger.error("login-profile secret decrypt failed", error=str(exc))
        return ""
