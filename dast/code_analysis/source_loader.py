"""
Source loader for the code analysis module.

Loads source files from two sources:
  1. Local filesystem path — recursive walk with .gitignore support
  2. GitLab repository URL — uses GitLab REST API to enumerate and fetch files

Returns a list of dicts: {"path": str, "content": str, "language": str}

Language is inferred from file extension. Files that cannot be decoded as UTF-8
are skipped silently. Binary files are detected by the presence of null bytes.
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import List, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Maximum number of files fetched from a remote GitLab repository.
_REMOTE_FILE_LIMIT = 500

# Maximum file size fetched from GitLab (bytes).
_REMOTE_MAX_FILE_BYTES = 100 * 1024  # 100 KB

# Directories always skipped during local traversal.
_SKIP_DIRS = {
    "node_modules",
    ".git",
    "__pycache__",
    "vendor",
    "dist",
    "build",
    ".tox",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    "coverage",
    ".coverage",
    ".eggs",
    "*.egg-info",
}

# Extension → language mapping.
_LANGUAGE_MAP: dict[str, str] = {
    ".rb": "ruby",
    ".py": "python",
    ".go": "go",
    ".js": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".jsx": "javascript",
    ".java": "java",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
}

_SUPPORTED_EXTENSIONS = set(_LANGUAGE_MAP.keys())


def _language_for_path(file_path: str) -> Optional[str]:
    """Return the language identifier for a file path, or None if unsupported."""
    suffix = Path(file_path).suffix.lower()
    return _LANGUAGE_MAP.get(suffix)


def _is_binary(content_bytes: bytes) -> bool:
    """Return True if content looks like a binary file (contains null bytes)."""
    return b"\x00" in content_bytes[:8192]


def _load_gitignore_spec(root: Path):
    """
    Load .gitignore patterns from root. Returns a pathspec.PathSpec if pathspec
    is available, otherwise returns None (caller falls back to basic skips).
    """
    gitignore_path = root / ".gitignore"
    if not gitignore_path.is_file():
        return None
    try:
        import pathspec  # type: ignore
        with gitignore_path.open(encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        return pathspec.PathSpec.from_lines("gitwildmatch", lines)
    except ImportError:
        logger.debug("pathspec not available — .gitignore patterns will be ignored")
        return None
    except Exception as exc:
        logger.debug("Failed to parse .gitignore", error=str(exc))
        return None


def _should_skip_dir(dir_name: str) -> bool:
    """Return True if the directory should be skipped unconditionally."""
    return dir_name in _SKIP_DIRS or dir_name.startswith(".")


def _should_skip_file(file_name: str) -> bool:
    """Return True if the file should be skipped based on name patterns."""
    if file_name.endswith(".min.js"):
        return True
    return False


def _load_local(root_path: str) -> List[dict]:
    """
    Recursively walk a local directory and return source file dicts.
    Respects .gitignore if pathspec is available; falls back to basic dir skips.
    """
    root = Path(root_path).resolve()
    if not root.is_dir():
        logger.warning("Source path is not a directory", path=root_path)
        return []

    gitignore_spec = _load_gitignore_spec(root)
    results: List[dict] = []

    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        current_dir = Path(dirpath)

        # Prune traversal in-place: modify dirnames to skip unwanted dirs.
        dirnames[:] = [
            d for d in dirnames
            if not _should_skip_dir(d) and not (
                gitignore_spec and gitignore_spec.match_file(
                    str((current_dir / d).relative_to(root)) + "/"
                )
            )
        ]

        for filename in filenames:
            if _should_skip_file(filename):
                continue

            language = _language_for_path(filename)
            if language is None:
                continue

            file_path = current_dir / filename
            relative_path = str(file_path.relative_to(root))

            # Check gitignore for this file.
            if gitignore_spec and gitignore_spec.match_file(relative_path):
                continue

            try:
                raw = file_path.read_bytes()
            except OSError as exc:
                logger.debug("Cannot read file", path=relative_path, error=str(exc))
                continue

            if _is_binary(raw):
                continue

            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    content = raw.decode("latin-1")
                except Exception:
                    continue

            results.append({
                "path": relative_path,
                "content": content,
                "language": language,
            })

    logger.info("Local source loaded", root=root_path, files=len(results))
    return results


def _parse_gitlab_project_path(url: str) -> str:
    """
    Extract the project path from a GitLab URL.

    Examples:
      https://gitlab.com/group/project        → group/project
      https://gitlab.com/group/sub/project    → group/sub/project
      https://gitlab.example.com/foo/bar      → foo/bar
    """
    # Strip trailing slash, .git suffix, and fragment/query.
    url = url.rstrip("/").split("?")[0].split("#")[0]
    if url.endswith(".git"):
        url = url[:-4]

    # Remove protocol + host.
    match = re.match(r"https?://[^/]+/(.+)$", url)
    if not match:
        raise ValueError(f"Cannot parse GitLab project path from URL: {url}")
    return match.group(1)


def _gitlab_base_url(url: str) -> str:
    """Return the GitLab instance base URL (protocol + host)."""
    match = re.match(r"(https?://[^/]+)", url)
    if not match:
        raise ValueError(f"Cannot parse GitLab host from URL: {url}")
    return match.group(1)


async def _load_gitlab(url: str, gitlab_token: str = "") -> List[dict]:
    """
    Fetch source files from a GitLab repository via the REST API.

    Uses:
      GET /api/v4/projects/{encoded_path}/repository/tree?recursive=true&per_page=100
    to enumerate files, then fetches each supported file individually.
    """
    import urllib.parse

    try:
        import httpx
    except ImportError:
        logger.error("httpx is not installed — cannot fetch from GitLab")
        return []

    project_path = _parse_gitlab_project_path(url)
    base_url = _gitlab_base_url(url)
    encoded_path = urllib.parse.quote(project_path, safe="")

    headers: dict[str, str] = {"Accept": "application/json"}
    if gitlab_token:
        headers["PRIVATE-TOKEN"] = gitlab_token

    tree_url = (
        f"{base_url}/api/v4/projects/{encoded_path}/repository/tree"
        f"?recursive=true&per_page=100"
    )

    file_entries: List[dict] = []

    async with httpx.AsyncClient(headers=headers, timeout=30.0, follow_redirects=True) as client:
        # Paginate through the tree listing.
        page = 1
        while len(file_entries) < _REMOTE_FILE_LIMIT:
            paged_url = f"{tree_url}&page={page}"
            try:
                response = await client.get(paged_url)
            except httpx.HTTPError as exc:
                logger.error("GitLab tree listing failed", url=paged_url, error=str(exc))
                break

            if response.status_code == 401:
                logger.error(
                    "GitLab API returned 401 — provide a valid gitlab_token",
                    url=paged_url,
                )
                break

            if response.status_code != 200:
                logger.error(
                    "GitLab tree listing returned unexpected status",
                    url=paged_url,
                    status=response.status_code,
                )
                break

            try:
                items = response.json()
            except Exception as exc:
                logger.error("Failed to parse GitLab tree response", error=str(exc))
                break

            if not isinstance(items, list) or len(items) == 0:
                break

            for item in items:
                if item.get("type") != "blob":
                    continue
                file_path = item.get("path", "")
                if _language_for_path(file_path) is None:
                    continue
                if _should_skip_file(Path(file_path).name):
                    continue
                # Skip files in ignored directory prefixes.
                parts = Path(file_path).parts
                if any(p in _SKIP_DIRS or p.startswith(".") for p in parts[:-1]):
                    continue
                file_entries.append(item)

            # Check if there are more pages.
            total_pages = int(response.headers.get("X-Total-Pages", "1"))
            if page >= total_pages:
                break
            page += 1

        # Cap file list.
        file_entries = file_entries[:_REMOTE_FILE_LIMIT]
        logger.info(
            "GitLab tree enumerated",
            project=project_path,
            files_to_fetch=len(file_entries),
        )

        # Fetch file contents concurrently (max 10 at a time).
        semaphore = asyncio.Semaphore(10)
        results: List[dict] = []

        async def fetch_file(item: dict) -> Optional[dict]:
            file_path = item["path"]
            language = _language_for_path(file_path)
            if language is None:
                return None

            encoded_file_path = urllib.parse.quote(file_path, safe="")
            raw_url = (
                f"{base_url}/api/v4/projects/{encoded_path}/repository/files"
                f"/{encoded_file_path}/raw?ref=HEAD"
            )
            async with semaphore:
                try:
                    file_response = await client.get(raw_url)
                except httpx.HTTPError as exc:
                    logger.debug("Failed to fetch file", path=file_path, error=str(exc))
                    return None

                if file_response.status_code != 200:
                    logger.debug(
                        "Unexpected status fetching file",
                        path=file_path,
                        status=file_response.status_code,
                    )
                    return None

                raw = file_response.content
                if len(raw) > _REMOTE_MAX_FILE_BYTES:
                    logger.debug("Skipping oversized file", path=file_path, size=len(raw))
                    return None

                if _is_binary(raw):
                    return None

                try:
                    content = raw.decode("utf-8")
                except UnicodeDecodeError:
                    try:
                        content = raw.decode("latin-1")
                    except Exception:
                        return None

            return {"path": file_path, "content": content, "language": language}

        fetch_tasks = [fetch_file(item) for item in file_entries]
        fetched = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        for item in fetched:
            if isinstance(item, dict):
                results.append(item)

    logger.info(
        "GitLab source loaded",
        project=project_path,
        files=len(results),
    )
    return results


async def load_source(source: str, gitlab_token: str = "") -> List[dict]:
    """
    Load source files from a local path or a GitLab repository URL.

    Args:
        source: An absolute or relative filesystem path, or a GitLab HTTPS URL.
        gitlab_token: Optional GitLab personal access token (for private repos).

    Returns:
        List of dicts with keys: path (str), content (str), language (str).
    """
    if source.startswith("http://") or source.startswith("https://"):
        return await _load_gitlab(source, gitlab_token=gitlab_token)

    # Local path — run blocking walk in executor to avoid blocking the event loop
    # on large repositories.
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _load_local, source)
