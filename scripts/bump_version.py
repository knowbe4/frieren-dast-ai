"""
Bump the project version across every file that hardcodes it, atomically.

The version is duplicated in 4 places (pyproject.toml, desktop/package.json,
CLAUDE.md, docs/ARCHITECTURE.md) with no single source of truth and no automation,
so they drift apart over time — this repo sat at 0.8.0 in all of them for
months while everything else moved on. This script is the fix: it never
decides *when* to bump (that stays a human/product judgement call — major vs
minor vs patch), only that a bump touches every location in one atomic pass.

Usage:
    uv run python scripts/bump_version.py 0.9.0
    make bump-version VERSION=0.9.0

Also updates each file's "Last Updated" date to today, where present, since a
version bump without a date bump is exactly the kind of drift this exists to
prevent.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


@dataclass
class VersionSite:
    path: Path
    pattern: re.Pattern
    replacement_template: str  # {version} placeholder


def _read_current_version() -> str:
    """The current version is authoritative from pyproject.toml — every other
    site must match it (checked by tests/unit/test_version_consistency.py)."""
    text = (_REPO_ROOT / "pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        raise RuntimeError("Could not find version in pyproject.toml")
    return m.group(1)


def _sites(new_version: str) -> list[VersionSite]:
    return [
        VersionSite(
            path=_REPO_ROOT / "pyproject.toml",
            pattern=re.compile(r'^version\s*=\s*"[^"]+"', re.MULTILINE),
            replacement_template=f'version = "{new_version}"',
        ),
        VersionSite(
            path=_REPO_ROOT / "desktop" / "package.json",
            pattern=re.compile(r'"version":\s*"[^"]+"'),
            replacement_template=f'"version": "{new_version}"',
        ),
        VersionSite(
            path=_REPO_ROOT / "CLAUDE.md",
            pattern=re.compile(r"\*\*Version:\*\*\s*[\d.]+"),
            replacement_template=f"**Version:** {new_version}",
        ),
        VersionSite(
            path=_REPO_ROOT / "docs" / "ARCHITECTURE.md",
            pattern=re.compile(r"\*\*Version:\*\*\s*[\d.]+"),
            replacement_template=f"**Version:** {new_version}",
        ),
    ]


_LAST_UPDATED_RE = re.compile(r"\*\*Last Updated:\*\*\s*\d{4}-\d{2}-\d{2}")


def _bump_last_updated(text: str, today: str) -> str:
    return _LAST_UPDATED_RE.sub(f"**Last Updated:** {today}", text)


def bump_version(new_version: str, today: str | None = None) -> list[Path]:
    """Apply the new version to every known site. Returns the list of files touched."""
    if not _SEMVER_RE.match(new_version):
        raise ValueError(f"Version must be in X.Y.Z form, got: {new_version!r}")

    today = today or date.today().isoformat()
    touched: list[Path] = []

    for site in _sites(new_version):
        text = site.path.read_text()
        if not site.pattern.search(text):
            raise RuntimeError(f"Version pattern not found in {site.path}")
        new_text = site.pattern.sub(site.replacement_template, text, count=1)
        new_text = _bump_last_updated(new_text, today)
        if new_text != text:
            site.path.write_text(new_text)
            touched.append(site.path)

    return touched


def main() -> int:
    if len(sys.argv) != 2:
        current = _read_current_version()
        print(f"Current version: {current}", file=sys.stderr)
        print(f"Usage: {sys.argv[0]} <new-version>  (e.g. 0.9.0)", file=sys.stderr)
        return 1

    new_version = sys.argv[1]
    try:
        touched = bump_version(new_version)
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not touched:
        print(f"Already at {new_version} everywhere — nothing to do.")
        return 0

    print(f"Bumped to {new_version} in:")
    for path in touched:
        print(f"  {path.relative_to(_REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
