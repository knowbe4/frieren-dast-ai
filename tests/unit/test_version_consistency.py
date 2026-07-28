"""
Version consistency check.

The project version is duplicated in 4 places with no single source of
truth: pyproject.toml, desktop/package.json, CLAUDE.md, docs/ARCHITECTURE.md.
Nothing enforced they stay in sync, and they drifted apart (all sat at
0.8.0 for months while unrelated work shipped). This test is the guard —
any future bump that misses a site (instead of going through
`scripts/bump_version.py` / `make bump-version`) turns it red.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _pyproject_version() -> str:
    text = (_REPO_ROOT / "pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "version not found in pyproject.toml"
    return m.group(1)


def _package_json_version() -> str:
    data = json.loads((_REPO_ROOT / "desktop" / "package.json").read_text())
    return data["version"]


def _markdown_version(filename: str) -> str:
    text = (_REPO_ROOT / filename).read_text()
    m = re.search(r"\*\*Version:\*\*\s*([\d.]+)", text)
    assert m, f"Version line not found in {filename}"
    return m.group(1)


def test_desktop_package_json_matches_pyproject():
    assert _package_json_version() == _pyproject_version()


def test_claude_md_matches_pyproject():
    assert _markdown_version("CLAUDE.md") == _pyproject_version()


def test_architecture_md_matches_pyproject():
    assert _markdown_version("docs/ARCHITECTURE.md") == _pyproject_version()


def test_bump_version_script_updates_all_sites(tmp_path, monkeypatch):
    """Exercise scripts/bump_version.py against a copy of the real files, so
    a future edit to its file list or regexes is caught even though the
    script itself never runs as part of the normal test suite (running it
    for real would mutate the repo's actual version)."""
    import shutil
    import sys

    sys.path.insert(0, str(_REPO_ROOT / "scripts"))
    import bump_version as bv

    sys.path.remove(str(_REPO_ROOT / "scripts"))

    fake_root = tmp_path / "repo"
    (fake_root / "desktop").mkdir(parents=True)
    (fake_root / "docs").mkdir(parents=True)
    shutil.copy(_REPO_ROOT / "pyproject.toml", fake_root / "pyproject.toml")
    shutil.copy(_REPO_ROOT / "desktop" / "package.json", fake_root / "desktop" / "package.json")
    shutil.copy(_REPO_ROOT / "CLAUDE.md", fake_root / "CLAUDE.md")
    shutil.copy(_REPO_ROOT / "docs" / "ARCHITECTURE.md", fake_root / "docs" / "ARCHITECTURE.md")

    monkeypatch.setattr(bv, "_REPO_ROOT", fake_root)

    touched = bv.bump_version("9.9.9", today="2026-01-01")

    assert len(touched) == 4
    assert 'version = "9.9.9"' in (fake_root / "pyproject.toml").read_text()
    assert json.loads((fake_root / "desktop" / "package.json").read_text())["version"] == "9.9.9"
    assert "**Version:** 9.9.9" in (fake_root / "CLAUDE.md").read_text()
    assert "**Last Updated:** 2026-01-01" in (fake_root / "CLAUDE.md").read_text()
    assert "**Version:** 9.9.9" in (fake_root / "docs" / "ARCHITECTURE.md").read_text()


def test_bump_version_rejects_non_semver(tmp_path, monkeypatch):
    import sys

    sys.path.insert(0, str(_REPO_ROOT / "scripts"))
    import bump_version as bv

    sys.path.remove(str(_REPO_ROOT / "scripts"))

    import pytest
    with pytest.raises(ValueError):
        bv.bump_version("not-a-version")


def test_bump_version_is_idempotent_noop_when_already_at_target(tmp_path, monkeypatch):
    import shutil
    import sys

    sys.path.insert(0, str(_REPO_ROOT / "scripts"))
    import bump_version as bv

    sys.path.remove(str(_REPO_ROOT / "scripts"))

    fake_root = tmp_path / "repo2"
    (fake_root / "desktop").mkdir(parents=True)
    (fake_root / "docs").mkdir(parents=True)
    shutil.copy(_REPO_ROOT / "pyproject.toml", fake_root / "pyproject.toml")
    shutil.copy(_REPO_ROOT / "desktop" / "package.json", fake_root / "desktop" / "package.json")
    shutil.copy(_REPO_ROOT / "CLAUDE.md", fake_root / "CLAUDE.md")
    shutil.copy(_REPO_ROOT / "docs" / "ARCHITECTURE.md", fake_root / "docs" / "ARCHITECTURE.md")

    monkeypatch.setattr(bv, "_REPO_ROOT", fake_root)

    current = _pyproject_version()
    # Same version, same "today" as whatever's already in the files' Last
    # Updated line is NOT guaranteed, so only assert the version site itself
    # is untouched when nothing changes (the date-touch is a separate concern
    # from the version-consistency guarantee this test protects).
    bv.bump_version(current, today="2026-01-01")
    touched_again = bv.bump_version(current, today="2026-01-01")
    assert touched_again == []
