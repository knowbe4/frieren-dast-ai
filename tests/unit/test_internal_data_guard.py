"""Tests for scripts/check_no_internal_data.py — the internal-hostname guard.

Locks the blind spot that let an on-demand (*.kb4od.run) host and internal
product subdomains slip past CI: the guard must flag them, while leaving public
references and placeholders alone.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_GUARD_PATH = Path(__file__).resolve().parents[2] / "scripts" / "check_no_internal_data.py"
_spec = importlib.util.spec_from_file_location("check_no_internal_data", _GUARD_PATH)
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


@pytest.mark.parametrize(
    "host",
    [
        "od-for-demo-user.kmsat.kb4od.run",
        "eai-agent-security-inventory-od-for-demo.ai-dev.kb4od.run",
        "api.phisher.knowbe4.com",
        "service.kmsat.knowbe4.com",
        "gw.internal.knowbe4.com",
        "x.corp.knowbe4.com",
        "y.private.knowbe4.com",
        "eai-extension.eai.knowbe4.com",
    ],
)
def test_internal_hosts_are_flagged(host: str) -> None:
    assert guard.INTERNAL_HOSTNAME_RE.search(host), f"{host} should be flagged"


@pytest.mark.parametrize(
    "text",
    [
        "see github.com/knowbe4 for the repo",
        "scope rule: *.knowbe4.com",
        "the on-demand run domain is kb4od.run",
        "https://app.example.com/login",
        "blocks internal/corp/private/kmsat/phisher/eai knowbe4.com subdomains",
        "any kb4od.run on-demand host",
    ],
)
def test_public_and_placeholder_refs_are_not_flagged(text: str) -> None:
    assert not guard.INTERNAL_HOSTNAME_RE.search(text), f"{text!r} must not be flagged"


def test_content_rule_reports_the_internal_host(tmp_path: Path) -> None:
    target = tmp_path / "leak.sh"
    target.write_text("curl https://od-for-demo.kmsat.kb4od.run/x\n", encoding="utf-8")
    violations = guard._check_content_rules(str(target))
    assert any("internal hostname" in v for v in violations)


def test_guard_does_not_flag_its_own_source_or_architecture_doc() -> None:
    """The guard scans tracked files including itself and the architecture doc,
    both of which mention the corp domain in prose/regex. Neither must self-flag."""
    repo_root = Path(__file__).resolve().parents[2]
    for rel in ("scripts/check_no_internal_data.py", "docs/ARCHITECTURE.md"):
        violations = guard._check_content_rules(str(repo_root / rel))
        host_hits = [v for v in violations if "internal hostname" in v]
        assert not host_hits, f"{rel} self-flagged: {host_hits}"
