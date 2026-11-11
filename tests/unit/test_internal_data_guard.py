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
        # bare concrete subdomains (no internal env segment) — the blind spot that let
        # training.knowbe4.com slip through until the pattern was broadened.
        "training.knowbe4.com",
        "api.training.knowbe4.com",
        "kmsat-tenant-a.knowbe4.com",
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


@pytest.mark.parametrize(
    "text",
    [
        "POST /modstore/graphql",
        "the customercontent service",
        "extract zenkaJwt from the session",
        "user.attributes.ccmJwt",
        "modstoreJwt bearer",
        "searchJwt field",
        "the zenka service",
        "GraphqlAdminController via /modstore/graphql_direct",
    ],
)
def test_internal_topology_identifiers_are_flagged(text: str) -> None:
    assert guard.INTERNAL_TOPOLOGY_RE.search(text), f"{text!r} should be flagged"


@pytest.mark.parametrize(
    "text",
    [
        "search the catalog",          # bare generic word, not a *Jwt
        "ccm is an acronym here",      # bare 'ccm' is not matched (only ccmJwt)
        "a content store for modules", # 'store'/'content' generic, not 'modstore'
        "direct graphql access",       # not the 'graphql_direct' token
        "https://app.example.com/graphql",
    ],
)
def test_generic_words_are_not_topology_flagged(text: str) -> None:
    assert not guard.INTERNAL_TOPOLOGY_RE.search(text), f"{text!r} must not be flagged"


def test_content_rule_reports_the_internal_host(tmp_path: Path) -> None:
    target = tmp_path / "leak.sh"
    target.write_text("curl https://od-for-demo.kmsat.kb4od.run/x\n", encoding="utf-8")
    violations = guard._check_content_rules(str(target))
    assert any("internal hostname" in v for v in violations)


def test_guard_source_is_content_allowlisted() -> None:
    """The guard's own source defines the forbidden hostname/topology patterns as
    literals, so it is content-allowlisted to avoid self-flagging; path rules still apply."""
    assert guard._is_content_allowlisted("scripts/check_no_internal_data.py")


def test_architecture_doc_does_not_self_flag() -> None:
    """The architecture doc mentions the corp domain in prose; it is NOT allowlisted,
    so it must carry no concrete internal hostname or topology identifier."""
    repo_root = Path(__file__).resolve().parents[2]
    violations = guard._check_content_rules(str(repo_root / "docs/ARCHITECTURE.md"))
    assert not violations, f"docs/ARCHITECTURE.md self-flagged: {violations}"
