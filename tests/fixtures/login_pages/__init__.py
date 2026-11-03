"""Local login-page fixtures for the login-difficulty harness.

A threaded, loopback-only HTTP server that serves login pages across escalating
difficulty tiers (T0-T11) plus a minimal JSON auth API (JWT issue/verify) used by
the SPA/bearer tiers. Everything is served on 127.0.0.1 so no external host is ever
touched and nothing enters the proxy scope.

See ``README.md`` for the tier catalogue and how each tier maps to a specific code
path in ``dast/browser/agent_browser.py`` and ``dast/ai/copilot/session.py``.
"""

from __future__ import annotations

from tests.fixtures.login_pages.server import (
    PASSWORD,
    USERNAME,
    LoginFixtureServer,
    issue_jwt,
    login_fixture,
)

__all__ = [
    "LoginFixtureServer",
    "login_fixture",
    "issue_jwt",
    "USERNAME",
    "PASSWORD",
]
