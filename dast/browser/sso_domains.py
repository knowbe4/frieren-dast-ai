"""SSO/IdP domain list for login detection.

A login that redirects to an identity provider (Auth0, Okta, Azure AD, …) must be
recognized as "still on the IdP" so the cascade waits for the full SSO redirect
chain to complete instead of navigating away mid-callback (which would drop the
auth cookies). The built-in list covers common vendors; deployment-specific IdP
hosts are added out-of-band via the ``DAST_SSO_DOMAINS`` env (CSV) so no
environment-specific hostname is hardcoded in the repo.
"""

from __future__ import annotations

import os

_BUILTIN = ("auth0", "okta", "login.microsoftonline",
            "accounts.google", "hrmauth", "cognito")

_ENV = "DAST_SSO_DOMAINS"


def sso_domains() -> tuple[str, ...]:
    """Built-in SSO vendor substrings plus any from ``DAST_SSO_DOMAINS`` (CSV)."""
    extra = tuple(s.strip().lower()
                  for s in os.environ.get(_ENV, "").split(",") if s.strip())
    return _BUILTIN + extra
