"""
OAuth / OIDC flow analyzer plugin — passive inspection of OAuth traffic.

Recognizes authorization-code / implicit / hybrid grant requests and token
requests seen in proxied traffic and flags the deterministic, well-known
weaknesses of each shape:

  - implicit grant (response_type=token|id_token) — tokens exposed in the URL
    fragment, no client authentication (deprecated by OAuth 2.1 / RFC 9700)
  - missing `state` on an authorization request — login CSRF / auth-code theft
  - authorization-code flow without PKCE (no code_challenge) — code interception
  - token endpoint receiving client credentials in the query string
  - redirect_uri host unrelated to the observed application host — possible
    weak redirect_uri validation (informational: real validation is active work)

Everything is derived from observed request/response pairs only — no probing,
no LLM. Values that look like secrets (tokens, codes, client secrets) are
redacted in the evidence.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from dast.proxy.plugin_base import ProxyPlugin
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

logger = get_logger(__name__)

_RESPONSE_TYPE_RE = re.compile(r"^(token|id_token)[\s%20+]*$", re.IGNORECASE)
_SENSITIVE_PARAM_RE = re.compile(r"token|secret|code|password|credential", re.IGNORECASE)
# Path shapes of the OAuth2/OIDC endpoints (authorization + token). The param
# check below is the real gate; the path hint only tightens token-endpoint
# detection, where `grant_type` alone would otherwise be too loose.
_AUTHZ_PATH_RE = re.compile(r"/(oauth2?|auth|authorization|login)[^/]*/?(authorize|authorise|login)?$", re.IGNORECASE)
_TOKEN_PATH_RE = re.compile(r"/(oauth2?|auth)?[^/]*/?(token|access[_-]?token)$", re.IGNORECASE)

# One finding per (host, client_id, check) — an OAuth app is configured once,
# every subsequent request through the same flow would re-fire otherwise.
_seen_checks: set[tuple[str, str, str]] = set()


def _query(entry: "ProxyEntry") -> dict[str, str]:
    """Flattened query params of the entry (first value wins)."""
    parsed = urlparse(entry.url)
    return {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}


def _redact(params: dict[str, str]) -> str:
    """Render params for evidence, masking anything secret-looking."""
    parts = []
    for key, value in params.items():
        if _SENSITIVE_PARAM_RE.search(key) and value:
            value = f"<redacted:{len(value)} chars>"
        parts.append(f"{key}={value}")
    return "&".join(parts)[:400] or "(no params)"


def _is_authorization_request(path: str, params: dict[str, str]) -> bool:
    if "response_type" in params and "client_id" in params:
        return True
    return bool(_AUTHZ_PATH_RE.search(path) and "response_type" in params)


def _is_token_request(path: str, params: dict[str, str]) -> bool:
    if "grant_type" in params:
        return True
    return bool(_TOKEN_PATH_RE.search(path) and ("code" in params or "client_id" in params))


class OauthFlowAnalyzerPlugin(ProxyPlugin):
    name = "oauth-flow-analyzer"
    description = "Passively analyzes OAuth/OIDC flows: implicit grant, missing state/PKCE, credentials in token requests"
    version = "1.0.0"
    author = "Frieren DAST-AI"
    enabled = True

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        # Skip the scanner's own injected requests — they are not real app traffic.
        if getattr(entry, "source", "proxy") not in ("proxy", "browse"):
            return
        params = _query(entry)
        if not params:
            return

        if _is_authorization_request(entry.path or "", params):
            await self._check_authorization(entry, store, params)
        elif _is_token_request(entry.path or "", params):
            await self._check_token_request(entry, store, params)

    async def _check_authorization(
        self, entry: "ProxyEntry", store: "SessionStore", params: dict[str, str]
    ) -> None:
        client_id = params.get("client_id", "")
        response_type = params.get("response_type", "")
        evidence_qs = _redact(params)

        def _fire(check: str, title: str, severity: str, cwe: str, evidence: str) -> None:
            key = (entry.host, client_id, check)
            if key in _seen_checks:
                return
            _seen_checks.add(key)
            store.add_finding(
                entry.id,
                {
                    "title": title,
                    "severity": severity,
                    "cwe": cwe,
                    "attack_type": "oauth",
                    "evidence": evidence,
                    "confirmed": False,
                    "validated_by": ["pattern"],
                },
                "safe",
            )

        # Implicit / hybrid-with-token grant — deprecated for a reason: the access
        # token lands in the URL fragment (browser history, referer leaks).
        if _RESPONSE_TYPE_RE.match(response_type.strip()):
            _fire(
                "implicit_flow",
                "OAuth Implicit Grant Flow In Use",
                "medium",
                "CWE-522",
                (
                    f"response_type={response_type!r} on {entry.path} returns tokens in the URL "
                    f"fragment. Deprecated by OAuth 2.1 (RFC 9700); use authorization code + PKCE. "
                    f"Request: {_redact(params)}"
                ),
            )

        # Missing state — login CSRF / authorization-code injection.
        if not params.get("state"):
            _fire(
                "missing_state",
                "OAuth Authorization Request Without state Parameter",
                "medium",
                "CWE-352",
                (
                    f"Authorization request to {entry.path} carries no state parameter — the flow "
                    f"is vulnerable to login CSRF and authorization-code injection. "
                    f"Request: {evidence_qs}"
                ),
            )

        # Authorization-code flow without PKCE — code interception risk. Only a
        # weak signal for confidential server clients, so informational.
        if "code" in response_type.lower() and not params.get("code_challenge"):
            _fire(
                "missing_pkce",
                "OAuth Authorization Code Flow Without PKCE",
                "low",
                "CWE-764",
                (
                    f"response_type=code without code_challenge on {entry.path} — interception-"
                    f"resistant PKCE is absent (required for public clients by RFC 7636, "
                    f"recommended for all clients by OAuth 2.1). Request: {evidence_qs}"
                ),
            )

        # redirect_uri pointing at a host unrelated to the app that initiated the
        # flow. In a NORMAL OAuth deployment the authorization request goes to the
        # IdP host and redirect_uri points back at the app host — different hosts
        # by design. The only passive evidence of the initiating app is the
        # Referer header, so without one (or when redirect_uri matches either the
        # IdP host or the Referer app host / their subdomains) we stay silent.
        redirect_uri = params.get("redirect_uri", "")
        if redirect_uri:
            redirect_host = (urlparse(redirect_uri).hostname or "").lower()
            referer = {k.lower(): v for k, v in (entry.request_headers or {}).items()}.get("referer", "")
            referer_host = (urlparse(referer).hostname or "").lower()
            entry_host = (entry.host or "").lower()
            related = any(
                h and (
                    host == h
                    or host.endswith("." + h)
                    or h.endswith("." + host)
                )
                for host in (redirect_host,)
                for h in (entry_host, referer_host)
            )
            if redirect_host and referer_host and not related:
                _fire(
                    "external_redirect_uri",
                    "OAuth redirect_uri Points To Unrelated Host",
                    "low",
                    "CWE-601",
                    (
                        f"redirect_uri host {redirect_host!r} matches neither the authorization "
                        f"server ({entry_host!r}) nor the referring application "
                        f"({referer_host!r}) on {entry.path}. Confirm the server validates "
                        f"redirect_uri against an allowlist — an open redirect_uri leaks "
                        f"authorization codes. Request: {evidence_qs}"
                    ),
                )

    async def _check_token_request(
        self, entry: "ProxyEntry", store: "SessionStore", params: dict[str, str]
    ) -> None:
        # Credentials in the query string of a token request — client_secret or
        # the authorization code itself must travel in the body, not the URL
        # (logged by proxies/servers/browser history).
        leaked = [
            key for key in params
            if _SENSITIVE_PARAM_RE.search(key) and params.get(key)
        ]
        if not leaked:
            return
        key = (entry.host, "token_query_credentials", ",".join(sorted(leaked)))
        if key in _seen_checks:
            return
        _seen_checks.add(key)
        store.add_finding(
            entry.id,
            {
                "title": "OAuth Token Request Sends Credentials In URL Query",
                "severity": "medium",
                "cwe": "CWE-598",
                "attack_type": "oauth",
                "evidence": (
                    f"{entry.method} {entry.path} is a token request carrying "
                    f"{', '.join(sorted(leaked))} in the query string. OAuth requires client "
                    f"credentials and authorization codes in the request body. "
                    f"Request: {_redact(params)}"
                ),
                "confirmed": False,
                "validated_by": ["pattern"],
            },
            "safe",
        )
