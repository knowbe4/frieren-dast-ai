"""
Read-only (production-safe) mode policy.

Shared by the copilot's tool gate, its live browser and the SPA crawler so an
unattended run against a production app can map it without changing anything:

  - only safe HTTP methods leave the machine (enforced at the network layer of
    every automated browser, so a click that would POST/PUT/DELETE is dropped
    no matter which button triggered it);
  - attack / active-scan tools are refused outright;
  - the crawler does not click action buttons (delete, send, launch, save...),
    which keeps it out of confirm dialogs and half-filled forms.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Tools that send probes/payloads or brute-force paths. Navigation (browser_*,
# crawl) and reads stay available; they are covered by the network guard.
BLOCKED_TOOLS = frozenset({
    "run_scan",
    "scan_surface",
    "idor_probe",
    "graphql_sweep",
    "match_replace",
    "param_mining",
    "content_discovery",
    "validate_chain",
    "graphql_fuzz",
})

_ACTION_LABEL = re.compile(
    r"\b(?:delete|remove|send|resend|launch|start|stop|pause|resume|create|add|new|save|submit|"
    r"update|archive|unarchive|restore|approve|reject|invite|import|upload|sync|enable|disable|"
    r"activate|deactivate|reset|run|schedule|publish|clone|duplicate|copy|apply|confirm|yes|ok|"
    r"purge|revoke|assign|unassign|move|rename|test|retry|install|uninstall|connect|disconnect|"
    r"generate|request|accept|decline|cancel)\b",
    re.IGNORECASE,
)


def is_safe_method(method: str) -> bool:
    return (method or "").upper() in SAFE_METHODS


_GRAPHQL_PATH = re.compile(r"/graphql\b", re.IGNORECASE)
_GRAPHQL_MUTATING = re.compile(r"\b(?:mutation|subscription)\b", re.IGNORECASE)
_GRAPHQL_QUERY_OP = re.compile(r"^\s*query\b", re.IGNORECASE)


def _extract_graphql_query(body: Any) -> str:
    """Pull the GraphQL document string out of a request body (dict or JSON str)."""
    import json

    candidate = body
    if isinstance(candidate, (bytes, bytearray)):
        try:
            candidate = candidate.decode("utf-8", "replace")
        except Exception:
            return ""
    if isinstance(candidate, str):
        text = candidate.strip()
        if text.startswith("{"):
            try:
                candidate = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                return text  # treat the raw string as the query document
        else:
            return text
    if isinstance(candidate, dict):
        query = candidate.get("query")
        return query if isinstance(query, str) else ""
    return ""


def is_read_only_graphql(url: str, body: Any) -> bool:
    """True when a POST to *url* with *body* is a non-mutating GraphQL request.

    GraphQL (even introspection) must use POST, so a blanket GET/HEAD/OPTIONS
    allowlist blocks read-only recon. This carve-out permits introspection and
    ``query`` operations while still refusing ``mutation``/``subscription``.
    Fails closed: anything not positively classified as a read-only query is
    rejected.
    """
    if not url or not _GRAPHQL_PATH.search(url):
        return False
    query = _extract_graphql_query(body)
    if not query:
        return False
    stripped = query.strip()
    if _GRAPHQL_MUTATING.search(stripped):
        return False
    lowered = stripped.lower()
    if "__schema" in lowered or "__type" in lowered:
        return True
    return stripped.startswith("{") or bool(_GRAPHQL_QUERY_OP.match(stripped))


def is_action_label(label: str) -> bool:
    """True when a clickable element's visible text/aria-label names an action."""
    return bool(_ACTION_LABEL.search(label or ""))


def blocked_tool_error(tool_name: str) -> dict:
    return {
        "ok": False,
        "read_only": True,
        "error": (
            f"read-only mode: '{tool_name}' sends probes or brute-forces paths and is disabled. "
            "Use crawl, browser_navigate/browser_click, send_request (GET/HEAD/OPTIONS) "
            "and get_history to observe the app instead."
        ),
    }


def make_route_guard(
    label: str,
    forward: Optional[Callable[[Any], Any]] = None,
    on_block: Optional[Callable[[str, str], None]] = None,
) -> Callable[[Any], Any]:
    """Playwright route handler that aborts unsafe methods before they leave.

    `forward(route)` continues an allowed request (defaults to route.continue_()),
    so callers that already rewrite headers keep doing so.
    """

    async def _guard(route: Any) -> None:
        request = route.request
        if not is_safe_method(request.method):
            logger.info("read-only mode: blocked request", browser=label,
                        method=request.method, url=request.url[:200])
            if on_block is not None:
                try:
                    on_block(request.method, request.url)
                except Exception as exc:
                    logger.warning("read-only on_block callback failed", error=str(exc))
            await route.abort("blockedbyclient")
            return
        if forward is not None:
            await forward(route)
        else:
            await route.continue_()

    return _guard
