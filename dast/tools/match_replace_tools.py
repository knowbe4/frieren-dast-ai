"""
match_replace tool — let the copilot add/list/remove proxy match-and-replace rules.

When the copilot needs to inject a payload transparently (e.g. swap BodyHtml in a
POST /compose/send while the browser submits the form with a fresh CSRF token),
it sets up a match/replace rule that the proxy applies on the fly. The copilot
then drives the browser to submit the form normally — the proxy injects the
payload, and the fresh token stays valid.

Rules added by this tool are tagged with ``copilot_session`` so they are
auto-removed when the copilot session ends (or by explicit ``action: clear``),
keeping the operator's own rules safe.
"""

from __future__ import annotations

from typing import Any, Dict, List

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_COPILOT_TAG = "copilot_session"

_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["add", "list", "remove", "clear"],
            "description": "add: create a rule; list: show current rules; remove: delete one by index; "
                           "clear: remove all copilot-added rules (auto-called at session end).",
        },
        "scope": {
            "type": "string",
            "description": "Where the rule applies: 'request' (default), 'response', or 'both'.",
        },
        "type": {
            "type": "string",
            "description": "What to match: 'body' (default), 'header', or 'url'.",
        },
        "match": {
            "type": "string",
            "description": "Regex to match in the request/response (empty = match everything of this type).",
        },
        "replace": {
            "type": "string",
            "description": "Replacement string (regex capture groups supported). This is the payload.",
        },
        "comment": {
            "type": "string",
            "description": "Short note shown in the UI (e.g. 'inject XSS payload in BodyHtml').",
        },
        "index": {
            "type": "integer",
            "description": "Rule index to remove (action=remove only).",
        },
    },
    "required": ["action"],
}


def _get_settings(ctx: ToolContext) -> Any:
    settings = getattr(ctx, "settings", None)
    if settings is None:
        settings = ctx.get_settings()
    return settings


def _copilot_rules(settings: Any) -> List[dict]:
    """Return only the rules this tool added (tagged with copilot_session)."""
    return [r for r in (settings.get_match_replace() or [])
            if r.get("comment", "").startswith(f"[{_COPILOT_TAG}]")]


async def _match_replace(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    action = str(args.get("action", "")).strip().lower()
    if action not in ("add", "list", "remove", "clear"):
        return {"ok": False, "error": "action must be add, list, remove, or clear"}

    settings = _get_settings(ctx)
    if settings is None:
        return {"ok": False, "error": "proxy settings not available in this context"}

    if action == "list":
        rules = settings.get_match_replace() or []
        return {"ok": True, "count": len(rules), "rules": [
            {"index": i, "enabled": r.get("enabled"), "scope": r.get("scope"),
             "type": r.get("type"), "match": r.get("match"), "replace": r.get("replace"),
             "comment": r.get("comment"), "copilot": r.get("comment", "").startswith(f"[{_COPILOT_TAG}]")}
            for i, r in enumerate(rules)
        ]}

    if action == "add":
        match_val = str(args.get("match", "")).strip()
        replace_val = str(args.get("replace", ""))
        comment = str(args.get("comment", "")).strip()
        # Tag so auto-cleanup knows which rules are ours.
        tagged_comment = f"[{_COPILOT_TAG}] {comment}" if comment else f"[{_COPILOT_TAG}]"
        rule = {
            "enabled": True,
            "scope": str(args.get("scope", "request")).strip().lower() or "request",
            "type": str(args.get("type", "body")).strip().lower() or "body",
            "match": match_val,
            "replace": replace_val,
            "comment": tagged_comment,
        }
        settings.add_match_replace(rule)
        rules = settings.get_match_replace() or []
        index = len(rules) - 1
        logger.info("match_replace: copilot added rule", index=index, match=match_val[:60],
                     replace=replace_val[:60])
        return {"ok": True, "index": index, "rule": rule}

    if action == "remove":
        index = args.get("index")
        if index is None:
            return {"ok": False, "error": "index is required for action=remove"}
        try:
            index = int(index)
        except (TypeError, ValueError):
            return {"ok": False, "error": "index must be an integer"}
        rules = settings.get_match_replace() or []
        if index < 0 or index >= len(rules):
            return {"ok": False, "error": f"index {index} out of range (0-{len(rules)-1})"}
        settings.remove_match_replace(index)
        logger.info("match_replace: copilot removed rule", index=index)
        return {"ok": True, "removed_index": index}

    if action == "clear":
        all_rules = settings.get_match_replace() or []
        # Remove copilot-tagged rules in reverse order so indices stay stable.
        removed = 0
        for i in reversed(range(len(all_rules))):
            if all_rules[i].get("comment", "").startswith(f"[{_COPILOT_TAG}]"):
                settings.remove_match_replace(i)
                removed += 1
        logger.info("match_replace: copilot cleared rules", removed=removed)
        return {"ok": True, "removed": removed}

    return {"ok": False, "error": f"unknown action: {action}"}


register(Tool(
    name="match_replace",
    description=(
        "Add, list, remove, or clear proxy match-and-replace rules. Use this when you need "
        "the proxy to transparently inject a payload into traffic while the browser submits a "
        "form normally (preserving CSRF tokens). For example: add a rule that swaps the "
        "BodyHtml field, then browser_click the submit button — the proxy injects the payload "
        "and the form's ComposeToken stays valid.\n"
        "Rules added by this tool are tagged and auto-cleaned at session end. They do NOT "
        "affect scanner/agent probes (only proxied browser traffic).\n"
        "Actions: add (scope/type/match/replace/comment), list, remove (index), clear."
    ),
    input_schema=_SCHEMA,
    handler=_match_replace,
    tags=["active"],
))
