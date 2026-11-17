"""
Pure, testable reflection-context classification for the deterministic ``xss_probe`` tool.

``xss_probe`` first injects a benign unique marker, reads the rendered DOM, and must decide
*where* the marker landed so it can pick a context-correct payload (an HTML-body reflection
needs a tag; a reflection inside a double-quoted JS string needs to break out of that string;
an AngularJS text node needs a ``{{ }}`` sandbox escape, not an HTML tag). Getting the context
right is what makes the probe self-generate a working payload instead of spraying a static list.

Everything here is a pure function over the response text + the marker string — no browser, no
network — so the classification logic is unit-testable in isolation. The tool layer
(``dast/tools/xss_probe_tools.py``) wires these to the live browser.
"""

from __future__ import annotations

import re
from typing import Dict

# Encoded forms of a double/single quote. Their presence NEAR the marker (while a raw quote did
# not survive) means the app HTML-encodes quotes, so a payload that relies on a raw " or ' to
# break out would be neutralised — the tool then picks a quote-free vector instead.
_ENCODED_QUOTES = ("&quot;", "&#34;", "&#034;", "&#x22;", "&#39;", "&#039;", "&#x27;", "&apos;")

# Explicit AngularJS presence markers (any era). Used to decide whether a text-node reflection
# is actually an Angular interpolation target (CSTI) rather than plain HTML.
_ANGULAR_MARKERS = re.compile(
    r"ng-app|ng-controller|ng-bind|ng-model|ng-version|angularjs|angular\.js|"
    r"angular\.min\.js|angular[._\-/]v?\d",
    re.IGNORECASE,
)
# ng-app / ng-controller establish an Angular scope subtree whose text nodes are interpolated.
_NG_SUBTREE = re.compile(r"ng-app|ng-controller", re.IGNORECASE)

# An Angular expression-evaluator call. When the <script> that the marker landed in feeds the
# marker through $parse(...) / $eval(...), the value reaches the AngularJS expression evaluator —
# an Angular-CSTI sink — even though its SURFACE context is a plain JS string literal.
_PARSE_SINK = re.compile(r"\$parse\s*\(|\$eval\s*\(", re.IGNORECASE)

# Window (chars each side of the marker) for the quote-encoding heuristic.
_QUOTE_WINDOW = 100


def detect_angular_version(response_text: str) -> str:
    """Return the AngularJS ERA key for the version referenced on the page.

    Scans, in order: a ``ng-version`` attribute, an ``angular`` script filename (dotted OR
    dashed, e.g. ``/resources/js/angular_1-4-4.js`` or ``angular-1.4.4.min.js``), and an inline
    ``angular.version`` object. The detected ``major.minor`` maps to the sandbox-escape era the
    CSTI cheat-sheet vectors are keyed by: ``1.2`` / ``1.3`` / ``1.4`` / ``1.5``. AngularJS 1.0-1.1
    (no expression sandbox) and 1.6+ (sandbox removed), as well as a page with no detectable
    version, map to ``no_sandbox`` (the constructor.constructor escape works there)."""
    text = response_text or ""
    m = re.search(r'ng-version=["\']?(\d+)\.(\d+)', text, re.IGNORECASE)
    if not m:
        m = re.search(r"angular[._\-/]?v?(\d+)[._\-](\d+)", text, re.IGNORECASE)
    if not m:
        m = re.search(r"angular\.version[^}]*?(\d+)\.(\d+)", text, re.IGNORECASE)
    if not m:
        return "no_sandbox"
    major, minor = int(m.group(1)), int(m.group(2))
    if major == 1 and minor in (2, 3, 4, 5):
        return f"1.{minor}"
    return "no_sandbox"


def _enclosing_quote(segment: str) -> str:
    """The nearer of the last unescaped double/single quote in ``segment`` — the quote that
    encloses the string the marker landed in. Returns '"' , "'" or "" (none)."""
    dq = segment.rfind('"')
    sq = segment.rfind("'")
    if dq == -1 and sq == -1:
        return ""
    return '"' if dq > sq else "'"


def _quotes_encoded(text: str, marker_idx: int, marker: str) -> bool:
    """True when an encoded-quote entity appears near the marker while NO raw quote survived in
    that window — i.e. the app HTML-encodes quotes, so a raw-quote break-out would be defused."""
    lo = max(0, marker_idx - _QUOTE_WINDOW)
    hi = marker_idx + len(marker) + _QUOTE_WINDOW
    window = text[lo:hi]
    has_encoded = any(e in window for e in _ENCODED_QUOTES)
    has_raw = '"' in window or "'" in window
    return has_encoded and not has_raw


def _angular_parse_sink(text: str, marker_idx: int) -> bool:
    """True when the ``<script>`` block the marker sits inside evaluates the marker through
    AngularJS's expression evaluator (``$parse(...)`` / ``$eval(...)``).

    This catches the shape ``$scope.query[key] = '<marker>'; $scope.value = $parse(key)($scope.query)``
    where the marker's SURFACE context is a single/double-quoted JS string, yet the value still
    reaches the Angular expression evaluator — so the Angular CSTI vectors apply, not just a
    JS-string break-out. Scoped to the enclosing script block (content before AND after the marker,
    since the ``$parse`` call typically follows the assignment)."""
    lower = text.lower()
    script_open = lower.rfind("<script", 0, marker_idx)
    if script_open == -1:
        return False
    script_close = lower.rfind("</script", 0, marker_idx)
    if script_open <= script_close:  # marker is not inside an open <script> block
        return False
    end = lower.find("</script", marker_idx)
    region = text[script_open:(end if end != -1 else len(text))]
    return bool(_PARSE_SINK.search(region))


def classify_context(response_text: str, marker: str) -> Dict[str, object]:
    """Locate ``marker`` in the rendered response and classify the reflection context.

    Returns ``{context, quotes_encoded, angular_parse_sink, framework, framework_version,
    snippet}`` where ``context`` is one of: ``js_string_double`` / ``js_string_single`` (inside a
    <script> string literal, by the enclosing quote), ``href_js`` (an href=/src= attribute value),
    ``attr_double_quote`` / ``attr_single_quote`` (any other quoted attribute value),
    ``angular_expression`` (a text node inside an Angular ng-app/ng-controller subtree or a
    ``{{ }}`` interpolation), ``html_body`` (a plain HTML text node), or ``unknown`` (marker not
    found — the probe cannot proceed on this response).

    ``angular_parse_sink`` is True when the marker's enclosing ``<script>`` feeds it through
    ``$parse``/``$eval`` — the value reaches the Angular expression evaluator even though its
    surface ``context`` is a JS string, so Angular CSTI vectors must still be tried."""
    text = response_text or ""
    framework_version = detect_angular_version(text)
    angular_present = bool(_ANGULAR_MARKERS.search(text))
    framework = "angularjs" if angular_present else ""

    idx = text.find(marker)
    if idx == -1:
        return {"context": "unknown", "quotes_encoded": False, "angular_parse_sink": False,
                "framework": framework, "framework_version": framework_version, "snippet": ""}

    snippet = text[max(0, idx - 40):idx + len(marker) + 60]
    quotes_encoded = _quotes_encoded(text, idx, marker)
    angular_parse_sink = _angular_parse_sink(text, idx)

    lower = text.lower()
    # 1. Inside a <script>…</script> block → a JS string literal context.
    script_open = lower.rfind("<script", 0, idx)
    script_close = lower.rfind("</script", 0, idx)
    if script_open != -1 and script_open > script_close:
        quote = _enclosing_quote(text[script_open:idx])
        context = "js_string_single" if quote == "'" else "js_string_double"
        return {"context": context, "quotes_encoded": quotes_encoded,
                "angular_parse_sink": angular_parse_sink, "framework": framework,
                "framework_version": framework_version, "snippet": snippet}

    # 2. Inside an (unclosed) tag → an attribute value context.
    last_lt = text.rfind("<", 0, idx)
    last_gt = text.rfind(">", 0, idx)
    if last_lt != -1 and last_lt > last_gt:
        tag_seg = text[last_lt:idx]
        m = re.search(r"([\w:-]+)\s*=\s*(\"|')?[^\"'<>]*$", tag_seg)
        attr_name = (m.group(1).lower() if m else "")
        quote = (m.group(2) if m and m.group(2) else "")
        if attr_name in ("href", "src"):
            context = "href_js"
        elif quote == "'":
            context = "attr_single_quote"
        else:
            context = "attr_double_quote"
        return {"context": context, "quotes_encoded": quotes_encoded,
                "angular_parse_sink": angular_parse_sink, "framework": framework,
                "framework_version": framework_version, "snippet": snippet}

    # 3. A text node. Inside an Angular subtree / {{ }} interpolation → CSTI; else plain HTML.
    moustache_open = text.rfind("{{", 0, idx)
    moustache_close = text.rfind("}}", 0, idx)
    inside_moustache = (moustache_open != -1 and moustache_open > moustache_close
                        and "}}" in text[idx:])
    if angular_present and (inside_moustache or _NG_SUBTREE.search(text)):
        context = "angular_expression"
    else:
        context = "html_body"
    return {"context": context, "quotes_encoded": quotes_encoded,
            "angular_parse_sink": angular_parse_sink, "framework": framework,
            "framework_version": framework_version, "snippet": snippet}
