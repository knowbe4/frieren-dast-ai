"""Unit tests for the pure reflection-context classifier used by ``xss_probe``.

Covers ``classify_context`` across every context the tool branches on (html_body, attribute
single/double, js-string single/double, href, AngularJS expression), the ``quotes_encoded``
heuristic both ways, and ``detect_angular_version`` across dotted/dashed script filenames, the
``ng-version`` attribute, an inline ``angular.version`` object, and the no-Angular default.
"""

from __future__ import annotations

from dast.triage.xss_context import classify_context, detect_angular_version

MK = "ZZMARKZZ"


# ── classify_context: context detection ──────────────────────────────────────

def test_html_body_text_node():
    out = classify_context(f"<html><body><div>hello {MK} world</div></body></html>", MK)
    assert out["context"] == "html_body"
    assert out["quotes_encoded"] is False
    assert out["framework"] == ""


def test_attr_double_quote():
    out = classify_context(f'<input type="text" value="{MK}">', MK)
    assert out["context"] == "attr_double_quote"


def test_attr_single_quote():
    out = classify_context(f"<input type='text' value='{MK}'>", MK)
    assert out["context"] == "attr_single_quote"


def test_href_attribute_is_href_js():
    out = classify_context(f'<a href="{MK}">link</a>', MK)
    assert out["context"] == "href_js"


def test_src_attribute_is_href_js():
    out = classify_context(f'<img src="{MK}">', MK)
    assert out["context"] == "href_js"


def test_js_string_double():
    out = classify_context(f'<script>var x = "{MK}"; foo();</script>', MK)
    assert out["context"] == "js_string_double"


def test_js_string_single():
    out = classify_context(f"<script>var x = '{MK}'; foo();</script>", MK)
    assert out["context"] == "js_string_single"


def test_angular_expression_moustache():
    html = f'<div ng-app><p>{{{{ {MK} }}}}</p></div>'
    out = classify_context(html, MK)
    assert out["context"] == "angular_expression"
    assert out["framework"] == "angularjs"


def test_angular_expression_ng_controller_subtree():
    html = f'<div ng-controller="C"><span>{MK}</span></div>'
    out = classify_context(html, MK)
    assert out["context"] == "angular_expression"


def test_marker_not_found_is_unknown():
    out = classify_context("<html><body>nothing here</body></html>", MK)
    assert out["context"] == "unknown"


def test_angular_parse_sink_inside_js_string():
    # The marker's SURFACE context is a single-quoted JS string, but the <script> feeds it through
    # $parse(...) — the value reaches the Angular expression evaluator (a CSTI sink).
    html = (
        '<html><head><script src="/resources/js/angular_1-4-4.js"></script></head>'
        '<body ng-app>'
        f"<script>$scope.query[key] = '{MK}'; $scope.value = $parse(key)($scope.query);</script>"
        '</body></html>'
    )
    out = classify_context(html, MK)
    assert out["context"] == "js_string_single"  # surface context still reported
    assert out["angular_parse_sink"] is True
    assert out["framework"] == "angularjs"
    assert out["framework_version"] == "1.4"


def test_angular_parse_sink_false_for_plain_js_string():
    out = classify_context(f"<script>var x = '{MK}'; foo();</script>", MK)
    assert out["context"] == "js_string_single"
    assert out["angular_parse_sink"] is False


# ── classify_context: quotes_encoded heuristic ───────────────────────────────

def test_quotes_encoded_true_when_entities_and_no_raw_quote():
    out = classify_context(f"<div>{MK} then a &quot; encoded quote</div>", MK)
    assert out["quotes_encoded"] is True


def test_quotes_encoded_false_when_raw_quote_present():
    out = classify_context(f'<input value="{MK}">', MK)
    assert out["quotes_encoded"] is False


# ── detect_angular_version ───────────────────────────────────────────────────

def test_version_from_dashed_script_filename():
    html = '<script src="/resources/js/angular_1-4-4.js"></script>'
    assert detect_angular_version(html) == "1.4"


def test_version_from_dotted_script_filename():
    assert detect_angular_version('<script src="/vendor/angular-1.2.9.min.js"></script>') == "1.2"


def test_version_from_ng_version_attr():
    assert detect_angular_version('<html ng-version="1.5.8">') == "1.5"


def test_version_from_inline_angular_version():
    assert detect_angular_version("angular.version = {full: '1.3.20', major: 1, minor: 3}") == "1.3"


def test_version_1_6_maps_to_no_sandbox():
    assert detect_angular_version('<script src="/js/angular-1.6.0.js"></script>') == "no_sandbox"


def test_no_angular_maps_to_no_sandbox():
    assert detect_angular_version("<html><body>plain page</body></html>") == "no_sandbox"
