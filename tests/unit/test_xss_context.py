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


def test_angular_html_injection_raw_text_in_ng_controller_subtree():
    # A marker reflected RAW as an HTML text node inside an Angular subtree is NOT an interpolation
    # target — it is a raw-HTML injection that Angular $compiles on the next digest (an element
    # directive gadget fires). (Previously mislabelled ``angular_expression`` because an
    # ng-app/ng-controller ANYWHERE matched — the bug this corrects.)
    html = f'<div ng-controller="C"><span>{MK}</span></div>'
    out = classify_context(html, MK)
    assert out["context"] == "angular_html_injection"
    assert out["framework"] == "angularjs"


def test_marker_not_found_is_unknown():
    out = classify_context("<html><body>nothing here</body></html>", MK)
    assert out["context"] == "unknown"
    # The CSP flags are present on EVERY return dict, including the unknown-marker short-circuit.
    assert out["ng_csp"] is False
    assert out["csp_present"] is False


def test_angular_html_injection_moustache_stays_angular_expression():
    # A marker INSIDE actual ``{{ }}`` remains ``angular_expression`` even in a CSP page — it is the
    # interpolation target itself, not a raw-HTML injection.
    html = f'<body ng-app ng-csp><p>{{{{ {MK} }}}}</p></body>'
    out = classify_context(html, MK)
    assert out["context"] == "angular_expression"
    assert out["csp_present"] is True


# ── classify_context: CSP detection (ng_csp / csp_present) ───────────────────

def test_ng_csp_attr_sets_csp_present():
    html = f'<body ng-app ng-csp><h1>0 results for {MK}</h1></body>'
    out = classify_context(html, MK)
    assert out["context"] == "angular_html_injection"
    assert out["ng_csp"] is True
    assert out["csp_present"] is True


def test_meta_csp_sets_csp_present_without_ng_csp():
    html = (f'<head><meta http-equiv="Content-Security-Policy" content="script-src \'self\'"></head>'
            f'<body ng-app><h1>0 results for {MK}</h1></body>')
    out = classify_context(html, MK)
    assert out["csp_present"] is True
    assert out["ng_csp"] is False


def test_no_csp_flags_default_false():
    out = classify_context(f"<body ng-app><h1>{MK}</h1></body>", MK)
    assert out["ng_csp"] is False
    assert out["csp_present"] is False


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
    assert out["angular_parse_key_sink"] is False


def test_angular_parse_key_sink_when_parse_arg_is_param_name():
    # The client $parses a VARIABLE (the query-param NAME), not a string literal:
    #   key = <paramName>; $scope.query[key] = '<marker>'; $scope.value = $parse(key)($scope.query)
    # → the param KEY is the evaluated Angular expression, so angular_parse_key_sink is set.
    html = (
        '<html><head><script src="/resources/js/angular_1-4-4.js"></script></head>'
        '<body ng-app>'
        f"<script>$scope.query[key] = '{MK}'; $scope.value = $parse(key)($scope.query);</script>"
        '</body></html>'
    )
    out = classify_context(html, MK)
    assert out["context"] == "js_string_single"       # surface context still reported
    assert out["angular_parse_sink"] is True
    assert out["angular_parse_key_sink"] is True
    assert out["framework_version"] == "1.4"


def test_angular_parse_key_sink_false_for_string_literal_arg():
    # $parse('search') feeds a STRING LITERAL (a fixed expression), not a param key → not a key sink
    # even though it is still a $parse sink.
    html = (
        '<html><body ng-app>'
        f"<script>$scope.query['search'] = '{MK}'; $scope.value = $parse('search')($scope.query);</script>"
        '</body></html>'
    )
    out = classify_context(html, MK)
    assert out["angular_parse_sink"] is True
    assert out["angular_parse_key_sink"] is False


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
