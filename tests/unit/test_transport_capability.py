"""Unit tests for the learned transport-capability store
(dast/session/transport_capability.py): record/resolve round-trip, sub-app + task keying,
parent-domain fallback, specificity widening, unknown host, malformed-line tolerance, and the
input-validation / never-raises contract. The _DIR is redirected to tmp by the autouse
_isolate_transport_capability fixture."""

from __future__ import annotations

from dast.session import transport_capability as tc


def test_record_and_resolve_host_level():
    assert tc.record_capability("https://app.example.com/x", auth="browser",
                                prefer="browser", reason="api_401_browser_ok") == "app.example.com"
    rec = tc.capability_for("app.example.com", "/x")
    assert rec is not None
    assert rec["prefer"] == "browser" and rec["auth"] == "browser"
    assert rec["sub_app"] == "" and rec["host"] == "app.example.com"


def test_record_rejects_bad_input():
    assert tc.record_capability("", auth="browser", prefer="browser") is None
    assert tc.record_capability("app.example.com", auth="bogus", prefer="browser") is None
    assert tc.record_capability("app.example.com", auth="api", prefer="bogus") is None


def test_unknown_host_resolves_to_none():
    assert tc.capability_for("never-seen.example.com", "/") is None
    assert tc.capability_for("", "/") is None


def test_sub_app_keying_is_distinct():
    # modstore and ccm share one host; a browser-only quirk of modstore must not flip ccm.
    tc.record_capability("https://app.acme.com/modstore/graphql", auth="browser",
                         prefer="browser", reason="modstore needs browser")
    tc.record_capability("https://app.acme.com/customercontent/x", auth="api", prefer="api")
    modstore = tc.capability_for("app.acme.com", "/modstore/graphql")
    ccm = tc.capability_for("app.acme.com", "/customercontent/x")
    assert modstore["sub_app"] == "modstore" and modstore["prefer"] == "browser"
    assert ccm["sub_app"] == "ccm" and ccm["prefer"] == "api"


def test_specificity_widening_falls_back_to_host_level():
    # A host-level record serves a sub-app path when no per-sub-app record exists.
    tc.record_capability("https://app.widen.com/", auth="browser", prefer="browser")
    rec = tc.capability_for("app.widen.com", "/modstore/graphql")
    assert rec is not None and rec["sub_app"] == "" and rec["prefer"] == "browser"


def test_task_specificity():
    tc.record_capability("https://app.task.com/", task="graphql", auth="api", prefer="api")
    tc.record_capability("https://app.task.com/", auth="browser", prefer="browser")
    # Exact task match wins over the task-agnostic host-level record.
    graphql = tc.capability_for("app.task.com", "/", task="graphql")
    assert graphql["task"] == "graphql" and graphql["prefer"] == "api"
    # A different/absent task falls through to the host-level record.
    other = tc.capability_for("app.task.com", "/")
    assert other["task"] == "" and other["prefer"] == "browser"


def test_parent_domain_fallback():
    # A record on the parent domain serves a subdomain, but not a bare TLD.
    tc.record_capability("https://phisher.example.com/", auth="browser", prefer="browser")
    rec = tc.capability_for("api.phisher.example.com", "/")
    assert rec is not None and rec["host"] == "phisher.example.com" and rec["prefer"] == "browser"


def test_more_specific_host_beats_parent():
    tc.record_capability("https://phisher.example.com/", auth="api", prefer="api")
    tc.record_capability("https://api.phisher.example.com/", auth="browser", prefer="browser")
    rec = tc.capability_for("api.phisher.example.com", "/")
    assert rec["host"] == "api.phisher.example.com" and rec["prefer"] == "browser"


def test_freshest_record_wins_within_a_tier():
    tc.record_capability("https://app.fresh.com/", auth="api", prefer="api")
    tc.record_capability("https://app.fresh.com/", auth="browser", prefer="browser")
    assert tc.capability_for("app.fresh.com", "/")["prefer"] == "browser"   # most recent


def test_malformed_lines_tolerated(tmp_path):
    tc.record_capability("https://app.bad.com/", auth="browser", prefer="browser")
    path = tc._path_for("app.bad.com")
    with path.open("a", encoding="utf-8") as handle:
        handle.write("not json\n")
    # The malformed trailing line is skipped; the good record still resolves.
    rec = tc.capability_for("app.bad.com", "/")
    assert rec is not None and rec["prefer"] == "browser"
