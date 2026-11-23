"""Rewrite-rule tests (3-I): matchers, stable ids, hit counters, integrity skips.

Extends test_proxy_settings.py (which keeps the legacy behavior coverage) with
the ARTEX-style upgrades: rule-level matchers (methods/host/url_regex/status),
fired-only-on-change trace with stable ids, persisted hit counters, caps and
validation as ERRORS (never silent fallbacks), and the body-integrity skips
(oversized / encoded / no-body-allowed).
"""

from __future__ import annotations

import pytest

from dast.proxy import proxy_settings as ps_mod
from dast.proxy.proxy_settings import ProxySettings


@pytest.fixture(autouse=True)
def _no_disk(monkeypatch):
    """Never read/write the developer's real ~/.dast-ai/ (same as test_proxy_settings)."""
    monkeypatch.setattr(ProxySettings, "_load", lambda self: None)
    monkeypatch.setattr(ProxySettings, "_save", lambda self: None)


# Kept so the migration test can restore the REAL loader after the autouse no-op.
_REAL_LOAD = ProxySettings.__dict__["_load"]


@pytest.fixture
def ps():
    return ProxySettings()


def _rule(**kw):
    base = {"enabled": True, "scope": "request", "type": "header",
            "match": "X-Inject", "replace": "X-Injected: yes"}
    base.update(kw)
    return base


# ── matchers ─────────────────────────────────────────────────────────────────

class TestMatchers:
    def test_method_matcher(self, ps):
        rid = ps.add_match_replace(_rule(methods=["POST"]))["id"]
        _, _, _, f_get = ps.apply_to_request("https://a.com/", {"x": "X-Inject: 1"}, None, method="GET")
        _, _, _, f_post = ps.apply_to_request("https://a.com/", {"x": "X-Inject: 1"}, None, method="POST")
        assert f_get == []
        assert f_post == [rid]

    def test_host_suffix_glob_excludes_apex(self, ps):
        rid = ps.add_match_replace(_rule(host="*.example.com"))["id"]
        _, _, _, f_sub = ps.apply_to_request("https://sub.example.com/", {"x": "X-Inject: 1"}, None)
        _, _, _, f_apex = ps.apply_to_request("https://example.com/", {"x": "X-Inject: 1"}, None)
        _, _, _, f_other = ps.apply_to_request("https://other.com/", {"x": "X-Inject: 1"}, None)
        assert f_sub == [rid]
        assert f_apex == []  # *.example.com does NOT match the apex (ARTEX semantics)
        assert f_other == []

    def test_host_exact(self, ps):
        rid = ps.add_match_replace(_rule(host="api.example.com"))["id"]
        _, _, _, f_hit = ps.apply_to_request("https://API.example.com/", {"x": "X-Inject: 1"}, None)
        _, _, _, f_miss = ps.apply_to_request("https://sub.api.example.com/", {"x": "X-Inject: 1"}, None)
        assert f_hit == [rid]  # case-insensitive exact
        assert f_miss == []

    def test_url_regex_over_path_and_query(self, ps):
        rid = ps.add_match_replace(_rule(url_regex=r"^/api/v2/"))["id"]
        _, _, _, f_hit = ps.apply_to_request("https://a.com/api/v2/x?a=1", {"x": "X-Inject: 1"}, None)
        _, _, _, f_miss = ps.apply_to_request("https://a.com/api/v1/x", {"x": "X-Inject: 1"}, None)
        assert f_hit == [rid] and f_miss == []

    def test_fired_only_when_something_changed(self, ps):
        ps.add_match_replace(_rule(match="X-Nomatch"))
        _, _, _, fired = ps.apply_to_request("https://a.com/", {"x": "1"}, None)
        assert fired == []


# ── trace: stable ids + hit counters ─────────────────────────────────────────

class TestTrace:
    def test_fired_ids_are_stable_rule_ids(self, ps):
        rid = ps.add_match_replace(_rule())["id"]
        _, _, _, fired = ps.apply_to_request("https://a.com/", {"x": "X-Inject: 1"}, None)
        assert fired == [rid]

    def test_counters_bumped_and_visible(self, ps):
        rid = ps.add_match_replace(_rule())["id"]
        ps.apply_to_request("https://a.com/", {"x": "X-Inject: 1"}, None)
        ps.apply_to_request("https://a.com/", {"y": "X-Inject: 2"}, None)
        (rule,) = [r for r in ps.get_match_replace() if r["id"] == rid]
        assert rule["hits"] == 2
        assert rule["last_applied_at"]

    def test_remove_by_id_keeps_others(self, ps):
        r1 = ps.add_match_replace(_rule(match="A"))
        r2 = ps.add_match_replace(_rule(match="B"))
        ps.remove_match_replace(r1["id"])
        assert [r["id"] for r in ps.get_match_replace()] == [r2["id"]]

    def test_remove_unknown_is_idempotent(self, ps):
        ps.add_match_replace(_rule())
        ps.remove_match_replace("nope")
        assert len(ps.get_match_replace()) == 1


# ── validation as errors (never silent fallbacks) ────────────────────────────

class TestValidation:
    def test_invalid_match_regex_rejected(self, ps):
        with pytest.raises(ValueError):
            ps.add_match_replace(_rule(match="("))

    def test_invalid_url_regex_rejected(self, ps):
        with pytest.raises(ValueError):
            ps.add_match_replace(_rule(url_regex="["))

    def test_invalid_scope_rejected(self, ps):
        with pytest.raises(ValueError):
            ps.add_match_replace(_rule(scope="sideways"))

    def test_status_matcher_is_response_only(self, ps):
        with pytest.raises(ValueError):
            ps.add_match_replace(_rule(status="4xx"))

    def test_bad_status_shape_rejected(self, ps):
        with pytest.raises(ValueError):
            ps.add_match_replace(_rule(scope="response", status="4x"))

    def test_bad_host_glob_rejected(self, ps):
        with pytest.raises(ValueError):
            ps.add_match_replace(_rule(host="sub.*.com"))

    def test_rule_cap_is_an_error(self, ps, monkeypatch):
        monkeypatch.setattr(ps_mod, "_MAX_MR_RULES", 1)
        ps.add_match_replace(_rule())
        with pytest.raises(ValueError):
            ps.add_match_replace(_rule(match="other"))

    def test_enabled_cap_is_an_error(self, ps, monkeypatch):
        monkeypatch.setattr(ps_mod, "_MAX_MR_ENABLED", 1)
        ps.add_match_replace(_rule())
        with pytest.raises(ValueError):
            ps.add_match_replace(_rule(match="other", enabled=True))


# ── body integrity skips ─────────────────────────────────────────────────────

class TestBodyIntegrity:
    def test_oversized_body_skips_body_rule(self, ps, monkeypatch):
        monkeypatch.setattr(ps_mod, "_MR_BODY_LIMIT", 8)
        ps.add_match_replace(_rule(type="body", match="secret", replace="gone"))
        _, _, b, fired = ps.apply_to_request(
            "https://a.com/", {}, b"my secret here", method="GET")
        assert fired == []
        assert b == b"my secret here"  # stream untouched

    def test_encoded_body_skips_body_rule(self, ps):
        ps.add_match_replace(_rule(type="body", match="secret", replace="gone"))
        _, _, _, fired = ps.apply_to_request(
            "https://a.com/", {}, b"my secret", method="GET", content_encoding="gzip")
        assert fired == []

    def test_response_body_rule_skips_on_no_body_status(self, ps):
        ps.add_match_replace(_rule(scope="response", type="body", match="a", replace="b"))
        _, b, fired = ps.apply_to_response(
            "https://a.com/x", {}, b"aaa", method="GET", status=304)
        assert fired == [] and b == b"aaa"

    def test_response_body_rule_skips_on_head(self, ps):
        ps.add_match_replace(_rule(scope="response", type="body", match="a", replace="b"))
        _, b, fired = ps.apply_to_response(
            "https://a.com/x", {}, b"aaa", method="HEAD", status=200)
        assert fired == [] and b == b"aaa"


# ── response phase (status matcher + the url fix) ────────────────────────────

class TestResponsePhase:
    def test_status_matcher_and_fired_trace(self, ps):
        # stored headers are lowercase — the rule regex must match that shape
        rid = ps.add_match_replace(_rule(
            scope="response", type="header",
            match="x-hit: 0", replace="x-hit: yes", status="4xx"))["id"]
        h, _, fired = ps.apply_to_response(
            "https://a.com/x", {"x-hit": "0"}, b"", method="GET", status=404)
        assert fired == [rid] and h.get("x-hit") == "yes"
        _, _, fired = ps.apply_to_response(
            "https://a.com/x", {"x-hit": "0"}, b"", method="GET", status=200)
        assert fired == []

    def test_response_rule_scoped_to_other_host_does_not_fire(self, ps):
        ps.add_match_replace(_rule(scope="response", type="header",
                                   match="X-Hit: 0", replace="X-Hit: yes",
                                   host="api.example.com"))
        _, _, fired = ps.apply_to_response(
            "https://other.com/x", {"x-hit": "0"}, b"", method="GET", status=200)
        assert fired == []


# ── legacy migration ─────────────────────────────────────────────────────────

class TestMigration:
    def test_legacy_rules_get_ids_and_defaults_on_load(self, monkeypatch, tmp_path):
        cfg = tmp_path / "proxy-settings.json"
        cfg.write_text('{"match_replace": [{"enabled": true, "scope": "request",'
                       ' "type": "header", "match": "A", "replace": "B"}]}')
        monkeypatch.setattr(ps_mod, "_SETTINGS_PATH", cfg)
        # restore the real loader (the autouse fixture no-ops it for isolation)
        monkeypatch.setattr(ProxySettings, "_load", _REAL_LOAD)
        s = ProxySettings()
        (rule,) = s.get_match_replace()
        assert rule.get("id")
        assert rule.get("hits") == 0
        assert rule.get("methods") == []
        assert rule.get("last_applied_at") == ""


# ── API surface (ids, 400/404) ───────────────────────────────────────────────

class TestApi:
    def _client(self, ps):
        from types import SimpleNamespace

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from dast.proxy.api.settings_routes import make_router

        ctx = SimpleNamespace(settings=ps, scan_queue_state=None,
                              mcp_last_heartbeat=[0.0], _scan_cfg={})
        app = FastAPI()
        app.include_router(make_router(ctx))
        return TestClient(app)

    def test_add_invalid_rule_returns_400(self, ps):
        c = self._client(ps)
        r = c.post("/api/settings/match-replace", json=_rule(match="("))
        assert r.status_code == 400
        assert "regex" in r.json()["error"]

    def test_add_returns_rule_with_stable_id(self, ps):
        c = self._client(ps)
        r = c.post("/api/settings/match-replace", json=_rule())
        assert r.status_code == 200
        assert r.json()["rule"]["id"]

    def test_delete_unknown_id_returns_404(self, ps):
        c = self._client(ps)
        ps.add_match_replace(_rule())
        r = c.request("DELETE", "/api/settings/match-replace", json={"id": "nope"})
        assert r.status_code == 404

    def test_toggle_by_id(self, ps):
        c = self._client(ps)
        rid = c.post("/api/settings/match-replace", json=_rule()).json()["rule"]["id"]
        r = c.post("/api/settings/match-replace/toggle",
                   json={"id": rid, "enabled": False})
        assert r.status_code == 200
        (rule,) = ps.get_match_replace()
        assert rule["enabled"] is False


# ── entry trace field ────────────────────────────────────────────────────────

def test_entry_persists_rewritten_by():
    from dast.proxy.session_store import ProxyEntry

    entry = ProxyEntry.from_dict({"id": "1", "method": "GET", "url": "https://a.com/",
                                  "host": "a.com", "path": "/"})
    entry.rewritten_by = ["rule-1"]
    restored = ProxyEntry.from_dict(entry.to_dict())
    assert restored.rewritten_by == ["rule-1"]
