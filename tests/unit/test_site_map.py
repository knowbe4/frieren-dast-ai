"""Unit tests for dast.session.site_map — the local product-group (site) identity map.
Uses only generic PLACEHOLDER topology (example.com), never real target names."""

from __future__ import annotations

import json

from dast.session import site_map


def _use_config(tmp_path, monkeypatch, content: str):
    cfg = tmp_path / "sites.json"
    cfg.write_text(content, encoding="utf-8")
    monkeypatch.setattr(site_map, "_CONFIG_PATH", cfg)
    site_map._reset_cache()
    return cfg


def test_missing_config_falls_back_to_host(tmp_path, monkeypatch):
    monkeypatch.setattr(site_map, "_CONFIG_PATH", tmp_path / "nope.json")
    site_map._reset_cache()
    assert site_map.site_for_host("admin.alpha.example.com") is None
    # site_key falls back to the bare host so unmapped hosts keep per-host behaviour
    assert site_map.site_key("admin.alpha.example.com") == "admin.alpha.example.com"
    assert site_map.sites() == {}


def test_exact_and_wildcard_grouping(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, json.dumps({
        "sites": [
            {"id": "egressish", "domains": ["admin.a.example.com", "*.esi.a.example.com",
                                            "*.api.a.example.com"]},
            {"id": "other", "domains": ["app.b.example.com"]},
        ]
    }))
    # exact match
    assert site_map.site_for_host("admin.a.example.com") == "egressish"
    # wildcard subdomain match (siblings share the site)
    assert site_map.site_for_host("us1.esi.a.example.com") == "egressish"
    assert site_map.site_for_host("https://eu.api.a.example.com/path") == "egressish"
    assert site_map.site_for_host("app.b.example.com") == "other"
    # site_key returns the group id for grouped hosts
    assert site_map.site_key("us1.esi.a.example.com") == "egressish"
    # unmapped host -> fallback to bare host
    assert site_map.site_for_host("lonely.example.com") is None
    assert site_map.site_key("lonely.example.com") == "lonely.example.com"


def test_wildcard_does_not_match_bare_suffix(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, json.dumps({
        "sites": [{"id": "s", "domains": ["*.esi.example.com"]}],
    }))
    assert site_map.site_for_host("x.esi.example.com") == "s"      # subdomain matches
    assert site_map.site_for_host("esi.example.com") is None       # the bare suffix does NOT


def test_most_specific_pattern_wins(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, json.dumps({
        "sites": [
            {"id": "broad", "domains": ["*.example.com"]},
            {"id": "specific", "domains": ["*.esi.example.com"]},
        ]
    }))
    # both patterns match x.esi.example.com; the longer (more specific) one wins
    assert site_map.site_for_host("x.esi.example.com") == "specific"
    # only the broad one matches here
    assert site_map.site_for_host("x.other.example.com") == "broad"


def test_normalise_host_strips_scheme_and_port():
    assert site_map.normalise_host("https://Admin.Example.com:443/x") == "admin.example.com"
    assert site_map.normalise_host("admin.example.com") == "admin.example.com"
    assert site_map.normalise_host("") == ""


def test_malformed_and_nondict_config_never_raise(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, "{ not json ]")
    assert site_map.sites() == {} and site_map.site_for_host("a.example.com") is None
    _use_config(tmp_path, monkeypatch, json.dumps(["not", "a", "dict"]))
    assert site_map.sites() == {}


def test_entries_without_id_or_domains_skipped(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, json.dumps({
        "sites": [
            {"domains": ["a.example.com"]},            # no id
            {"id": "noDomains"},                        # no domains
            {"id": "ok", "domains": ["ok.example.com"]},
        ]
    }))
    assert set(site_map.sites()) == {"ok"}
