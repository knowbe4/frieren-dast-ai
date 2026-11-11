"""Unit tests for dast.session.subapp_map — the local, operator-supplied sub-app/service map
loader. Uses only generic PLACEHOLDER topology (never real target service names)."""

from __future__ import annotations

import json

from dast.session import subapp_map


def _use_config(tmp_path, monkeypatch, content: str):
    """Point the loader at a tmp config holding *content* (raw text) and clear the cache."""
    cfg = tmp_path / "subapp_map.json"
    cfg.write_text(content, encoding="utf-8")
    monkeypatch.setattr(subapp_map, "_CONFIG_PATH", cfg)
    subapp_map._reset_cache()
    return cfg


def test_missing_config_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(subapp_map, "_CONFIG_PATH", tmp_path / "does-not-exist.json")
    subapp_map._reset_cache()
    assert subapp_map.subapp_prefixes() == ()
    assert subapp_map.app_map() == {}


def test_valid_config_parses_prefixes_and_app_map(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, json.dumps({
        "sub_apps": [
            {"prefix": "/alpha", "app": "alpha", "jwt_field": "alphaJwt", "probe": "/alpha/graphql"},
            {"app": "gamma", "jwt_field": "gammaJwt"},   # no prefix
        ]
    }))
    assert subapp_map.subapp_prefixes() == (("/alpha", "alpha"),)   # gamma excluded (no prefix)
    assert subapp_map.app_map() == {
        "alpha": {"field": "alphaJwt", "probe": "/alpha/graphql"},
        "gamma": {"field": "gammaJwt", "probe": ""},
    }


def test_entries_without_app_or_jwt_field_are_skipped(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, json.dumps({
        "sub_apps": [
            {"prefix": "/noapp"},                                   # no app -> dropped
            {"app": "nofield", "prefix": "/nofield"},               # no jwt_field -> not in app_map
            {"app": "ok", "prefix": "/ok", "jwt_field": "okJwt"},
        ]
    }))
    # {"prefix": "/noapp"} has no app -> dropped from both maps.
    # {"app": "nofield", "prefix": "/nofield"} has a prefix+app but no jwt_field -> in the prefix
    # map, not the app_map.
    assert set(dict(subapp_map.subapp_prefixes())) == {"/nofield", "/ok"}
    assert set(subapp_map.app_map()) == {"ok"}


def test_prime_descriptor_parses_and_defaults_method(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, json.dumps({
        "sub_apps": [
            {"app": "withprime", "jwt_field": "wpJwt",
             "prime": {"endpoint": "/wp/session", "cookie": "_wp_session", "referer": "/wp/area"}},
            {"app": "noprime", "jwt_field": "npJwt"},
        ]
    }))
    assert subapp_map.prime_for_app("withprime") == {
        "endpoint": "/wp/session", "method": "GET",   # method defaults to GET
        "cookie": "_wp_session", "referer": "/wp/area", "nav": "",
    }
    assert subapp_map.prime_for_app("noprime") is None
    assert subapp_map.prime_for_app("absent") is None


def test_prime_descriptor_browser_nav_mode(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, json.dumps({
        "sub_apps": [
            {"app": "navonly", "jwt_field": "nJwt", "prime": {"nav": "/app/area"}},
            {"app": "both", "jwt_field": "bJwt",
             "prime": {"nav": "/app/area", "endpoint": "/b/session", "cookie": "_b_session"}},
        ]
    }))
    # nav-only is valid (browser-activation mode); cookie fields blank.
    assert subapp_map.prime_for_app("navonly") == {
        "endpoint": "", "method": "", "cookie": "", "referer": "", "nav": "/app/area",
    }
    # both modes declared together.
    assert subapp_map.prime_for_app("both") == {
        "endpoint": "/b/session", "method": "GET", "cookie": "_b_session",
        "referer": "", "nav": "/app/area",
    }


def test_prime_descriptor_requires_a_mode(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, json.dumps({
        "sub_apps": [
            {"app": "a", "jwt_field": "aJwt", "prime": {"endpoint": "/a/session"}},   # cookie-mode incomplete, no nav
            {"app": "b", "jwt_field": "bJwt", "prime": {"cookie": "_b"}},              # cookie-mode incomplete, no nav
            {"app": "c", "jwt_field": "cJwt", "prime": "not-a-dict"},                  # wrong type
            {"app": "d", "jwt_field": "dJwt", "prime": {}},                            # empty
        ]
    }))
    for a in ("a", "b", "c", "d"):
        assert subapp_map.prime_for_app(a) is None


def test_malformed_config_never_raises(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, "{ this is : not json ]")
    assert subapp_map.subapp_prefixes() == ()
    assert subapp_map.app_map() == {}


def test_non_dict_json_is_empty(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, json.dumps(["not", "a", "dict"]))
    assert subapp_map.subapp_prefixes() == ()
    assert subapp_map.app_map() == {}


def test_site_field_parses_and_app_site(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, json.dumps({
        "sub_apps": [
            {"prefix": "/x", "app": "xapp", "jwt_field": "xJwt", "site": "siteA"},
            {"prefix": "/y", "app": "yapp", "jwt_field": "yJwt"},   # site-less (global)
        ]
    }))
    assert subapp_map.app_site("xapp") == "siteA"
    assert subapp_map.app_site("yapp") == ""
    assert subapp_map.app_site("absent") == ""


def test_subapp_prefixes_scoped_by_site(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, json.dumps({
        "sub_apps": [
            {"prefix": "/shared", "app": "a_shared", "jwt_field": "aJwt", "site": "siteA"},
            {"prefix": "/shared", "app": "b_shared", "jwt_field": "bJwt", "site": "siteB"},
            {"prefix": "/global", "app": "g", "jwt_field": "gJwt"},   # no site -> always included
        ]
    }))
    # no site -> all prefixes (unchanged behaviour)
    assert set(subapp_map.subapp_prefixes()) == {("/shared", "a_shared"), ("/shared", "b_shared"),
                                                 ("/global", "g")}
    # scoped to siteA -> siteA's entry + the site-less global, NOT siteB's
    assert set(subapp_map.subapp_prefixes("siteA")) == {("/shared", "a_shared"), ("/global", "g")}
    assert set(subapp_map.subapp_prefixes("siteB")) == {("/shared", "b_shared"), ("/global", "g")}


def test_subapp_for_path_site_scoping(tmp_path, monkeypatch):
    from dast.session.auth_provider import subapp_for_path
    _use_config(tmp_path, monkeypatch, json.dumps({
        "sub_apps": [
            {"prefix": "/shared", "app": "a_shared", "jwt_field": "aJwt", "site": "siteA"},
            {"prefix": "/shared", "app": "b_shared", "jwt_field": "bJwt", "site": "siteB"},
        ]
    }))
    # same prefix resolves to the correct sub-app per site; unscoped falls to first match
    assert subapp_for_path("/shared/graphql", "siteA") == "a_shared"
    assert subapp_for_path("/shared/graphql", "siteB") == "b_shared"
    assert subapp_for_path("/shared/graphql") in ("a_shared", "b_shared")   # unscoped: any match
