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


def test_malformed_config_never_raises(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, "{ this is : not json ]")
    assert subapp_map.subapp_prefixes() == ()
    assert subapp_map.app_map() == {}


def test_non_dict_json_is_empty(tmp_path, monkeypatch):
    _use_config(tmp_path, monkeypatch, json.dumps(["not", "a", "dict"]))
    assert subapp_map.subapp_prefixes() == ()
    assert subapp_map.app_map() == {}
