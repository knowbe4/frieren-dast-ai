"""
Proxy session persistence — save/load named sessions as JSON files.

A session file captures:
  - Metadata: name, created_at, description, proxy settings snapshot
  - All ProxyEntry records (with full request/response bodies)
  - Cookie jar

Stored at: ~/.dast-ai/sessions/<session_id>.json
Session ID: ISO timestamp slug + sanitized name, e.g. 20260513-143021-my-app
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_SESSIONS_DIR = Path.home() / ".dast-ai" / "sessions"


def _sessions_dir() -> Path:
    _SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    return _SESSIONS_DIR


def _make_id(name: str) -> str:
    slug = re.sub(r"[^\w\-]", "-", name.lower().strip())
    slug = re.sub(r"-+", "-", slug).strip("-")[:40]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{ts}-{slug}" if slug else ts


def _serialize_session_intelligence(si) -> dict:
    """Convert SessionIntelligence to a JSON-serializable dict."""
    result = {}
    for host in si.all_hosts():
        intel = si.get(host)
        result[host] = {
            "confirmed_vulns": {
                f"{p}|{param}": types
                for (p, param), types in intel.confirmed_vulns.items()
            },
            "effective_attack_types": list(intel.effective_attack_types),
            "ineffective_attack_types": list(intel.ineffective_attack_types),
            "structural_errors": {
                f"{p}|{op}" if op else p: errs
                for (p, op), errs in intel.structural_errors.items()
            },
            "waf_observations": intel.waf_observations,
            "auth_headers_seen": list(intel.auth_headers_seen),
            "rate_limit_observed": intel.rate_limit_observed,
            "graphql_endpoints": list(intel.graphql_endpoints),
        }
    return result


def save_session(
    store,
    settings,
    name: str,
    description: str = "",
    session_id: Optional[str] = None,
) -> dict:
    """
    Persist the current SessionStore + ProxySettings to disk.

    Returns the session metadata dict.
    """
    sid = session_id or _make_id(name)
    path = _sessions_dir() / f"{sid}.json"

    entries = []
    for entry in store.all_entries():
        d = entry.to_dict(include_bodies=True)
        entries.append(d)

    data = {
        "id": sid,
        "name": name,
        "description": description,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "entry_count": len(entries),
        "settings": settings.to_dict() if settings else {},
        "entries": entries,
        "cookies": getattr(store, "_cookies", {}),
    }

    si = getattr(store, "session_intelligence", None)
    if si is not None:
        data["session_intelligence"] = _serialize_session_intelligence(si)

    # AI context: app profiles and threat models per host
    discovery = getattr(store, "discovery_engine", None)
    if discovery is not None:
        app_profiles = {}
        threat_models = {}
        try:
            for host, profile in getattr(discovery, "_app_profiles", {}).items():
                app_profiles[host] = profile.__dict__ if hasattr(profile, "__dict__") else profile
        except Exception:
            pass
        try:
            for host, tm in getattr(discovery, "_threat_models", {}).items():
                threat_models[host] = tm.__dict__ if hasattr(tm, "__dict__") else tm
        except Exception:
            pass
        data["app_profiles"] = app_profiles
        data["threat_models"] = threat_models

    # AI suggestions
    data["active_suggestions"] = list(getattr(store, "active_suggestions", []))

    # Named sessions (multi-user IDOR testing)
    named = getattr(store, "named_sessions", {})
    data["named_sessions"] = {
        name: {
            "name": s.name,
            "role": s.role,
            "cookies": s.cookies,
            "auth_headers": s.auth_headers,
            "created_at": s.created_at,
        }
        for name, s in named.items()
    }

    # System logs (last 500 events)
    plugin_mgr = getattr(store, "_plugin_manager_ref", None)
    if plugin_mgr is None:
        # Try to get via store reference set at startup
        plugin_mgr = getattr(store, "_plugin_manager", None)
    if plugin_mgr is not None:
        try:
            data["event_log"] = list(getattr(plugin_mgr, "_event_log", []))
        except Exception:
            pass

    path.write_text(json.dumps(data, indent=2, default=str))
    return _meta(data, path)


def list_sessions() -> list[dict]:
    """Return metadata for all saved sessions, newest first."""
    result = []
    for f in _sessions_dir().glob("*.json"):
        try:
            raw = json.loads(f.read_text())
            result.append(_meta(raw))
        except Exception:
            continue
    return sorted(result, key=lambda x: x.get("created_at", ""), reverse=True)


def load_session(session_id: str) -> Optional[dict]:
    """Return full session data including entries, or None if not found."""
    path = _sessions_dir() / f"{session_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def delete_session(session_id: str) -> bool:
    path = _sessions_dir() / f"{session_id}.json"
    if path.exists():
        path.unlink()
        return True
    return False


def get_session_path(session_id: str) -> Optional[Path]:
    path = _sessions_dir() / f"{session_id}.json"
    return path if path.exists() else None


def _meta(data: dict, path: Optional[Path] = None) -> dict:
    sid = data.get("id", "")
    resolved_path = path or (_sessions_dir() / f"{sid}.json")
    return {
        "id": sid,
        "name": data.get("name", ""),
        "description": data.get("description", ""),
        "created_at": data.get("created_at", ""),
        "entry_count": data.get("entry_count", len(data.get("entries", []))),
        "file_size": _file_size(sid),
        "path": str(resolved_path),
    }


def _file_size(session_id: str) -> int:
    try:
        p = _sessions_dir() / f"{session_id}.json"
        return p.stat().st_size
    except Exception:
        return 0
