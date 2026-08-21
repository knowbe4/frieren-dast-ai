"""
Persistent proxy settings — bypass domains, hidden extensions, and structured scope rules.

Tool settings (bypass domains, hidden extensions) are global and stored at:
  ~/.dast-ai/proxy-settings.json

Project settings (scope rules) are saved/loaded per project at:
  ~/.dast-ai/projects/<slug>.json
"""

import fnmatch
import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_SETTINGS_PATH = Path.home() / ".dast-ai" / "proxy-settings.json"
_PROJECTS_DIR  = Path.home() / ".dast-ai" / "projects"

# Bundled scope presets — one per organization, auto-discovered from
# dast/scope_presets/*.json and written to ~/.dast-ai/projects/ on first run
# if absent. Each org drops its own preset file there; none are bundled by
# default. See dast/scope_presets/example.json.example for the schema.
_PRESETS_DIR = Path(__file__).parent.parent / "scope_presets"


def _load_bundled_presets() -> dict:
    """Load org scope presets from dast/scope_presets/*.json, keyed by slug."""
    presets: dict = {}
    if not _PRESETS_DIR.is_dir():
        return presets
    for json_path in sorted(_PRESETS_DIR.glob("*.json")):
        slug = json_path.stem
        try:
            presets[slug] = json.loads(json_path.read_text())
        except Exception as exc:
            logger.warning("failed to load scope preset", file=str(json_path), error=str(exc))
    return presets


_BUNDLED_PRESETS: dict = _load_bundled_presets()

_DEFAULT_BYPASS: Set[str] = {
    # OAuth / SSO providers that reject certificate substitution
    "accounts.google.com",
    "login.microsoftonline.com",
    "appleid.apple.com",
    "login.live.com",
    "auth.atlassian.com",
    "ocsp.apple.com",
    # LaunchDarkly — SSE streaming connections; buffering them breaks feature flags
    "app.launchdarkly.com",
    "clientstream.launchdarkly.com",
    "events.launchdarkly.com",
    "stream.launchdarkly.com",
}

_DEFAULT_HIDDEN_EXT: Set[str] = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".svg", ".map",
    ".webp", ".avif", ".mp4", ".mp3", ".pdf",
}


def _slug(name: str) -> str:
    """Convert a project name to a filesystem-safe slug."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", name.strip())[:64]


def _matches_field(value: str, pattern: str) -> bool:
    """
    Return True if value matches pattern.
    Empty pattern always matches.
    Tries fnmatch first; if the pattern contains regex metacharacters not used
    by fnmatch (^, $, +, (, ), [, ]), it falls back to re.search.
    """
    if not pattern:
        return True
    # Detect regex intent: presence of ^, $, +, (, ), [, ] or the sequence .*
    # Plain globs only use * and ? — everything else is treated as a regex.
    has_regex_chars = bool(re.search(r"[\^\$\+\(\)\[\]]", pattern)) or r"\." in pattern or re.search(r"\.\*|\.\+|\.\?", pattern)
    if not has_regex_chars:
        return fnmatch.fnmatch(value.lower(), pattern.lower())
    try:
        return bool(re.search(pattern, value, re.IGNORECASE))
    except re.error:
        return fnmatch.fnmatch(value.lower(), pattern.lower())


def _rule_matches_url(rule: dict, url: str) -> bool:
    """
    Return True if the structured scope rule matches the given URL.

    rule keys: enabled, protocol ("http"|"https"|"any"), host, port, file, kind
    """
    if not rule.get("enabled", True):
        return False
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        host   = parsed.hostname or ""
        port   = str(parsed.port) if parsed.port else ("443" if scheme == "https" else "80")
        path   = parsed.path or "/"
    except Exception:
        return False

    rule_protocol = rule.get("protocol", "any").lower()
    if rule_protocol not in ("any", ""):
        if rule_protocol != scheme:
            return False

    if not _matches_field(host, rule.get("host", "")):
        return False
    if not _matches_field(port, rule.get("port", "")):
        return False
    if not _matches_field(path, rule.get("file", "")):
        return False
    return True


def _install_bundled_presets() -> None:
    """Write bundled presets to ~/.dast-ai/projects/ if they don't exist yet."""
    _PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    for slug, preset in _BUNDLED_PRESETS.items():
        path = _PROJECTS_DIR / f"{slug}.json"
        if not path.exists():
            data = dict(preset)
            data["created_at"] = datetime.now(timezone.utc).isoformat()
            data["rule_count"] = len(preset["scope_rules"])
            path.write_text(json.dumps(data, indent=2))


def _apply_rule(
    rule: dict,
    url: str,
    headers: dict,
    body: Optional[bytes],
) -> Tuple[str, dict, Optional[bytes]]:
    """Apply a single match/replace rule to the given url/headers/body."""
    rtype   = rule.get("type", "header")
    pattern = rule.get("match", "")
    repl    = rule.get("replace", "")

    def _sub(text: str) -> str:
        if not pattern:
            # No match regex — treat replace as a value to append/set,
            # only meaningful for header type where the rule also needs a header name.
            # For body/url with empty match, skip to avoid replacing entire content.
            return text
        try:
            return re.sub(pattern, repl, text)
        except re.error:
            return text

    if rtype == "url":
        url = _sub(url)

    elif rtype == "header":
        new_headers = {}
        for k, v in headers.items():
            subbed = _sub(f"{k}: {v}")
            if ": " in subbed:
                nk, nv = subbed.split(": ", 1)
                new_headers[nk.strip().lower()] = nv.strip()
            else:
                new_headers[k] = v
        headers = new_headers

    elif rtype == "body" and body is not None:
        try:
            text = body.decode("utf-8", errors="replace")
            text = _sub(text)
            body = text.encode("utf-8")
        except Exception:
            pass

    return url, headers, body


def _convert_old_scope_pattern(pattern: str) -> dict:
    """Convert a legacy flat scope string into a structured include rule."""
    return {
        "enabled": True,
        "protocol": "any",
        "host": pattern.strip(),
        "port": "",
        "file": "",
        "kind": "include",
    }


class ProxySettings:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._bypass: Set[str] = set(_DEFAULT_BYPASS)
        self._hidden_ext: Set[str] = set(_DEFAULT_HIDDEN_EXT)
        # Structured scope rules; each is a dict with keys:
        #   enabled, protocol, host, port, file, kind ("include"|"exclude")
        self._scope_rules: List[dict] = []
        # Match & Replace rules; each is a dict with keys:
        #   enabled, scope ("request"|"response"|"both"), type ("header"|"body"|"url"),
        #   match (regex string — empty matches everything), replace (replacement string)
        self._match_replace: List[dict] = []
        # Proxy listener bind host. "127.0.0.1" keeps the proxy loopback-only;
        # a LAN IP or "0.0.0.0" exposes it to other machines (see set_bind_host).
        self._bind_host: str = "127.0.0.1"
        # Persisted proxy listener port. 0 = unset → use the runtime default
        # (CLI --proxy-port / free-port fallback) instead of a saved value.
        self._bind_port: int = 0
        _install_bundled_presets()
        self._load()

    # ── persistence ────────────────────────────────────────────────────

    def _load(self) -> None:
        if not _SETTINGS_PATH.exists():
            return
        try:
            data = json.loads(_SETTINGS_PATH.read_text())
            with self._lock:
                self._bypass     = set(data.get("bypass_domains", list(_DEFAULT_BYPASS)))
                self._hidden_ext = set(data.get("hidden_extensions", list(_DEFAULT_HIDDEN_EXT)))
                # Migrate legacy flat scope list to structured rules
                if "scope_rules" in data:
                    self._scope_rules = list(data["scope_rules"])
                elif "scope" in data:
                    self._scope_rules = [
                        _convert_old_scope_pattern(p) for p in data["scope"]
                    ]
                self._match_replace = list(data.get("match_replace", []))
                self._bind_host = str(data.get("bind_host", "127.0.0.1")) or "127.0.0.1"
                try:
                    self._bind_port = int(data.get("bind_port", 0) or 0)
                except (TypeError, ValueError):
                    self._bind_port = 0
        except Exception:
            pass

    def _save(self) -> None:
        _SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            data = {
                "bypass_domains":    sorted(self._bypass),
                "hidden_extensions": sorted(self._hidden_ext),
                "scope_rules":       list(self._scope_rules),
                "match_replace":     list(self._match_replace),
                "bind_host":         self._bind_host,
                "bind_port":         self._bind_port,
            }
        _SETTINGS_PATH.write_text(json.dumps(data, indent=2))

    # ── queries ────────────────────────────────────────────────────────

    def is_bypassed(self, host: str) -> bool:
        host = host.lower()
        with self._lock:
            return host in self._bypass or any(
                host == d or host.endswith("." + d) for d in self._bypass
            )

    def is_hidden(self, path: str) -> bool:
        """Return True if the path's extension is in the hidden list."""
        bare = path.split("?")[0].split("#")[0]
        if "." not in bare:
            return False
        ext = "." + bare.rsplit(".", 1)[-1].lower()
        with self._lock:
            return ext in self._hidden_ext

    def is_in_scope(self, url: str) -> bool:
        """
        Return True if url is in scope according to structured rules.

        Logic:
        - No include rules: everything is in scope.
        - URL must match at least one enabled include rule.
        - Exclude rules take priority: if any enabled exclude rule matches, return False.
        """
        with self._lock:
            include_rules = [r for r in self._scope_rules if r.get("kind") == "include" and r.get("enabled", True)]
            exclude_rules = [r for r in self._scope_rules if r.get("kind") == "exclude" and r.get("enabled", True)]

        if not include_rules:
            # No scope filter active — check excludes only
            for rule in exclude_rules:
                if _rule_matches_url(rule, url):
                    return False
            return True

        included = any(_rule_matches_url(r, url) for r in include_rules)
        if not included:
            return False

        for rule in exclude_rules:
            if _rule_matches_url(rule, url):
                return False

        return True

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "bypass_domains":    sorted(self._bypass),
                "hidden_extensions": sorted(self._hidden_ext),
                "scope_rules":       list(self._scope_rules),
                "match_replace":     list(self._match_replace),
                "bind_host":         self._bind_host,
                "bind_port":         self._bind_port,
            }

    # ── proxy bind host ─────────────────────────────────────────────────

    def get_bind_host(self) -> str:
        with self._lock:
            return self._bind_host

    def set_bind_host(self, host: str) -> None:
        """Persist the proxy listener bind host. The caller is responsible for
        validating the value and for restarting the listener to apply it."""
        with self._lock:
            self._bind_host = host or "127.0.0.1"
        self._save()

    def get_bind_port(self) -> int:
        with self._lock:
            return self._bind_port

    def set_bind_port(self, port: int) -> None:
        """Persist the proxy listener port (0 = unset → runtime default)."""
        with self._lock:
            self._bind_port = int(port or 0)
        self._save()

    # ── match & replace ────────────────────────────────────────────────

    def get_match_replace(self) -> List[dict]:
        with self._lock:
            return list(self._match_replace)

    def add_match_replace(self, rule: dict) -> None:
        """
        Add a match & replace rule.

        rule keys: enabled, scope, type, match, replace
          scope: "request" | "response" | "both"
          type:  "header"  | "body"     | "url"
          match: regex string (empty = always matches, acts as plain insert/replace)
          replace: replacement string (regex substitution with capture groups supported)
        """
        normalized = {
            "enabled": bool(rule.get("enabled", True)),
            "scope":   str(rule.get("scope",   "request")).lower(),
            "type":    str(rule.get("type",    "header")).lower(),
            "match":   str(rule.get("match",   "")),
            "replace": str(rule.get("replace", "")),
            "comment": str(rule.get("comment", "")),
        }
        with self._lock:
            self._match_replace.append(normalized)
        self._save()

    def remove_match_replace(self, index: int) -> None:
        with self._lock:
            if 0 <= index < len(self._match_replace):
                self._match_replace.pop(index)
        self._save()

    def toggle_match_replace(self, index: int, enabled: bool) -> None:
        with self._lock:
            if 0 <= index < len(self._match_replace):
                self._match_replace[index]["enabled"] = bool(enabled)
        self._save()

    def apply_to_request(
        self,
        url: str,
        headers: dict,
        body: Optional[bytes],
    ) -> tuple:
        """Apply all enabled request-scope match/replace rules. Returns (url, headers, body)."""
        with self._lock:
            rules = [r for r in self._match_replace if r.get("enabled") and r.get("scope") in ("request", "both")]
        for rule in rules:
            url, headers, body = _apply_rule(rule, url, headers, body)
        return url, headers, body

    def apply_to_response(
        self,
        headers: dict,
        body: Optional[bytes],
    ) -> tuple:
        """Apply all enabled response-scope match/replace rules. Returns (headers, body)."""
        with self._lock:
            rules = [r for r in self._match_replace if r.get("enabled") and r.get("scope") in ("response", "both")]
        for rule in rules:
            _, headers, body = _apply_rule(rule, "", headers, body)
        return headers, body

    # ── scope rule mutations ───────────────────────────────────────────

    def add_scope_rule(self, rule: dict) -> None:
        """Append a structured scope rule."""
        normalized = {
            "enabled":  bool(rule.get("enabled", True)),
            "protocol": str(rule.get("protocol", "any")).lower(),
            "host":     str(rule.get("host", "")),
            "port":     str(rule.get("port", "")),
            "file":     str(rule.get("file", "")),
            "kind":     str(rule.get("kind", "include")).lower(),
        }
        with self._lock:
            self._scope_rules.append(normalized)
        self._save()

    def remove_scope_rule(self, index: int) -> None:
        """Remove scope rule at the given index."""
        with self._lock:
            if 0 <= index < len(self._scope_rules):
                self._scope_rules.pop(index)
        self._save()

    def toggle_scope_rule(self, index: int, enabled: bool) -> None:
        """Enable or disable a scope rule by index."""
        with self._lock:
            if 0 <= index < len(self._scope_rules):
                self._scope_rules[index]["enabled"] = bool(enabled)
        self._save()

    def get_scope_rules(self) -> List[dict]:
        with self._lock:
            return list(self._scope_rules)

    # ── project settings (scope snapshots) ────────────────────────────

    def save_project(self, name: str) -> str:
        """
        Save current scope rules as a named project.
        Returns the file path of the saved project.
        """
        _PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
        slug      = _slug(name)
        file_path = _PROJECTS_DIR / f"{slug}.json"
        with self._lock:
            rules = list(self._scope_rules)
        project = {
            "id":         slug,
            "name":       name.strip(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "scope_rules": rules,
        }
        file_path.write_text(json.dumps(project, indent=2))
        return str(file_path)

    def load_project(self, project_id: str) -> bool:
        """
        Load scope rules from a saved project by id (slug).
        Returns True if the project was found and loaded.
        """
        file_path = _PROJECTS_DIR / f"{project_id}.json"
        if not file_path.exists():
            return False
        try:
            data = json.loads(file_path.read_text())
            with self._lock:
                self._scope_rules = list(data.get("scope_rules", []))
            self._save()
            return True
        except Exception:
            return False

    def list_projects(self) -> List[dict]:
        """Return metadata for all saved projects, sorted by name."""
        if not _PROJECTS_DIR.exists():
            return []
        projects = []
        for path in sorted(_PROJECTS_DIR.glob("*.json")):
            try:
                data = json.loads(path.read_text())
                projects.append({
                    "id":         data.get("id", path.stem),
                    "name":       data.get("name", path.stem),
                    "created_at": data.get("created_at", ""),
                    "rule_count": len(data.get("scope_rules", [])),
                })
            except Exception:
                continue
        return projects

    def delete_project(self, project_id: str) -> bool:
        """Delete a saved project by id. Returns True if it existed."""
        file_path = _PROJECTS_DIR / f"{project_id}.json"
        if not file_path.exists():
            return False
        file_path.unlink()
        return True

    # ── bypass / extension mutations ──────────────────────────────────

    def add_bypass(self, domain: str) -> None:
        with self._lock:
            self._bypass.add(domain.lower().strip())
        self._save()

    def remove_bypass(self, domain: str) -> None:
        with self._lock:
            self._bypass.discard(domain.lower().strip())
        self._save()

    def add_hidden_ext(self, ext: str) -> None:
        if not ext.startswith("."):
            ext = "." + ext
        with self._lock:
            self._hidden_ext.add(ext.lower())
        self._save()

    def remove_hidden_ext(self, ext: str) -> None:
        if not ext.startswith("."):
            ext = "." + ext
        with self._lock:
            self._hidden_ext.discard(ext.lower())
        self._save()
