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
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_SETTINGS_PATH = Path.home() / ".dast-ai" / "proxy-settings.json"
_PROJECTS_DIR  = Path.home() / ".dast-ai" / "projects"

# Rewrite-rule caps (ARTEX parity): over-limit is an ERROR, never a silent drop.
_MAX_MR_RULES = 100
_MAX_MR_ENABLED = 50
# Integrity guard: body-targeting rules are SKIPPED (whole rule) on oversized or
# encoded bodies instead of corrupting the stream (ARTEX rewrite engine).
_MR_BODY_LIMIT = 1024 * 1024
_MR_BODYLESS_STATUS = range(100, 300)  # 1xx/2xx-no-content-ish guard handled per-call

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
) -> Tuple[str, dict, Optional[bytes], bool]:
    """Apply a single match/replace rule to the given url/headers/body.

    Returns (url, headers, body, fired) — ``fired`` is True only when the rule
    actually CHANGED something (a rule that matches but produces identical
    output does not count as a hit, unlike the old diff-based inference)."""
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
        new_url = _sub(url)
        fired = new_url != url
        url = new_url

    elif rtype == "header":
        new_headers = {}
        fired = False
        for k, v in headers.items():
            subbed = _sub(f"{k}: {v}")
            if ": " in subbed:
                nk, nv = subbed.split(": ", 1)
                nk = nk.strip().lower()
                nv = nv.strip()
                if nk != k or nv != v:
                    fired = True
                new_headers[nk] = nv
            else:
                new_headers[k] = v
        headers = new_headers

    elif rtype == "body" and body is not None:
        try:
            text = body.decode("utf-8", errors="replace")
            new_text = _sub(text)
            fired = new_text != text
            if fired:
                body = new_text.encode("utf-8")
        except Exception as exc:
            logger.debug("failed to apply match/replace to request body", error=str(exc))
            fired = False
    else:
        fired = False

    return url, headers, body, fired


def _validate_mr_rule(rule: dict) -> dict:
    """Normalise + validate one rewrite rule. Raises ValueError on anything
    invalid (bad enum, uncompilable regex, bad status shape) — the API turns
    that into a 400 instead of the old silent regex fallback."""
    normalized = {
        "id": str(rule.get("id") or uuid.uuid4()),
        "enabled": bool(rule.get("enabled", True)),
        "scope":   str(rule.get("scope",   "request")).lower(),
        "type":    str(rule.get("type",    "header")).lower(),
        "match":   str(rule.get("match",   "")),
        "replace": str(rule.get("replace", "")),
        "comment": str(rule.get("comment", "")),
        # Matchers (3-I): all optional — absent/empty matcher matches everything.
        "methods": [str(m).upper() for m in (rule.get("methods") or []) if str(m).strip()],
        "host":    str(rule.get("host", "")).strip().lower(),
        "url_regex": str(rule.get("url_regex", "")),
        "status":  str(rule.get("status", "")).strip(),
        # Trace (3-I): hit counters, persisted with the rule.
        "hits": max(0, int(rule.get("hits", 0) or 0)),
        "last_applied_at": str(rule.get("last_applied_at", "")),
    }
    if normalized["scope"] not in ("request", "response", "both"):
        raise ValueError(f"invalid scope: {normalized['scope']!r}")
    if normalized["type"] not in ("header", "body", "url"):
        raise ValueError(f"invalid type: {normalized['type']!r}")
    if normalized["scope"] == "request" and normalized["status"]:
        raise ValueError("status matcher is response-only")
    for field in ("match", "url_regex"):
        pattern = normalized[field]
        if pattern:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid {field} regex: {exc}") from exc
    if normalized["status"]:
        m = re.fullmatch(r"([1-5])xx|([1-5]\d{2})", normalized["status"])
        if not m:
            raise ValueError(f"invalid status matcher: {normalized['status']!r}")
    if normalized["host"] and "*" in normalized["host"] and not normalized["host"].startswith("*."):
        raise ValueError("host matcher supports exact host or a leading '*.suffix' glob")
    return normalized


def _host_matches(rule_host: str, host: str) -> bool:
    """Exact (case-insensitive) or leading '*.suffix' glob — ``*.example.com``
    matches sub.example.com but NOT example.com itself (ARTEX semantics)."""
    rule_host = (rule_host or "").lower()
    host = (host or "").lower()
    if not rule_host:
        return True
    if rule_host.startswith("*."):
        suffix = rule_host[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == rule_host


def _rule_matches(rule: dict, method: str, host: str,
                  path_query: str, status: int = 0) -> bool:
    """Rule-level matchers — AND; an absent matcher matches everything."""
    methods = rule.get("methods") or []
    if methods and str(method).upper() not in methods:
        return False
    if rule.get("host") and not _host_matches(rule["host"], host):
        return False
    url_re = rule.get("url_regex") or ""
    if url_re:
        try:
            if not re.search(url_re, path_query):
                return False
        except re.error:
            return False
    status_m = str(rule.get("status") or "")
    if status_m:
        m = re.fullmatch(r"([1-5])xx|([1-5]\d{2})", status_m)
        if not m:
            return False
        if m.group(1):  # "4xx" → half-open class range
            lo = int(m.group(1)) * 100
            if not (lo <= status < lo + 100):
                return False
        elif status != int(m.group(2)):
            return False
    return True


def _body_eligible(headers: dict, body: Optional[bytes],
                   method: str, status: int) -> bool:
    """Integrity guard for body-targeting rules (ARTEX rewrite engine): skip
    the WHOLE rule on oversized/encoded/no-body responses instead of corrupting
    the stream. Returns False when a body rule must not run."""
    if body is None:
        return True  # nothing to rewrite — a body rule will simply not fire
    if len(body) > _MR_BODY_LIMIT:
        return False
    enc = ""
    for k, v in (headers or {}).items():
        if k.lower() == "content-encoding" and str(v).strip().lower() not in ("identity", ""):
            enc = str(v)
            break
    if enc:
        return False
    if str(method).upper() == "HEAD" or 100 <= status < 200 or status in (204, 304):
        return False
    return True


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
                # 3-I migration: legacy rules (no id/matchers/counters) get the
                # new fields so stable ids work from the first run.
                for _mr in self._match_replace:
                    if not _mr.get("id"):
                        _mr["id"] = str(uuid.uuid4())
                    _mr.setdefault("methods", [])
                    _mr.setdefault("host", "")
                    _mr.setdefault("url_regex", "")
                    _mr.setdefault("status", "")
                    _mr.setdefault("hits", 0)
                    _mr.setdefault("last_applied_at", "")
                self._bind_host = str(data.get("bind_host", "127.0.0.1")) or "127.0.0.1"
                try:
                    self._bind_port = int(data.get("bind_port", 0) or 0)
                except (TypeError, ValueError):
                    self._bind_port = 0
        except Exception as exc:
            logger.warning("failed to load proxy settings; using defaults", error=str(exc))

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

    def add_match_replace(self, rule: dict) -> dict:
        """
        Add a rewrite rule (3-I: matchers + stable id + hit counters).

        rule keys: enabled, scope, type, match, replace, comment, and the
        optional matchers methods[]/host/url_regex/status:
          scope:  "request" | "response" | "both"
          type:   "header"  | "body"     | "url"
          match:  regex string (empty = always matches, acts as plain insert/replace)
          replace: replacement string (regex substitution with capture groups)
          methods: ["GET", "POST"] — empty = any
          host:   "api.example.com" or "*.example.com" (subdomains only) — empty = any
          url_regex: regex over path+query — empty = any
          status: "404" or "4xx" — response rules only
        Raises ValueError on invalid input or over the ARTEX caps (100 rules,
        50 enabled) — the API maps that to a 400. Returns the normalized rule.
        """
        normalized = _validate_mr_rule(rule)
        with self._lock:
            if len(self._match_replace) >= _MAX_MR_RULES:
                raise ValueError(f"rewrite-rule cap reached ({_MAX_MR_RULES} rules)")
            if normalized["enabled"]:
                enabled = sum(1 for r in self._match_replace if r.get("enabled"))
                if enabled >= _MAX_MR_ENABLED:
                    raise ValueError(f"enabled rewrite-rule cap reached ({_MAX_MR_ENABLED})")
            self._match_replace.append(normalized)
        self._save()
        return dict(normalized)

    def _find_mr_index(self, identifier) -> int:
        """Locate a rule by id (3-I) or legacy list index. Raises KeyError when
        unknown — the API turns that into a 404."""
        with self._lock:
            if isinstance(identifier, int):
                if not 0 <= identifier < len(self._match_replace):
                    raise KeyError(identifier)
                return identifier
            for i, r in enumerate(self._match_replace):
                if r.get("id") == str(identifier):
                    return i
        raise KeyError(identifier)

    def remove_match_replace(self, identifier) -> None:
        try:
            idx = self._find_mr_index(identifier)
        except KeyError:
            return
        with self._lock:
            if 0 <= idx < len(self._match_replace):
                self._match_replace.pop(idx)
        self._save()

    def toggle_match_replace(self, identifier, enabled: bool) -> None:
        try:
            idx = self._find_mr_index(identifier)
        except KeyError:
            return
        with self._lock:
            if 0 <= idx < len(self._match_replace):
                self._match_replace[idx]["enabled"] = bool(enabled)
        self._save()

    def apply_to_request(
        self,
        url: str,
        headers: dict,
        body: Optional[bytes],
        method: str = "",
        content_encoding: str = "identity",
    ) -> tuple:
        """Apply enabled request-scope rewrite rules whose matchers accept this
        request. Returns (url, headers, body, fired_ids) — fired_ids carries the
        stable rule ids that CHANGED something (the trace the old diff-based
        detection approximated)."""
        from urllib.parse import urlparse as _up
        _parsed = _up(url)
        _host = _parsed.hostname or ""
        _path_query = _parsed.path or "/"
        if _parsed.query:
            _path_query += "?" + _parsed.query
        with self._lock:
            rules = [dict(r) for r in self._match_replace
                     if r.get("enabled") and r.get("scope") in ("request", "both")]
        fired_ids: List[str] = []
        changed = False
        for rule in rules:
            if rule.get("type") == "body" and (
                    (body is not None and len(body) > _MR_BODY_LIMIT)
                    or (content_encoding and content_encoding.lower() not in ("identity", ""))
                    or not _rule_matches(rule, method, _host, _path_query)):
                continue
            if not _rule_matches(rule, method, _host, _path_query):
                continue
            url, headers, body, fired = _apply_rule(rule, url, headers, body)
            if fired:
                changed = True
                fired_ids.append(rule.get("id") or "")
        if changed:
            self._record_hits(fired_ids)
        return url, headers, body, fired_ids

    def apply_to_response(
        self,
        url: str,
        headers: dict,
        body: Optional[bytes],
        method: str = "",
        status: int = 0,
        content_encoding: str = "identity",
    ) -> tuple:
        """Apply enabled response-scope rewrite rules. Returns (headers, body,
        fired_ids). The url is now REAL (pre-3-I it was always "" so url-type
        response rules could never fire) and response matchers (status) work."""
        from urllib.parse import urlparse as _up
        _parsed = _up(url)
        _host = _parsed.hostname or ""
        _path_query = _parsed.path or "/"
        if _parsed.query:
            _path_query += "?" + _parsed.query
        with self._lock:
            rules = [dict(r) for r in self._match_replace
                     if r.get("enabled") and r.get("scope") in ("response", "both")]
        fired_ids: List[str] = []
        changed = False
        for rule in rules:
            if rule.get("type") == "body" and not _body_eligible(
                    headers, body, method, status):
                continue
            if not _rule_matches(rule, method, _host, _path_query, status):
                continue
            _, headers, body, fired = _apply_rule(rule, url, headers, body)
            if fired:
                changed = True
                fired_ids.append(rule.get("id") or "")
        if changed:
            self._record_hits(fired_ids)
        return headers, body, fired_ids

    def _record_hits(self, rule_ids: List[str]) -> None:
        """Bump hit counters for the rules that fired (persisted with _save by
        the caller's next save; counters are advisory trace, best-effort)."""
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        with self._lock:
            for r in self._match_replace:
                if r.get("id") in rule_ids:
                    r["hits"] = max(0, int(r.get("hits", 0) or 0)) + 1
                    r["last_applied_at"] = now

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

    def get_scope_hosts(self) -> List[str]:
        """Extract unique host patterns from enabled include scope rules."""
        with self._lock:
            hosts: List[str] = []
            for rule in self._scope_rules:
                if rule.get("kind") == "include" and rule.get("enabled", True):
                    host = (rule.get("host") or "").strip()
                    if host and host not in hosts:
                        hosts.append(host)
            return hosts

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
