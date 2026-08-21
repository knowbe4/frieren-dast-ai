"""
Service graph — discovers that multiple hosts belong to the same application.

Detection signals (passive, zero extra requests):
  1. Shared JWT — same `iss` claim or identical token seen across hosts
  2. Common parent domain — api.example.com + app.example.com → same group
  3. Correlation headers — X-Request-ID / X-Trace-ID value seen on multiple hosts
  4. Shared session cookie name — same cookie name with same value across hosts

Manual overrides are stored alongside auto-detected groups and take precedence
over split decisions (a manually merged group is never auto-split).

Thread-safe. All mutating operations hold _lock.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from dast.utils.jwt import decode_segment


# ── JWT helpers ──────────────────────────────────────────────────────────────

def _decode_jwt_claims(token: str) -> Optional[dict]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return decode_segment(parts[1])
    except Exception:
        return None


def _extract_jwt(headers: dict, cookies: dict) -> Optional[str]:
    """Extract a JWT string from Authorization header or cookie values."""
    auth = headers.get("authorization", "") or headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token.count(".") == 2:
            return token

    for value in cookies.values():
        v = value.get("value", "") if isinstance(value, dict) else str(value)
        if v.count(".") == 2 and len(v) > 40:
            claims = _decode_jwt_claims(v)
            if claims is not None:
                return v

    return None


_CORRELATION_HEADERS = {
    "x-request-id", "x-trace-id", "x-correlation-id",
    "x-b3-traceid", "traceparent",
}


# ── data model ───────────────────────────────────────────────────────────────

@dataclass
class ServiceGroup:
    id: str
    hosts: Set[str] = field(default_factory=set)
    # why these hosts were grouped together
    detection_signals: List[str] = field(default_factory=list)
    # manually edited by user — never auto-split
    manually_managed: bool = False
    # shared auth tokens seen across hosts in this group (for Layer 2)
    shared_tokens: List[str] = field(default_factory=list)
    # shared cookie names+values seen across hosts
    shared_cookies: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "hosts": sorted(self.hosts),
            "detection_signals": self.detection_signals,
            "manually_managed": self.manually_managed,
            "shared_tokens": self.shared_tokens,
            "shared_cookies": self.shared_cookies,
        }


# ── graph ────────────────────────────────────────────────────────────────────

class ServiceGraph:
    """
    Maintains a map of host → ServiceGroup.
    Hosts not yet associated with any group each have their own singleton group.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # group_id → ServiceGroup
        self._groups: Dict[str, ServiceGroup] = {}
        # host → group_id (fast lookup)
        self._host_to_group: Dict[str, str] = {}
        # JWT iss/prefix → group_id (to link new hosts to existing JWT group)
        self._jwt_key_to_group: Dict[str, str] = {}
        # correlation header value → set of hosts seen with that value
        self._correlation_values: Dict[str, Set[str]] = {}

    # ── public API ────────────────────────────────────────────────────────

    def observe(
        self,
        host: str,
        request_headers: dict,
        response_headers: dict,
        cookies: dict,
    ) -> str:
        """
        Called for every completed proxy entry. Returns the group_id for this host.
        All auto-detection runs here — zero extra requests.
        """
        with self._lock:
            # Ensure host has a group (singleton if new)
            if host not in self._host_to_group:
                self._ensure_singleton(host)

            # Run all detectors
            self._detect_jwt(host, request_headers, cookies)
            self._detect_parent_domain(host)
            self._detect_correlation_headers(host, request_headers, response_headers)
            self._detect_shared_cookie(host, cookies)

            return self._host_to_group[host]

    def group_for_host(self, host: str) -> Optional[ServiceGroup]:
        with self._lock:
            gid = self._host_to_group.get(host)
            return self._groups.get(gid) if gid else None

    def all_groups(self) -> List[ServiceGroup]:
        with self._lock:
            # Return only non-singleton groups + all singletons
            seen_ids = set()
            result = []
            for g in self._groups.values():
                if g.id not in seen_ids:
                    seen_ids.add(g.id)
                    result.append(g)
            return result

    def multi_host_groups(self) -> List[ServiceGroup]:
        """Return only groups with more than one host."""
        with self._lock:
            return [g for g in self._groups.values() if len(g.hosts) > 1]

    def merge(self, host_a: str, host_b: str, reason: str = "manual") -> str:
        """Manually merge the groups containing host_a and host_b."""
        with self._lock:
            if host_a not in self._host_to_group:
                self._ensure_singleton(host_a)
            if host_b not in self._host_to_group:
                self._ensure_singleton(host_b)

            gid_a = self._host_to_group[host_a]
            gid_b = self._host_to_group[host_b]
            if gid_a == gid_b:
                return gid_a

            group_a = self._groups[gid_a]
            group_b = self._groups[gid_b]

            # Merge B into A
            group_a.hosts.update(group_b.hosts)
            group_a.detection_signals.append(f"{reason}: merged with group {gid_b}")
            group_a.manually_managed = True
            group_a.shared_tokens = list(set(group_a.shared_tokens + group_b.shared_tokens))
            group_a.shared_cookies.update(group_b.shared_cookies)

            for h in group_b.hosts:
                self._host_to_group[h] = gid_a

            del self._groups[gid_b]
            return gid_a

    def split(self, host: str) -> str:
        """Remove host from its current group and give it a new singleton group."""
        with self._lock:
            gid = self._host_to_group.get(host)
            if gid and gid in self._groups:
                group = self._groups[gid]
                group.hosts.discard(host)
                if not group.detection_signals or group.detection_signals[-1] != "manual split":
                    group.detection_signals.append("manual split")

            new_gid = str(uuid.uuid4())[:8]
            new_group = ServiceGroup(id=new_gid, hosts={host}, manually_managed=True)
            new_group.detection_signals.append(f"manual split from {gid}")
            self._groups[new_gid] = new_group
            self._host_to_group[host] = new_gid
            return new_gid

    def known_hosts_for(self, host: str) -> List[str]:
        """Return all hosts in the same service group as host (excluding itself)."""
        with self._lock:
            gid = self._host_to_group.get(host)
            if not gid:
                return []
            group = self._groups.get(gid)
            if not group:
                return []
            return [h for h in group.hosts if h != host]

    def shared_tokens_for(self, host: str) -> List[str]:
        """Return auth tokens seen on any host in the same group."""
        with self._lock:
            gid = self._host_to_group.get(host)
            if not gid:
                return []
            group = self._groups.get(gid)
            return list(group.shared_tokens) if group else []

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "groups": [g.to_dict() for g in self._groups.values()],
                "host_count": len(self._host_to_group),
            }

    # ── private helpers ───────────────────────────────────────────────────

    def _ensure_singleton(self, host: str) -> str:
        gid = str(uuid.uuid4())[:8]
        group = ServiceGroup(id=gid, hosts={host})
        group.detection_signals.append("auto: new host")
        self._groups[gid] = group
        self._host_to_group[host] = gid
        return gid

    def _merge_into(self, keep_gid: str, drop_gid: str, signal: str) -> None:
        """Merge drop_gid group into keep_gid. Must hold _lock."""
        if keep_gid == drop_gid:
            return
        if drop_gid not in self._groups:
            return

        keep = self._groups[keep_gid]
        drop = self._groups[drop_gid]

        if drop.manually_managed and not keep.manually_managed:
            # Respect manual split — don't auto-merge a manually split group
            return

        keep.hosts.update(drop.hosts)
        keep.detection_signals.append(signal)
        keep.shared_tokens = list(set(keep.shared_tokens + drop.shared_tokens))
        keep.shared_cookies.update(drop.shared_cookies)

        for h in drop.hosts:
            self._host_to_group[h] = keep_gid

        del self._groups[drop_gid]

    def _detect_jwt(self, host: str, request_headers: dict, cookies: dict) -> None:
        token = _extract_jwt(request_headers, cookies)
        if not token:
            return

        claims = _decode_jwt_claims(token)
        jwt_key = None

        if claims:
            # Use `iss` claim as the linking key — same issuer = same auth service
            jwt_key = claims.get("iss") or claims.get("azp") or claims.get("client_id")

        if not jwt_key:
            # Fallback: use the header+payload prefix (first 40 chars) as a fingerprint
            jwt_key = token[:40]

        gid = self._host_to_group[host]
        group = self._groups[gid]

        # Store token in group for Layer 2 sharing
        if token not in group.shared_tokens:
            group.shared_tokens.append(token)

        if jwt_key in self._jwt_key_to_group:
            existing_gid = self._jwt_key_to_group[jwt_key]
            if existing_gid != gid:
                signal = f"auto: shared JWT (iss/key={jwt_key!r})"
                self._merge_into(existing_gid, gid, signal)
                # Update jwt_key registry after merge
                self._jwt_key_to_group[jwt_key] = existing_gid
        else:
            self._jwt_key_to_group[jwt_key] = gid

    def _detect_parent_domain(self, host: str) -> None:
        # Strip port
        bare = host.split(":")[0]
        parts = bare.split(".")
        if len(parts) < 3:
            return  # top-level or second-level — no parent to share

        # parent = everything after the first label: api.example.com → example.com
        parent = ".".join(parts[1:])

        gid = self._host_to_group[host]
        for other_host, other_gid in list(self._host_to_group.items()):
            if other_host == host:
                continue
            other_bare = other_host.split(":")[0]
            other_parts = other_bare.split(".")
            if len(other_parts) < 2:
                continue
            other_parent = ".".join(other_parts[1:]) if len(other_parts) >= 3 else other_bare
            if other_parent == parent and other_gid != gid:
                signal = f"auto: common parent domain ({parent})"
                self._merge_into(other_gid, gid, signal)
                break

    def _detect_correlation_headers(
        self, host: str, request_headers: dict, response_headers: dict
    ) -> None:
        combined = {k.lower(): v for k, v in {**request_headers, **response_headers}.items()}
        for hdr in _CORRELATION_HEADERS:
            value = combined.get(hdr)
            if not value or len(value) < 8:
                continue

            key = f"{hdr}:{value}"
            hosts_seen = self._correlation_values.setdefault(key, set())
            hosts_seen.add(host)

            if len(hosts_seen) > 1:
                gid = self._host_to_group[host]
                for other_host in hosts_seen:
                    if other_host == host:
                        continue
                    other_gid = self._host_to_group.get(other_host)
                    if other_gid and other_gid != gid:
                        signal = f"auto: shared {hdr} value"
                        self._merge_into(other_gid, gid, signal)
                        gid = self._host_to_group[host]  # may have changed after merge

    def _detect_shared_cookie(self, host: str, cookies: dict) -> None:
        if not cookies:
            return
        gid = self._host_to_group[host]

        for other_host, other_gid in list(self._host_to_group.items()):
            if other_host == host or other_gid == gid:
                continue
            other_group = self._groups.get(other_gid)
            if not other_group:
                continue
            for name, info in cookies.items():
                val = info.get("value", "") if isinstance(info, dict) else str(info)
                if name in other_group.shared_cookies and other_group.shared_cookies[name] == val:
                    signal = f"auto: shared cookie '{name}'"
                    self._merge_into(other_gid, gid, signal)
                    break

        # Record cookies in this host's group for future matching
        group = self._groups.get(self._host_to_group[host])
        if group:
            for name, info in cookies.items():
                val = info.get("value", "") if isinstance(info, dict) else str(info)
                if val:
                    group.shared_cookies[name] = val
