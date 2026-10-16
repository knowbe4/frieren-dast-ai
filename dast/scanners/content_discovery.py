"""
Content discovery (forced browsing).

Actively probes a curated set of common directory names, file names, and
GraphQL endpoint paths (dast/wordlists/*.txt) against a single in-scope host to
surface endpoints the crawler and JS analyzer never see because nothing links
to them (admin panels, backup files, hidden GraphQL endpoints).

Safety:
  * GET-only, detection-only — no destructive requests, no payloads.
  * EVERY candidate URL is filtered through ProxySettings.is_in_scope() BEFORE
    any request is issued, so an out-of-scope host is never probed. This is the
    hard safety guarantee of this module.
  * Reuses dast.scanners.active_checks._client()/_send(), so every probe is
    proxy-routed, rate-limited (429/503 backoff), and circuit-broken
    (dead-host short-circuit) exactly like the vulnerability scanner.

The caller (the discovery worker in dast/proxy/runner.py) turns each hit into a
synthetic sitemap entry plus an AI scan suggestion.
"""

from __future__ import annotations

import re
from typing import Awaitable, Callable, Dict, List, Optional
from urllib.parse import urlparse

from dast.scanners.active_checks import (
    _client,
    _send,
    is_host_dead,
    reset_host_reachability,
)
from dast.wordlists.loader import load_wordlist
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# A response whose status is one of these is not a "hit" — the path does not
# exist (404) or the request was malformed/rejected (400).
_MISS_STATUSES = frozenset({400, 404})

# Random path used once per run to detect soft-404s / SPA catch-alls: servers
# (especially SPAs) that answer 200 with a generic shell/not-found page for ANY
# path. We capture the baseline's content-type + a structural signature and drop
# hits that look like that same shell (exact length is too brittle — a SPA shell
# varies by a nonce/CSRF token per route).
_SOFT404_PROBE_PATH = "dast-content-discovery-nonexistent-a9f3c1e7"

# A probe path that implies a non-HTML resource. If such a path returns HTML, it
# is the SPA/catch-all shell, not a real endpoint (a real graphql.php/.json
# returns JSON, not an HTML document).
_EXPECTS_NONHTML_RE = re.compile(
    r"(?:\.(?:php|json|xml|aspx?|jsp|do|action|wsdl)(?:$|\?)|/graphql|/api/|altair|/v\d+/)",
    re.IGNORECASE,
)


def _shell_signature(body: Optional[bytes]) -> str:
    """A length-insensitive structural signature: keep only the lowercased tag
    skeleton (tag names), drop text/digits/attributes/whitespace, hash it. Two
    renders of the same SPA shell that differ only by a nonce/token/length produce
    the same signature."""
    import hashlib
    text = (body or b"")[:200_000].decode("utf-8", errors="replace").lower()
    tags = re.findall(r"<\s*([a-z0-9]+)", text)
    skeleton = ">".join(tags) if tags else re.sub(r"\s+|\d+", "", text)[:4000]
    return hashlib.sha256(skeleton.encode("utf-8", errors="replace")).hexdigest()

LogCb = Optional[Callable[[str], Awaitable[None]]]


def _origin(url: str) -> str:
    """Return scheme://host[:port] for url (no path)."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _candidate_url(origin: str, entry: str, *, is_dir: bool) -> str:
    """Join origin + wordlist entry into a full URL (dirs get a trailing slash)."""
    path = entry.strip("/")
    suffix = "/" if is_dir else ""
    return f"{origin}/{path}{suffix}"


async def _log(log_cb: LogCb, message: str) -> None:
    """Emit a live-progress line to the caller's callback, if any."""
    if log_cb is None:
        return
    try:
        await log_cb(message)
    except Exception as exc:  # never let a logging failure abort a run
        logger.warning("Content-discovery log callback failed", error=str(exc))


async def run_content_discovery(
    base_url: str,
    headers: Dict[str, str],
    settings,
    proxy_url: Optional[str] = None,
    log_cb: LogCb = None,
    *,
    include_dirs: bool = True,
    include_files: bool = True,
    include_graphql: bool = True,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> List[dict]:
    """
    Probe common paths against the host of base_url and return a list of hits.

    Each hit is a dict:
      {"path": str, "url": str, "method": "GET", "status": int,
       "length": int, "content_type": str, "kind": "dir"|"file"|"graphql"}

    `settings` must expose is_in_scope(url) -> bool. Any candidate that is not
    in scope is skipped WITHOUT being requested. `should_cancel`, if given, is
    polled between probes so the caller can stop the run.
    """
    origin = _origin(base_url)
    hostname = urlparse(base_url).hostname or base_url

    # Fresh reachability state for this run (network/target may have changed).
    reset_host_reachability()

    if settings is not None and not settings.is_in_scope(base_url):
        await _log(log_cb, f"Refusing content discovery: {base_url} is out of scope")
        logger.warning("Content discovery target out of scope", url=base_url)
        return []

    # Build the (kind, entry, is_dir) candidate list from the enabled wordlists.
    candidates: List[tuple[str, str, bool]] = []
    if include_dirs:
        candidates += [("dir", e, True) for e in load_wordlist("directories")]
    if include_files:
        candidates += [("file", e, False) for e in load_wordlist("files")]
    if include_graphql:
        candidates += [("graphql", e, False) for e in load_wordlist("graphql")]

    if not candidates:
        await _log(log_cb, "Content discovery: no wordlist entries loaded")
        return []

    await _log(
        log_cb,
        f"Content discovery starting: {len(candidates)} paths against {origin}",
    )

    hits: List[dict] = []
    skipped_out_of_scope = 0
    baseline_len: Optional[int] = None
    baseline_ct: Optional[str] = None
    baseline_sig: Optional[str] = None

    async with _client(proxy_url) as client:
        # Soft-404 / catch-all baseline: probe a path that should not exist.
        baseline_url = _candidate_url(origin, _SOFT404_PROBE_PATH, is_dir=False)
        if settings is None or settings.is_in_scope(baseline_url):
            baseline_resp = await _send(
                client, "GET", baseline_url, headers, None, source="discovery"
            )
            if baseline_resp is not None and baseline_resp.status_code not in _MISS_STATUSES:
                baseline_len = len(baseline_resp.content or b"")
                baseline_ct = (baseline_resp.headers.get("content-type", "")
                               .split(";")[0].strip().lower())
                baseline_sig = _shell_signature(baseline_resp.content)
                await _log(
                    log_cb,
                    f"Catch-all baseline: status {baseline_resp.status_code}, "
                    f"type {baseline_ct or 'n/a'}, len {baseline_len} "
                    f"(matching shell responses will be filtered)",
                )

        for index, (kind, entry, is_dir) in enumerate(candidates):
            if should_cancel is not None and should_cancel():
                await _log(log_cb, "Content discovery cancelled")
                break
            if is_host_dead(hostname):
                await _log(log_cb, f"Host {hostname} unreachable — stopping discovery")
                break

            url = _candidate_url(origin, entry, is_dir=is_dir)

            # HARD SAFETY GATE: never probe an out-of-scope URL.
            if settings is not None and not settings.is_in_scope(url):
                skipped_out_of_scope += 1
                continue

            resp = await _send(client, "GET", url, headers, None, source="discovery")
            if resp is None:
                continue
            if resp.status_code in _MISS_STATUSES:
                continue

            body_len = len(resp.content or b"")
            resp_ct = resp.headers.get("content-type", "").split(";")[0].strip().lower()
            is_html = "text/html" in resp_ct or "application/xhtml" in resp_ct
            path = urlparse(url).path

            if resp.status_code == 200:
                # (a) A path that implies a non-HTML resource but returns an HTML
                # document is the SPA/catch-all shell, not a real endpoint.
                if is_html and _EXPECTS_NONHTML_RE.search(path):
                    logger.debug("Catch-all shell filtered (html for non-html path)", url=url)
                    continue
                # (b) Response looks like the catch-all baseline: same content-type
                # AND structurally identical shell (or near-identical length). Length
                # alone is too brittle for SPA shells that vary by a nonce per route.
                if baseline_sig is not None and resp_ct == (baseline_ct or ""):
                    near_len = (baseline_len is not None
                                and abs(body_len - baseline_len) <= max(64, int(baseline_len * 0.05)))
                    if _shell_signature(resp.content) == baseline_sig or near_len:
                        logger.debug("Catch-all shell filtered (matches baseline)", url=url)
                        continue

            hit = {
                "path": urlparse(url).path,
                "url": url,
                "method": "GET",
                "status": resp.status_code,
                "length": body_len,
                "content_type": resp.headers.get("content-type", ""),
                "kind": kind,
            }
            hits.append(hit)
            await _log(
                log_cb,
                f"HIT [{kind}] {resp.status_code} {hit['path']} ({body_len} bytes)",
            )

    await _log(
        log_cb,
        f"Content discovery done: {len(hits)} hit(s), "
        f"{skipped_out_of_scope} out-of-scope path(s) skipped",
    )
    logger.info(
        "Content discovery complete",
        host=hostname,
        hits=len(hits),
        skipped_out_of_scope=skipped_out_of_scope,
        probed=len(candidates) - skipped_out_of_scope,
    )
    return hits
