"""
Hidden-parameter discovery ("param mining").

Actively guesses unlinked request parameters — names the application accepts
but never advertises in forms, links, or JS (debug flags, admin toggles,
cache-busting keys, mass-assignment fields). Each name is injected against a
single in-scope request and the response is diffed against a baseline; a name
that changes the response is a hidden parameter and becomes fresh attack
surface the vulnerability agents then get to test.

This is the discovery-side companion to dast/scanners/content_discovery.py
(which brute-forces unlinked *paths*); param mining brute-forces unlinked
*parameters* on a path that already exists.

Detection signals (ordered by confidence, lowest false-positive first):
  * Reflection — each candidate in a batch is injected with its OWN unique
    canary token, so a single request reveals exactly which names are echoed
    back in the response body. No isolation search needed.
  * Behavior change — a batch that shifts the response status code (or its body
    length beyond a noise threshold) is binary-searched down to the individual
    name, then that name is RE-CONFIRMED on its own against the baseline before
    being reported. The lone-confirmation step is the anti-false-positive guard:
    dynamic pages whose length drifts on every request never survive it.

Safety:
  * Detection-only — the injected value is an inert canary token, never a payload.
  * EVERY candidate URL is filtered through ProxySettings.is_in_scope() BEFORE
    any request is issued, exactly like content_discovery — the hard safety
    guarantee of this module.
  * Reuses dast.scanners.active_checks._client()/_send(), so every probe is
    proxy-routed, rate-limited (429/503 backoff), and circuit-broken
    (dead-host short-circuit) like the vulnerability scanner.

The caller (the param-mining worker in dast/proxy/runner.py) turns each
discovered parameter into a synthetic AI scan suggestion so the coordinator
re-tests the now-enriched endpoint.
"""

from __future__ import annotations

import json
from typing import Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from dast.scanners.active_checks import (
    _client,
    _send,
    is_host_dead,
    reset_host_reachability,
)
from dast.wordlists.loader import load_wordlist
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Candidate names are injected in batches of this size. Larger batches mean
# fewer requests but a wider binary-search when a batch shows a behavior change.
_BATCH_SIZE = 25

# A body-length delta smaller than this (bytes) between a probe and the baseline
# is treated as page noise, not a real behavior change. Reflection is exact and
# does not use this threshold.
_LENGTH_NOISE_BYTES = 32

# Inert marker injected as each candidate's value. Unique per candidate within a
# batch (a numeric suffix is appended) so reflection pinpoints the exact name.
_CANARY_PREFIX = "dastpm7c1e"

LogCb = Optional[Callable[[str], Awaitable[None]]]


def _canary(index: int) -> str:
    """
    Return the unique inert canary value for the candidate at `index`.

    A trailing non-digit delimiter ('q') terminates the numeric suffix so no
    canary is a substring of another (without it, 'dastpm7c1e1' matches inside
    'dastpm7c1e16', producing phantom reflection hits during the substring scan).
    """
    return f"{_CANARY_PREFIX}{index}q"


def _build_query_url(base_url: str, extra: Dict[str, str]) -> str:
    """Return base_url with `extra` merged into its query string."""
    parsed = urlparse(base_url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    pairs += list(extra.items())
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def _build_form_body(body: Optional[str], extra: Dict[str, str]) -> str:
    """Return a form-urlencoded body with `extra` merged in."""
    pairs = parse_qsl(body or "", keep_blank_values=True)
    pairs += list(extra.items())
    return urlencode(pairs)


def _build_json_body(body: Optional[str], extra: Dict[str, str]) -> Optional[str]:
    """Return a JSON body with `extra` merged in, or None if body isn't a JSON object."""
    try:
        obj = json.loads(body) if body else {}
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    obj = dict(obj)
    obj.update(extra)
    return json.dumps(obj)


def _detect_location(method: str, body: Optional[str], content_type: str) -> str:
    """
    Decide where to inject candidate parameters for this request.

    Returns "query" | "form" | "json". A body-bearing request injects into the
    body (matching how the app actually reads its params); everything else uses
    the query string.
    """
    ct = (content_type or "").lower()
    has_body = bool(body) and (method or "GET").upper() in ("POST", "PUT", "PATCH")
    if has_body and "json" in ct:
        return "json"
    if has_body and "x-www-form-urlencoded" in ct:
        return "form"
    if has_body:
        # Body-bearing but unknown encoding — fall back to query mining, which is
        # always safe and never corrupts the original body.
        return "query"
    return "query"


async def _log(log_cb: LogCb, message: str) -> None:
    """Emit a live-progress line to the caller's callback, if any."""
    if log_cb is None:
        return
    try:
        await log_cb(message)
    except Exception as exc:  # never let a logging failure abort a run
        logger.warning("Param-mining log callback failed", error=str(exc))


class _Prober:
    """Sends one request with a set of injected params and returns the response."""

    def __init__(
        self,
        client,
        base_url: str,
        method: str,
        headers: Dict[str, str],
        body: Optional[str],
        location: str,
        settings,
    ) -> None:
        self._client = client
        self._base_url = base_url
        self._method = method
        self._headers = headers
        self._body = body
        self._location = location
        self._settings = settings

    async def send(self, extra: Dict[str, str]):
        """
        Send the base request augmented with `extra` params in the chosen
        location. Returns the httpx response, or None if the request was
        skipped (out of scope, dead host, or transport failure).
        """
        url = self._base_url
        body = self._body
        if self._location == "query":
            url = _build_query_url(self._base_url, extra)
        elif self._location == "form":
            body = _build_form_body(self._body, extra)
        elif self._location == "json":
            built = _build_json_body(self._body, extra)
            if built is None:
                return None
            body = built

        # HARD SAFETY GATE: never probe an out-of-scope URL.
        if self._settings is not None and not self._settings.is_in_scope(url):
            return None

        return await _send(
            self._client, self._method, url, self._headers, body, source="param-mining"
        )


def _length(resp) -> int:
    return len(resp.content or b"")


def _changed(resp, baseline_status: int, baseline_len: int, length_stable: bool) -> bool:
    """
    True if `resp` differs from baseline by status code, or by non-trivial body
    length WHEN the page length is stable. On an unstable (drifting) page,
    length is pure noise and only a status-code change counts — this is the
    guard that keeps dynamic pages from producing false positives.
    """
    if resp.status_code != baseline_status:
        return True
    if not length_stable:
        return False
    return abs(_length(resp) - baseline_len) >= _LENGTH_NOISE_BYTES


async def _isolate_behavior_change(
    prober: _Prober,
    names: List[str],
    baseline_status: int,
    baseline_len: int,
    length_stable: bool,
    should_cancel: Optional[Callable[[], bool]],
) -> List[str]:
    """
    Binary-search a batch known to change behavior down to the individual
    name(s) responsible, then re-confirm each in isolation against the baseline.

    Only names that reproduce a change ON THEIR OWN are returned — the
    confirmation step is what keeps dynamic-page noise out of the results.
    """
    if should_cancel is not None and should_cancel():
        return []
    if len(names) == 1:
        # Confirm the lone candidate independently reproduces the change.
        resp = await prober.send({names[0]: _canary(0)})
        if resp is not None and _changed(resp, baseline_status, baseline_len, length_stable):
            return names
        return []

    mid = len(names) // 2
    left, right = names[:mid], names[mid:]
    found: List[str] = []
    for half in (left, right):
        if should_cancel is not None and should_cancel():
            break
        extra = {name: _canary(i) for i, name in enumerate(half)}
        resp = await prober.send(extra)
        if resp is None:
            continue
        if _changed(resp, baseline_status, baseline_len, length_stable):
            found += await _isolate_behavior_change(
                prober, half, baseline_status, baseline_len, length_stable, should_cancel
            )
    return found


async def run_param_mining(
    base_url: str,
    headers: Dict[str, str],
    settings,
    method: str = "GET",
    body: Optional[str] = None,
    content_type: str = "",
    proxy_url: Optional[str] = None,
    log_cb: LogCb = None,
    *,
    wordlist: str = "params",
    should_cancel: Optional[Callable[[], bool]] = None,
    client=None,
) -> List[dict]:
    """
    Discover hidden parameters on the request described by base_url/method/body.

    Returns a list of hit dicts:
      {"parameter": str, "location": "query"|"form"|"json",
       "reason": "reflected"|"behavior-change", "status": int,
       "url": str, "method": str}

    `settings` must expose is_in_scope(url) -> bool. Any candidate injected into
    an out-of-scope URL is skipped WITHOUT being requested. `should_cancel`, if
    given, is polled between batches so the caller can stop the run.

    `client`, if given, is reused (so the caller's proxy-routed client is
    honoured) and is NEVER closed here; otherwise a fresh proxy-routed client is
    opened from `proxy_url` and closed on exit. This mirrors probe_diff so the
    coordinator can reuse its shared client.
    """
    hostname = urlparse(base_url).hostname or base_url
    method = (method or "GET").upper()

    # Fresh reachability state for this run (network/target may have changed).
    reset_host_reachability()

    if settings is not None and not settings.is_in_scope(base_url):
        await _log(log_cb, f"Refusing param mining: {base_url} is out of scope")
        logger.warning("Param mining target out of scope", url=base_url)
        return []

    candidates = load_wordlist(wordlist)
    if not candidates:
        await _log(log_cb, f"Param mining: wordlist '{wordlist}' is empty")
        return []

    # Do not re-guess parameters the request already carries.
    existing = {k for k, _ in parse_qsl(urlparse(base_url).query, keep_blank_values=True)}
    if body:
        existing |= {k for k, _ in parse_qsl(body, keep_blank_values=True)}
    candidates = [c for c in candidates if c not in existing]

    location = _detect_location(method, body, content_type)
    await _log(
        log_cb,
        f"Param mining starting: {len(candidates)} candidate(s) into '{location}' "
        f"of {method} {urlparse(base_url).path or '/'}",
    )

    hits: List[dict] = []
    seen: set[str] = set()

    async def _mine(client) -> None:
        prober = _Prober(client, base_url, method, headers, body, location, settings)

        # Baseline: send the unmodified request TWICE. If the two responses
        # differ in length, the page is dynamic — length-based detection is
        # disabled (status-only) so drifting content never yields a hit.
        baseline = await prober.send({})
        if baseline is None:
            await _log(log_cb, "Param mining: baseline request failed — aborting")
            return
        baseline_status = baseline.status_code
        baseline_len = _length(baseline)

        baseline2 = await prober.send({})
        length_stable = (
            baseline2 is not None
            and baseline2.status_code == baseline_status
            and abs(_length(baseline2) - baseline_len) < _LENGTH_NOISE_BYTES
        )
        await _log(
            log_cb,
            f"Baseline: status {baseline_status}, len {baseline_len}, "
            f"length_stable={length_stable}",
        )

        def _record(name: str, reason: str, status: int) -> None:
            if name in seen:
                return
            seen.add(name)
            hits.append({
                "parameter": name,
                "location": location,
                "reason": reason,
                "status": status,
                "url": base_url,
                "method": method,
            })

        for batch_start in range(0, len(candidates), _BATCH_SIZE):
            if should_cancel is not None and should_cancel():
                await _log(log_cb, "Param mining cancelled")
                break
            if is_host_dead(hostname):
                await _log(log_cb, f"Host {hostname} unreachable — stopping param mining")
                break

            batch = candidates[batch_start:batch_start + _BATCH_SIZE]
            # Each candidate gets a unique canary so reflection pinpoints the name.
            canary_of = {name: _canary(i) for i, name in enumerate(batch)}
            resp = await prober.send(canary_of)
            if resp is None:
                continue

            # ── reflection: which unique canaries came back in the body? ──────
            try:
                text = resp.text
            except Exception:
                text = ""
            for name, canary in canary_of.items():
                if canary in text:
                    _record(name, "reflected", resp.status_code)
                    await _log(log_cb, f"HIT [reflected] {name} (status {resp.status_code})")

            # ── behavior change: status/length shift → isolate + confirm ──────
            if _changed(resp, baseline_status, baseline_len, length_stable):
                isolated = await _isolate_behavior_change(
                    prober, batch, baseline_status, baseline_len, length_stable, should_cancel
                )
                for name in isolated:
                    if name not in seen:
                        _record(name, "behavior-change", resp.status_code)
                        await _log(
                            log_cb,
                            f"HIT [behavior-change] {name} (status {resp.status_code})",
                        )

                # A disruptive param (one that flips status to 403/500 or errors
                # the page) makes the batch response its OWN page, not one that
                # echoes the co-injected canaries — so reflection detection above
                # was unreliable for every OTHER name in the batch. Re-probe the
                # batch without the disruptive name(s) so masked reflections still
                # surface.
                offenders = set(isolated)
                remaining = [n for n in batch if n not in offenders]
                if offenders and remaining:
                    clean = await prober.send({n: canary_of[n] for n in remaining})
                    if clean is not None:
                        try:
                            clean_text = clean.text
                        except Exception:
                            clean_text = ""
                        for name in remaining:
                            if name not in seen and canary_of[name] in clean_text:
                                _record(name, "reflected", clean.status_code)
                                await _log(
                                    log_cb,
                                    f"HIT [reflected] {name} (status {clean.status_code})",
                                )

    # Reuse the caller's client if provided (never close it); otherwise own one.
    if client is not None:
        await _mine(client)
    else:
        async with _client(proxy_url) as owned_client:
            await _mine(owned_client)

    await _log(log_cb, f"Param mining done: {len(hits)} hidden parameter(s) found")
    logger.info(
        "Param mining complete",
        host=hostname,
        location=location,
        hits=len(hits),
        candidates=len(candidates),
    )
    return hits
