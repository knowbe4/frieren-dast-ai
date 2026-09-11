"""
Live vulnerability-detection benchmark — measures the scanner's true-positive,
false-positive and false-negative rate against a hand-labelled ground-truth
spec, end to end through the running Frieren proxy + dashboard.

This answers the question unit tests and the LLM eval harness cannot: given a
real vulnerable app, does the full pipeline (proxy interception -> coordinator
-> agents -> LLM/deterministic validation -> dashboard) actually surface the
vulns that are really there, and only those? It is the empirical counterpart to
tests/evals/ (which scores individual LLM decisions in isolation).

Opt-in and NOT part of `uv run pytest`: it needs a running proxy, a configured
AI provider, and a live vulnerable target. See tests/live/README.md.

All traffic is driven THROUGH the proxy (never straight at the target and never
by invoking agents directly) so the run exercises the exact production path.

Usage:
    # Start the proxy first (separate terminal), then bring up the target:
    #   uv run dast-ai proxy
    #   docker run --rm -it -p 8081:80 vulnerables/web-dvwa
    uv run python -m tests.live.vuln_bench --spec tests/live/ground_truth/dvwa.yaml
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import httpx
import yaml

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_USER_TOKEN_RE = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-f]+)['\"]", re.IGNORECASE)


@dataclass
class EndpointResult:
    path: str
    expected: Set[str]
    found: Set[str] = field(default_factory=set)

    @property
    def true_positives(self) -> Set[str]:
        return self.expected & self.found

    @property
    def false_negatives(self) -> Set[str]:
        return self.expected - self.found


@dataclass
class BenchReport:
    target: str
    endpoints: List[EndpointResult] = field(default_factory=list)
    false_positives: List[Tuple[str, str]] = field(default_factory=list)  # (path, attack_type)

    @property
    def total_tp(self) -> int:
        return sum(len(e.true_positives) for e in self.endpoints)

    @property
    def total_fn(self) -> int:
        return sum(len(e.false_negatives) for e in self.endpoints)

    @property
    def total_fp(self) -> int:
        return len(self.false_positives)

    @property
    def recall(self) -> float:
        expected = self.total_tp + self.total_fn
        return self.total_tp / expected if expected else 1.0

    @property
    def precision(self) -> float:
        reported = self.total_tp + self.total_fp
        return self.total_tp / reported if reported else 1.0


class ProxyBench:
    """Drives a ground-truth spec through a running proxy and scores findings."""

    def __init__(self, spec: dict, proxy_port: int, dashboard_port: int, scan_timeout: float):
        self.spec = spec
        self.proxy_url = f"http://127.0.0.1:{proxy_port}"
        self.dashboard = f"http://127.0.0.1:{dashboard_port}"
        self.scan_timeout = scan_timeout
        self.base_url: str = spec["target"]["base_url"].rstrip("/")

    # ── dashboard control plane ──────────────────────────────────────────────

    def _configure_scope_and_mode(self) -> None:
        scope = self.spec.get("scope", {})
        rule = {
            "enabled": True,
            "protocol": "any",
            "host": str(scope.get("host", "")),
            "port": str(scope.get("port", "")),
            "file": "",
            "kind": "include",
        }
        resp = httpx.post(f"{self.dashboard}/api/settings/scope", json={"rule": rule}, timeout=10)
        resp.raise_for_status()
        # Active scanning + AI-driven agents must be on for the pipeline to run.
        httpx.post(f"{self.dashboard}/api/mode", json={"ai_mode": True}, timeout=10).raise_for_status()
        # Disable auto-scan so the queue holds ONLY the entries we explicitly
        # enqueue. Otherwise the proxy auto-scans all intercepted traffic —
        # including the probe requests our own scan generates — which floods the
        # queue, recurses, and makes the targeted drain impossible to track.
        httpx.post(f"{self.dashboard}/api/ai/auto-scan", json={"enabled": False}, timeout=10).raise_for_status()
        logger.info("Bench: scope + AI mode configured, auto-scan off",
                    host=rule["host"], port=rule["port"])

    # ── target driving (through the proxy) ───────────────────────────────────

    def _client(self) -> httpx.Client:
        # Route every request through the Frieren proxy so it is intercepted;
        # verify=False because the proxy MITMs TLS with its own CA.
        return httpx.Client(
            proxy=self.proxy_url,
            verify=False,
            timeout=15,
            follow_redirects=True,
        )

    def _authenticate(self, client: httpx.Client) -> None:
        auth = self.spec["target"].get("auth", {})
        if auth.get("type") == "dvwa":
            self._authenticate_dvwa(client, auth)
        elif auth.get("type") in (None, "none"):
            logger.info("Bench: no authentication configured")
        else:
            raise ValueError(f"Unknown auth type: {auth.get('type')!r}")

    def _authenticate_dvwa(self, client: httpx.Client, auth: dict) -> None:
        login_page = client.get(f"{self.base_url}/login.php")
        match = _USER_TOKEN_RE.search(login_page.text)
        token = match.group(1) if match else ""
        client.post(
            f"{self.base_url}/login.php",
            data={
                "username": auth.get("username", "admin"),
                "password": auth.get("password", "password"),
                "Login": "Login",
                "user_token": token,
            },
        )
        # DVWA reads the difficulty level from the `security` cookie.
        client.cookies.set("security", str(auth.get("security", "low")))
        logger.info("Bench: DVWA authenticated", user=auth.get("username", "admin"))

    def _drive_endpoints(self, client: httpx.Client) -> None:
        for ep in self.spec.get("endpoints", []):
            url = f"{self.base_url}{ep['path']}"
            method = ep.get("method", "GET").upper()
            try:
                if method == "GET":
                    client.get(url, params=ep.get("query"))
                elif method == "POST":
                    client.post(url, params=ep.get("query"), data=ep.get("form"))
                else:
                    logger.warning("Bench: unsupported method, skipping", method=method, path=ep["path"])
                    continue
                logger.info("Bench: drove endpoint", method=method, path=ep["path"])
            except Exception as exc:
                logger.warning("Bench: failed to drive endpoint", path=ep["path"], error=str(exc))

    # ── scanning ─────────────────────────────────────────────────────────────

    def _scoped_entries(self) -> List[dict]:
        scope = self.spec.get("scope", {})
        host_port = f"{scope.get('host', '')}:{scope.get('port', '')}"
        entries = httpx.get(f"{self.dashboard}/api/entries?limit=1000", timeout=10).json()
        return [e for e in entries if str(e.get("host", "")) == host_port]

    def _scoped_entry_ids(self) -> Set[str]:
        return {str(e["id"]) for e in self._scoped_entries() if e.get("id")}

    def _scan_driven_endpoints(self, pre_existing_ids: Set[str]) -> List[str]:
        # Scan only the entries this run just created (set-difference against the
        # snapshot taken before driving). A long-running proxy accumulates one
        # entry per driven endpoint per run; re-scanning the whole history would
        # enqueue hundreds of stale duplicates and never drain within the budget.
        driven_paths = {ep["path"] for ep in self.spec.get("endpoints", [])}
        entries = self._scoped_entries()
        ids = [
            str(e["id"]) for e in entries
            if e.get("path") in driven_paths and str(e.get("id")) not in pre_existing_ids
        ]
        if not ids:
            logger.warning("Bench: no newly intercepted entries matched the driven endpoints")
            return []
        resp = httpx.post(f"{self.dashboard}/api/scan", json={"ids": ids}, timeout=30)
        resp.raise_for_status()
        logger.info("Bench: enqueued scan", entry_count=len(ids))
        return ids

    def _wait_for_scan_drain(self, scanned_ids: List[str]) -> None:
        # Wait only for the entries WE enqueued to leave the queue — not for the
        # whole queue to drain. A running proxy may have a large pre-existing
        # auto-scan backlog of unrelated traffic; blocking on that would time out
        # even though our targeted scans finished long ago.
        wanted = set(scanned_ids)
        if not wanted:
            return
        deadline = time.monotonic() + self.scan_timeout
        while time.monotonic() < deadline:
            queue = httpx.get(f"{self.dashboard}/api/scan-queue", timeout=10).json()
            in_flight = {item.get("id") for item in queue.get("pending", []) + queue.get("running", [])}
            remaining = wanted & in_flight
            if not remaining:
                logger.info("Bench: targeted scans complete", scanned=len(wanted))
                return
            logger.info("Bench: waiting for scan", remaining=len(remaining), total=len(wanted))
            time.sleep(3)
        logger.warning("Bench: scan-drain timeout reached", timeout=self.scan_timeout,
                       still_pending=len(wanted & in_flight))

    # ── scoring ──────────────────────────────────────────────────────────────

    def _collect_confirmed(self) -> Dict[str, Set[str]]:
        """Map path -> set of confirmed active attack_types on scoped endpoints."""
        ignore = set(self.spec.get("ignore_attack_types", []))
        findings = httpx.get(f"{self.dashboard}/api/findings", timeout=10).json()
        scope = self.spec.get("scope", {})
        host_port = f"{scope.get('host', '')}:{scope.get('port', '')}"
        by_path: Dict[str, Set[str]] = {}
        for f in findings:
            if str(f.get("host", "")) != host_port:
                continue
            if not f.get("confirmed"):
                continue
            attack = str(f.get("attack_type", ""))
            if attack in ignore:
                continue
            by_path.setdefault(str(f.get("path", "")), set()).add(attack)
        return by_path

    def score(self) -> BenchReport:
        report = BenchReport(target=self.spec["target"].get("name", self.base_url))
        confirmed_by_path = self._collect_confirmed()
        expected_union: Set[str] = set()
        expected_paths: Set[str] = set()

        for ep in self.spec.get("endpoints", []):
            expected = set(ep.get("expect", []))
            expected_union |= expected
            expected_paths.add(ep["path"])
            found_here = confirmed_by_path.get(ep["path"], set())
            report.endpoints.append(
                EndpointResult(path=ep["path"], expected=expected, found=found_here & expected)
            )

        # False positives: any confirmed active finding whose class was not
        # expected anywhere (on any scoped path we drove or otherwise).
        for path, attacks in confirmed_by_path.items():
            for attack in attacks:
                if attack not in expected_union:
                    report.false_positives.append((path, attack))
        return report

    # ── orchestration ─────────────────────────────────────────────────────────

    def run(self) -> BenchReport:
        self._configure_scope_and_mode()
        pre_existing_ids = self._scoped_entry_ids()
        with self._client() as client:
            self._authenticate(client)
            self._drive_endpoints(client)
        # Give the proxy a moment to persist intercepted entries.
        time.sleep(1)
        scanned_ids = self._scan_driven_endpoints(pre_existing_ids)
        self._wait_for_scan_drain(scanned_ids)
        return self.score()


def _print_report(report: BenchReport) -> None:
    print("\n" + "=" * 68)
    print(f"  VULN BENCHMARK — {report.target}")
    print("=" * 68)
    for ep in report.endpoints:
        for attack in sorted(ep.expected):
            mark = "TP " if attack in ep.true_positives else "FN!"
            print(f"  [{mark}] {attack:<8} {ep.path}")
    for path, attack in report.false_positives:
        print(f"  [FP!] {attack:<8} {path}")
    print("-" * 68)
    print(f"  TP={report.total_tp}  FN={report.total_fn}  FP={report.total_fp}")
    print(f"  recall={report.recall:.0%}  precision={report.precision:.0%}")
    print("=" * 68 + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Live vuln-detection benchmark through the proxy.")
    parser.add_argument("--spec", required=True, help="Path to a ground-truth YAML spec.")
    parser.add_argument("--proxy-port", type=int, default=8080)
    parser.add_argument("--dashboard-port", type=int, default=8088)
    parser.add_argument("--scan-timeout", type=float, default=300.0,
                        help="Max seconds to wait for the scan queue to drain.")
    parser.add_argument("--min-recall", type=float, default=0.0,
                        help="Exit non-zero if recall falls below this threshold.")
    args = parser.parse_args(argv)

    spec_path = Path(args.spec)
    if not spec_path.exists():
        print(f"Spec not found: {spec_path}", file=sys.stderr)
        return 2
    spec = yaml.safe_load(spec_path.read_text())

    try:
        httpx.get(f"http://127.0.0.1:{args.dashboard_port}/api/status", timeout=5)
    except Exception as exc:
        print(f"Dashboard not reachable on :{args.dashboard_port} — start `uv run dast-ai proxy` first "
              f"({exc}).", file=sys.stderr)
        return 2

    bench = ProxyBench(spec, args.proxy_port, args.dashboard_port, args.scan_timeout)
    report = bench.run()
    _print_report(report)

    if report.recall < args.min_recall:
        print(f"FAIL: recall {report.recall:.0%} < required {args.min_recall:.0%}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
