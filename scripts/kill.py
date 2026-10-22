#!/usr/bin/env python3
"""Kill all dast-ai proxy and dashboard processes on Linux, macOS, or Windows."""
import os
import re
import subprocess
import sys
from typing import List

PROXY_PORT = int(os.environ.get("PROXY_PORT", "8080"))
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "8088"))

PATTERNS = [
    "dast-ai.*proxy",
    "dast/proxy/runner",
    "mitmproxy",
    "mitmdump",
]


def _run(*args: str) -> None:
    subprocess.run(list(args), capture_output=True)


def kill_by_pattern(pattern: str) -> None:
    if sys.platform == "win32":
        _run("wmic", "process", "where", f"CommandLine like '%{pattern}%'", "delete")
    else:
        _run("pkill", "-f", pattern)


def listening_pids(port: int) -> List[str]:
    """PIDs LISTENING on the port — never its clients.

    A bare `lsof -ti :PORT` (or `fuser -k PORT/tcp`) also returns every process
    with a client connection to the port. With the dashboard open in Chrome
    that is Chrome's network service; SIGKILLing it wipes in-memory session
    cookies and logs the user out of SSO (Okta) on every restart.
    """
    try:
        result = subprocess.run(
            ["lsof", "-nP", "-t", f"-iTCP:{port}", "-sTCP:LISTEN"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        return _listening_pids_ss(port)
    own_pid = str(os.getpid())
    return [pid.strip() for pid in result.stdout.splitlines() if pid.strip() and pid.strip() != own_pid]


def _listening_pids_ss(port: int) -> List[str]:
    """Linux fallback when lsof is missing: parse `ss -ltnpH`."""
    try:
        result = subprocess.run(["ss", "-ltnpH", f"sport = :{port}"], capture_output=True, text=True)
    except FileNotFoundError:
        print(f"  neither lsof nor ss found; not killing by port {port}")
        return []
    return sorted(set(re.findall(r"pid=(\d+)", result.stdout)))


def kill_by_port_posix(port: int) -> None:
    for pid in listening_pids(port):
        _run("kill", "-9", pid)


def kill_by_port_windows(port: int) -> None:
    result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if f":{port}" in line and "LISTENING" in line:
            parts = line.split()
            if parts:
                _run("taskkill", "/F", "/PID", parts[-1])


def main() -> None:
    print(f"Stopping dast-ai (proxy:{PROXY_PORT} dashboard:{DASHBOARD_PORT})...")

    for pattern in PATTERNS:
        kill_by_pattern(pattern)

    for port in (PROXY_PORT, DASHBOARD_PORT):
        if sys.platform == "win32":
            kill_by_port_windows(port)
        else:
            kill_by_port_posix(port)

    print("Done.")


if __name__ == "__main__":
    main()
