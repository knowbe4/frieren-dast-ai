#!/usr/bin/env python3
"""Kill all dast-ai proxy and dashboard processes on Linux, macOS, or Windows."""
import os
import subprocess
import sys

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


def kill_by_port_macos(port: int) -> None:
    result = subprocess.run(["lsof", "-ti", f":{port}"], capture_output=True, text=True)
    for pid in result.stdout.strip().splitlines():
        if pid.strip():
            _run("kill", "-9", pid.strip())


def kill_by_port_linux(port: int) -> None:
    _run("fuser", "-k", f"{port}/tcp")


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
        if sys.platform == "darwin":
            kill_by_port_macos(port)
        elif sys.platform == "win32":
            kill_by_port_windows(port)
        else:
            kill_by_port_linux(port)

    print("Done.")


if __name__ == "__main__":
    main()
