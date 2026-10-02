#!/usr/bin/env python3
"""
PoC: kb4-agent-defend rule trigger → Okta session health correlation.

GOAL: systematically trigger known agent-defend rule categories (block, warn,
inert) while monitoring whether the Okta session drops. Determines whether the
agent's block/audit activity has a side-effect on Okta session validity.

WHAT IT DOES:
  1. Checks Okta session health (via the /api/v1/sessions/me endpoint if an Okta
     domain + session cookie are provided, otherwise via a HEAD to an Okta-protected
     URL that returns 200 when authenticated and 302/401 when not).
  2. Sends a controlled payload to the agent-defend daemon socket, triggering a
     BLOCK verdict (patterns extracted from the live rules file).
  3. Waits a configurable interval, then re-checks Okta.
  4. Repeats for several rule categories to isolate which (if any) class causes it.
  5. Logs every step with timestamps for correlation.

SAFE BY DESIGN:
  - No real command is executed — the PoC talks directly to the Unix socket,
    bypassing the shell entirely (the daemon evaluates the payload but nothing runs).
  - No external network calls except the Okta health check (a single GET/HEAD).
  - No file writes, no credential access, no keychain reads.

USAGE:
  # Minimal — uses the socket directly, checks Okta via a protected URL:
  uv run python scripts/poc_agent_defend_okta.py \
      --okta-check-url https://knowbe4.okta.com/app/UserHome

  # With Okta session API (more precise):
  uv run python scripts/poc_agent_defend_okta.py \
      --okta-domain knowbe4.okta.com \
      --okta-sid <your_sid_cookie_value>
"""

from __future__ import annotations

import argparse
import json
import socket
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

SOCKET_PATH = "/Library/Application Support/agent-defend/agent-defend.sock"
WAIT_AFTER_TRIGGER = 5  # seconds to wait after each trigger before re-checking Okta

# Payloads that trigger known rule categories — extracted from the live rules JSON.
# Each one is sent as a DetectorInput to the daemon socket (no real command runs).
TRIGGERS = [
    {
        "label": "block-macos-keychain (regex, block severity on live / warn on current rules)",
        "rule_id": "block-macos-keychain",
        "detector_input": {
            "client": "claude",
            "action": "shell_exec",
            "native_tool_name": "Bash",
            "command": "security find-generic-password -s test-service -w",
            "tool_input": {"command": "security find-generic-password -s test-service -w"},
            "cwd": "/tmp",
            "session_id": "poc-test-session",
        },
    },
    {
        "label": "block-sudo (regex, block severity)",
        "rule_id": "block-sudo",
        "detector_input": {
            "client": "claude",
            "action": "shell_exec",
            "native_tool_name": "Bash",
            "command": "sudo ls /etc",
            "tool_input": {"command": "sudo ls /etc"},
            "cwd": "/tmp",
            "session_id": "poc-test-session",
        },
    },
    {
        "label": "block-cat-ssh (regex, block severity)",
        "rule_id": "block-cat-ssh",
        "detector_input": {
            "client": "claude",
            "action": "shell_exec",
            "native_tool_name": "Bash",
            "command": "cat ~/.ssh/id_rsa",
            "tool_input": {"command": "cat ~/.ssh/id_rsa"},
            "cwd": "/tmp",
            "session_id": "poc-test-session",
        },
    },
    {
        "label": "R-BP-001 TLS verify disabled (ast, block severity)",
        "rule_id": "R-BP-001",
        "detector_input": {
            "client": "claude",
            "action": "shell_exec",
            "native_tool_name": "Bash",
            "command": "curl -k https://example.com",
            "tool_input": {"command": "curl -k https://example.com"},
            "cwd": "/tmp",
            "session_id": "poc-test-session",
        },
    },
    {
        "label": "INERT baseline (should be ALLOW — no rule match)",
        "rule_id": "none",
        "detector_input": {
            "client": "claude",
            "action": "shell_exec",
            "native_tool_name": "Bash",
            "command": "echo hello world",
            "tool_input": {"command": "echo hello world"},
            "cwd": "/tmp",
            "session_id": "poc-test-session",
        },
    },
]


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def send_to_daemon(detector_input: dict) -> dict:
    """Send a DetectorInput to the agent-defend daemon and return the verdict."""
    payload = json.dumps(detector_input).encode() + b"\n"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect(SOCKET_PATH)
        s.sendall(payload)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break
        return json.loads(data.strip())
    finally:
        s.close()


def check_okta_session_api(domain: str, sid: str) -> dict:
    """Check Okta session via /api/v1/sessions/me (most accurate)."""
    import urllib.request
    url = f"https://{domain}/api/v1/sessions/me"
    req = urllib.request.Request(url, headers={"Cookie": f"sid={sid}"})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        body = json.loads(resp.read())
        return {"alive": True, "status": resp.status, "login": body.get("login"),
                "expires": body.get("expiresAt")}
    except urllib.error.HTTPError as e:
        return {"alive": False, "status": e.code, "reason": str(e.reason)[:100]}
    except Exception as e:
        return {"alive": None, "error": str(e)[:100]}


def check_okta_url(url: str) -> dict:
    """HEAD a protected URL: 200 = alive, 302/401 = dead."""
    import urllib.request
    req = urllib.request.Request(url, method="HEAD")
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return {"alive": True, "status": resp.status}
    except urllib.error.HTTPError as e:
        alive = e.code not in (302, 301, 401, 403)
        return {"alive": alive, "status": e.code}
    except Exception as e:
        return {"alive": None, "error": str(e)[:100]}


def main():
    parser = argparse.ArgumentParser(
        description="PoC: trigger agent-defend rules and check Okta session health.")
    parser.add_argument("--okta-domain", help="Okta domain (e.g. knowbe4.okta.com)")
    parser.add_argument("--okta-sid", help="Okta session cookie (sid) value")
    parser.add_argument("--okta-check-url",
                        help="Okta-protected URL to HEAD (fallback if no domain/sid)")
    parser.add_argument("--wait", type=int, default=WAIT_AFTER_TRIGGER,
                        help=f"Seconds to wait after each trigger (default {WAIT_AFTER_TRIGGER})")
    args = parser.parse_args()

    use_api = args.okta_domain and args.okta_sid
    use_url = args.okta_check_url
    if not use_api and not use_url:
        print("Provide --okta-domain + --okta-sid OR --okta-check-url for session health checks.")
        print("Without it the PoC still triggers rules and prints verdicts, but cannot check Okta.")

    def check_okta() -> Optional[dict]:
        if use_api:
            return check_okta_session_api(args.okta_domain, args.okta_sid)
        if use_url:
            return check_okta_url(args.okta_check_url)
        return None

    print(f"[{ts()}] === kb4-agent-defend Okta correlation PoC ===")
    print(f"[{ts()}] Socket: {SOCKET_PATH}")
    print(f"[{ts()}] Triggers: {len(TRIGGERS)}")
    print(f"[{ts()}] Wait between triggers: {args.wait}s")
    print()

    # Baseline Okta check
    okta_before = check_okta()
    if okta_before is not None:
        print(f"[{ts()}] BASELINE Okta: {json.dumps(okta_before)}")
        if not okta_before.get("alive"):
            print(f"[{ts()}] WARNING: Okta session already dead/unreachable — results may not be meaningful.")
    print()

    results = []
    for i, trigger in enumerate(TRIGGERS, 1):
        label = trigger["label"]
        print(f"[{ts()}] --- Trigger {i}/{len(TRIGGERS)}: {label} ---")

        # Send to daemon
        try:
            verdict = send_to_daemon(trigger["detector_input"])
            print(f"[{ts()}] Verdict: {json.dumps(verdict)}")
        except Exception as e:
            verdict = {"error": str(e)[:100]}
            print(f"[{ts()}] Socket error: {e}")

        # Wait
        print(f"[{ts()}] Waiting {args.wait}s...")
        time.sleep(args.wait)

        # Check Okta
        okta_after = check_okta()
        if okta_after is not None:
            print(f"[{ts()}] Okta after trigger: {json.dumps(okta_after)}")
            alive_before = okta_before.get("alive") if okta_before else None
            alive_after = okta_after.get("alive")
            if alive_before and not alive_after:
                print(f"[{ts()}] >>> OKTA SESSION DROPPED after trigger '{label}' <<<")
        else:
            okta_after = {}

        results.append({
            "trigger": label, "rule_id": trigger["rule_id"],
            "verdict": verdict.get("verdict", verdict.get("error", "?")),
            "okta_alive_after": okta_after.get("alive"),
        })
        print()

    # Summary
    print(f"[{ts()}] === SUMMARY ===")
    print(f"{'Trigger':<55} {'Verdict':<10} {'Okta alive'}")
    print("-" * 80)
    for r in results:
        print(f"{r['trigger'][:55]:<55} {r['verdict']:<10} {r['okta_alive_after']}")

    dropped = [r for r in results if r["okta_alive_after"] is False]
    if dropped:
        print(f"\nOkta session dropped after {len(dropped)} trigger(s):")
        for r in dropped:
            print(f"  - {r['trigger']} (verdict: {r['verdict']})")
        print("\nThis suggests agent-defend activity correlates with Okta session loss.")
    else:
        if any(r["okta_alive_after"] is not None for r in results):
            print("\nOkta session survived all triggers — agent-defend likely not the cause.")
        else:
            print("\nNo Okta health check configured — add --okta-domain/--okta-sid or --okta-check-url.")

    # Also note the audit log storm
    log_path = Path("/Library/Application Support/agent-defend/agent-defend.log")
    if log_path.exists():
        log_text = log_path.read_text(errors="replace")
        n403 = log_text.count("rejected with 403")
        if n403 > 10:
            print(f"\nNOTE: agent-defend.log contains {n403} lines with '403 (invalid/revoked API key)'.")
            print("The daemon is in a retry storm (heartbeat + tamper-alert + audit, all failing).")
            print("If the audit endpoint shares infrastructure or auth with your identity provider,")
            print("this could indirectly cause session churn. The API key needs to be renewed.")


if __name__ == "__main__":
    main()
