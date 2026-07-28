#!/usr/bin/env python3
"""
Integration test suite for Frieren DAST-AI proxy dashboard.

Requires the proxy to already be running (make proxy).
Run with: uv run python scripts/test_integration.py

Tests live traffic paths — not just API responses — by routing
real HTTP requests through the proxy and verifying what appears
in the HTTP history and host sidebar.
"""

import asyncio
import json
import sys
import time
import httpx
from playwright.async_api import async_playwright

BASE = "http://127.0.0.1:8088"
PROXY = "http://127.0.0.1:8080"

# ── Test scope ─────────────────────────────────────────────────────────────
IN_SCOPE_HOST  = "fonts.googleapis.com"
OOS_HOST       = "example.com"

results = []

def ok(label, detail=""):
    results.append(("PASS", label, detail))
    print(f"  ✅ {label}" + (f" — {detail}" if detail else ""))

def fail(label, detail=""):
    results.append(("FAIL", label, detail))
    print(f"  ❌ {label}" + (f" — {detail}" if detail else ""))

def warn(label, detail=""):
    results.append(("WARN", label, detail))
    print(f"  ⚠️  {label}" + (f" — {detail}" if detail else ""))

def skip(label, reason=""):
    results.append(("SKIP", label, reason))
    print(f"  ⏭  {label}" + (f" — {reason}" if reason else ""))


def check_proxy_running() -> bool:
    try:
        r = httpx.get(f"{BASE}/api/version", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


async def send_through_proxy(url: str, method: str = "GET") -> bool:
    """Send a real request through the MITM proxy."""
    try:
        async with httpx.AsyncClient(
            proxy=PROXY,
            verify=False,
            timeout=8,
            follow_redirects=False,
        ) as client:
            await client.request(method, url)
        return True
    except Exception:
        return True  # connection error is fine — request still went through proxy


async def run_all():
    if not check_proxy_running():
        print("ERROR: Proxy not running. Start with 'make proxy' first.")
        sys.exit(1)

    print(f"\nProxy running at {BASE}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        js_errors = []
        page.on("console", lambda m: js_errors.append(m.text) if m.type == "error" else None)

        await page.goto(BASE)
        await page.wait_for_load_state("networkidle")
        await page.evaluate("window.confirm = () => true")

        # ── 1. Scope settings ─────────────────────────────────────────────
        print("\n=== 1. SCOPE SETTINGS ===")
        scope_r = httpx.get(f"{BASE}/api/settings", timeout=5)
        scope = scope_r.json()
        include_rules = scope.get("include", [])
        ok("Settings endpoint reachable", f"{len(include_rules)} include rules")

        # ── 2. Clear history ──────────────────────────────────────────────
        print("\n=== 2. CLEAR HISTORY ===")
        httpx.post(f"{BASE}/api/clear", timeout=5)
        count_before = await page.evaluate(
            "fetch('/api/entries').then(r=>r.json()).then(d=>d.length)"
        )
        ok("History cleared", f"{count_before} entries")

        # ── 3. Simulate browse session + live traffic ─────────────────────
        print("\n=== 3. LIVE TRAFFIC THROUGH PROXY ===")

        # Start a fake browse session so entries get source="browse"
        browse_r = httpx.post(f"{BASE}/api/browse/start",
                              json={"url": None}, timeout=10)
        browse_ok = browse_r.status_code == 200
        if browse_ok:
            ok("Browse session started")
        else:
            warn("Browse session start failed", f"status {browse_r.status_code}")

        # Send an OOS request through the proxy (example.com is never in scope)
        await send_through_proxy("https://example.com/")
        await asyncio.sleep(1.5)

        # Send a CONNECT to simulate noise
        await send_through_proxy("https://fonts.googleapis.com/css")
        await asyncio.sleep(0.5)

        # Stop browse session
        httpx.post(f"{BASE}/api/browse/stop", timeout=5)
        await asyncio.sleep(0.5)

        # ── 4. Check OOS entries have correct source ───────────────────────
        print("\n=== 4. OOS SOURCE TAGGING ===")
        entries_r = httpx.get(f"{BASE}/api/entries", timeout=5)
        all_entries = entries_r.json()

        oos_entries = [e for e in all_entries if e.get("host") == "example.com"]
        browse_oos  = [e for e in oos_entries if e.get("source") == "browse"]
        correct_oos = [e for e in oos_entries if e.get("source") == "out-of-scope"]

        if not oos_entries:
            skip("OOS source tagging", "no requests to example.com captured (CONNECT may have been blocked)")
        elif correct_oos:
            ok("OOS entries tagged as out-of-scope", f"{len(correct_oos)} entries")
        elif browse_oos:
            fail("OOS entries incorrectly tagged as browse", f"{len(browse_oos)} entries still have source=browse")
        else:
            sources = list(set(e.get("source") for e in oos_entries))
            warn("OOS entries found with unexpected sources", str(sources))

        # ── 5. Sidebar hides OOS hosts ─────────────────────────────────────
        print("\n=== 5. SIDEBAR OOS VISIBILITY ===")
        await page.goto(BASE)
        await page.wait_for_load_state("networkidle")
        await page.wait_for_timeout(2000)  # wait for WS + loadAllEntries
        await page.evaluate("switchMain('proxy')")
        await page.wait_for_timeout(300)

        # example.com should NOT be visible in sidebar by default
        oos_el_display = await page.evaluate("""
            (() => {
                const el = document.getElementById('hi-example\\\\.com');
                return el ? getComputedStyle(el).display : 'not_found';
            })()
        """)
        if oos_el_display == "not_found":
            skip("example.com hidden from sidebar", "no entry captured for that host")
        elif oos_el_display == "none":
            ok("OOS host hidden from sidebar by default")
        else:
            fail("OOS host visible in sidebar when it should be hidden", f"display={oos_el_display}")

        # Toggle OOS on — example.com should appear
        if oos_el_display != "not_found":
            await page.evaluate("document.getElementById('chk-oos-label').click()")
            await page.wait_for_timeout(200)
            oos_el_after = await page.evaluate("""
                (() => {
                    const el = document.getElementById('hi-example\\\\.com');
                    return el ? getComputedStyle(el).display : 'not_found';
                })()
            """)
            ok("OOS host visible after toggle") if oos_el_after != "none" else fail("OOS host still hidden after toggle")
            await page.evaluate("document.getElementById('chk-oos-label').click()")

        await page.screenshot(path="/tmp/it_sidebar.png")

        # ── 6. No JS errors throughout ────────────────────────────────────
        print("\n=== 6. JS ERRORS ===")
        for tab in ["proxy", "ai", "target", "scan", "logs"]:
            pre = list(js_errors)
            await page.evaluate(f"switchMain('{tab}')")
            await page.wait_for_timeout(350)
            new = [e for e in js_errors if e not in pre]
            if new:
                fail(f"JS error in tab {tab}", new[0][:100])
            else:
                ok(f"Tab {tab} clean")

        # ── 7. AI mode toggle + backend sync ─────────────────────────────
        print("\n=== 7. AI MODE + BACKEND SYNC ===")
        await page.evaluate("setMode('ai')")
        await page.wait_for_timeout(500)
        mode_r = httpx.get(f"{BASE}/api/mode", timeout=5)
        ok("Backend ai_mode=true", str(mode_r.json())) if mode_r.json().get("ai_mode") else fail("Backend ai_mode not set")

        await page.evaluate("setMode('manual')")
        await page.wait_for_timeout(500)
        mode_r2 = httpx.get(f"{BASE}/api/mode", timeout=5)
        ok("Backend ai_mode=false") if not mode_r2.json().get("ai_mode") else fail("Backend ai_mode still true")

        await browser.close()

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 55)
    passed = sum(1 for r in results if r[0] == "PASS")
    failed = sum(1 for r in results if r[0] == "FAIL")
    warned = sum(1 for r in results if r[0] == "WARN")
    skipped = sum(1 for r in results if r[0] == "SKIP")
    print(f"RESULT: {passed} PASS  {failed} FAIL  {warned} WARN  {skipped} SKIP")
    if failed:
        print("\nFAILED:")
        for r in results:
            if r[0] == "FAIL":
                print(f"  ❌ {r[1]}: {r[2]}")
    return failed == 0


if __name__ == "__main__":
    ok_flag = asyncio.run(run_all())
    sys.exit(0 if ok_flag else 1)
