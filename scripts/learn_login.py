#!/usr/bin/env python3
"""
Standalone Playwright login learning script.

Learns how a target app's login flow works step by step, logging cookies,
DOM state, and responses at each phase. Use the output to understand
what Frieren's copilot needs to do to authenticate autonomously.

Usage:
    uv run python scripts/learn_login.py \
        --url https://training.knowbe4.com \
        --email user@example.com \
        --password secret \
        --graphql-query '{ dkimConfig(id: 1, configurableType: partner, configurableId: 100) { id domain } }'
"""

import argparse
import asyncio
import json
from urllib.parse import urljoin

from playwright.async_api import async_playwright


def log_step(step: int, title: str, data: dict) -> None:
    print(f"\n{'='*60}")
    print(f"STEP {step}: {title}")
    print(f"{'='*60}")
    for k, v in data.items():
        if isinstance(v, list) and len(v) > 3:
            print(f"  {k}: [{len(v)} items]")
            for item in v[:5]:
                print(f"    {json.dumps(item, default=str)[:120]}")
        elif isinstance(v, str) and len(v) > 200:
            print(f"  {k}: {v[:200]}...")
        else:
            print(f"  {k}: {json.dumps(v, default=str)[:200]}")


def cookies_summary(cookies: list) -> list:
    return [{"name": c["name"], "value": c["value"][:30] + "..." if len(c["value"]) > 30 else c["value"],
             "domain": c.get("domain", "")} for c in cookies]


async def find_fields(page) -> dict:
    return await page.evaluate("""() => {
        const fields = [];
        document.querySelectorAll('input:not([type=hidden])').forEach(el => {
            fields.push({
                tag: 'input', type: el.type, name: el.name, id: el.id,
                placeholder: el.placeholder, value: el.value ? '(has value)' : ''
            });
        });
        const buttons = [];
        document.querySelectorAll('button, input[type=submit]').forEach(el => {
            buttons.push({
                tag: el.tagName.toLowerCase(), type: el.type, id: el.id,
                text: el.textContent?.trim()?.substring(0, 50)
            });
        });
        return { fields, buttons, url: location.href, title: document.title };
    }""")


async def run(args: argparse.Namespace) -> None:
    step = 0

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=args.headless)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        # Step 1: Navigate to login page
        step += 1
        login_url = urljoin(args.url, "/app/login")
        resp = await page.goto(login_url, wait_until="networkidle", timeout=30000)
        cookies = await context.cookies()
        dom = await find_fields(page)
        log_step(step, f"Navigate to {login_url}", {
            "status": resp.status if resp else None,
            "final_url": page.url,
            "title": dom["title"],
            "cookies": cookies_summary(cookies),
            "fields": dom["fields"],
            "buttons": dom["buttons"],
        })

        # Step 2: Find and fill email
        step += 1
        email_selectors = ["#REGISTRATION-EMAIL", "input[type=email]", "input[name=email]", "#LOGIN-EMAIL", "#email"]
        filled_email = False
        for sel in email_selectors:
            try:
                el = page.locator(sel)
                if await el.count() > 0 and await el.is_visible():
                    await el.fill(args.email)
                    filled_email = True
                    log_step(step, f"Fill email via {sel}", {"selector": sel, "email": args.email})
                    break
            except Exception:
                continue
        if not filled_email:
            log_step(step, "FAILED: no email field found", {"tried": email_selectors})
            return

        # Step 3: Click Continue/Next/Submit
        step += 1
        submit_selectors = ["#LOGIN-SUBMIT-BTN", "button[type=submit]", "button:has-text('Continue')",
                            "button:has-text('Next')", "button:has-text('Log In')", "input[type=submit]"]
        clicked = False
        for sel in submit_selectors:
            try:
                el = page.locator(sel)
                if await el.count() > 0 and await el.is_visible():
                    await el.click()
                    clicked = True
                    log_step(step, f"Click submit via {sel}", {"selector": sel})
                    break
            except Exception:
                continue
        if not clicked:
            log_step(step, "FAILED: no submit button found", {"tried": submit_selectors})
            return

        # Step 4: Wait for page transition
        step += 1
        await page.wait_for_timeout(2000)
        cookies = await context.cookies()
        dom = await find_fields(page)
        log_step(step, "After submit - check page state", {
            "url": page.url,
            "title": dom["title"],
            "cookies": cookies_summary(cookies),
            "fields": dom["fields"],
            "buttons": dom["buttons"],
        })

        # Step 5: Check if password field appeared (2-step login)
        step += 1
        password_selectors = ["#LOGIN-PASSWORD", "input[type=password]"]
        has_password = False
        for sel in password_selectors:
            try:
                el = page.locator(sel)
                if await el.count() > 0:
                    await el.wait_for(state="visible", timeout=5000)
                    has_password = True
                    break
            except Exception:
                continue

        if has_password:
            log_step(step, "Password field found (2-step login)", {"selector": sel})

            # Re-fill email if there's a separate email field on page 2
            email2_selectors = ["#LOGIN-EMAIL", "input[type=email]"]
            for esel in email2_selectors:
                try:
                    el = page.locator(esel)
                    if await el.count() > 0 and await el.is_visible():
                        current = await el.input_value()
                        if not current or current != args.email:
                            await el.fill(args.email)
                            log_step(step, f"Re-filled email on page 2 via {esel}",
                                     {"selector": esel, "previous_value": current})
                        break
                except Exception:
                    continue

            # Fill password
            step += 1
            for sel in password_selectors:
                try:
                    el = page.locator(sel)
                    if await el.count() > 0 and await el.is_visible():
                        await el.fill(args.password)
                        log_step(step, f"Fill password via {sel}", {"selector": sel})
                        break
                except Exception:
                    continue

            # Click Log In
            step += 1
            for sel in submit_selectors:
                try:
                    el = page.locator(sel)
                    if await el.count() > 0 and await el.is_visible():
                        async with page.expect_navigation(timeout=10000, wait_until="networkidle"):
                            await el.click()
                        log_step(step, f"Click Log In via {sel}", {"selector": sel})
                        break
                except Exception as exc:
                    log_step(step, f"Click {sel} exception (may still work)", {"error": str(exc)[:100]})
                    break
        else:
            log_step(step, "No password field (single-step or SSO)", {})

        # Step 6: Post-login state
        step += 1
        await page.wait_for_timeout(3000)
        cookies = await context.cookies()
        dom = await find_fields(page)
        log_step(step, "Post-login state", {
            "url": page.url,
            "title": dom["title"],
            "cookies": cookies_summary(cookies),
            "fields_count": len(dom["fields"]),
            "buttons_count": len(dom["buttons"]),
            "logged_in": "/login" not in page.url.lower(),
        })

        # Find specific cookies
        csrf_cookie = next((c for c in cookies if c["name"] == "CSRF-TOKEN"), None)
        session_cookie = next((c for c in cookies if c["name"] == "_knowbe4_session_new"), None)
        log_step(step, "Key cookies", {
            "CSRF-TOKEN": csrf_cookie["value"][:30] + "..." if csrf_cookie else "MISSING",
            "session": session_cookie["value"][:30] + "..." if session_cookie else "MISSING",
        })

        # Step 7: Test GraphQL request if query provided
        if args.graphql_query:
            step += 1
            cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            csrf_value = csrf_cookie["value"] if csrf_cookie else ""

            result = await page.evaluate("""async (args) => {
                try {
                    const resp = await fetch('/graphql', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': args.csrf,
                            'X-Requested-With': 'XMLHttpRequest',
                        },
                        body: JSON.stringify({ query: args.query }),
                        credentials: 'include',
                    });
                    const text = await resp.text();
                    return { status: resp.status, body: text.substring(0, 2000), ok: true };
                } catch (e) {
                    return { ok: false, error: e.message };
                }
            }""", {"csrf": csrf_value, "query": args.graphql_query})

            log_step(step, "GraphQL test via page.evaluate(fetch)", {
                "status": result.get("status"),
                "body": result.get("body", "")[:500],
                "ok": result.get("ok"),
            })

            # Also try via external httpx for comparison
            step += 1
            try:
                import httpx
                async with httpx.AsyncClient(verify=False) as client:
                    resp = await client.post(
                        urljoin(args.url, "/graphql"),
                        headers={
                            "Content-Type": "application/json",
                            "X-CSRF-Token": csrf_value,
                            "X-Requested-With": "XMLHttpRequest",
                            "Cookie": cookie_header,
                        },
                        content=json.dumps({"query": args.graphql_query}).encode(),
                    )
                    log_step(step, "GraphQL test via httpx (external)", {
                        "status": resp.status_code,
                        "body": resp.text[:500],
                    })
            except Exception as exc:
                log_step(step, "httpx test failed", {"error": str(exc)[:200]})

        print(f"\n{'='*60}")
        print("DONE")
        print(f"{'='*60}")
        print(f"Final URL: {page.url}")
        print(f"Logged in: {'/login' not in page.url.lower()}")
        print(f"Total cookies: {len(cookies)}")

        await browser.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="Learn login flow for Frieren")
    ap.add_argument("--url", required=True, help="Target base URL")
    ap.add_argument("--email", required=True, help="Login email")
    ap.add_argument("--password", required=True, help="Login password")
    ap.add_argument("--headless", action="store_true", help="Run headless")
    ap.add_argument("--graphql-query", help="GraphQL query to test after login")
    args = ap.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
