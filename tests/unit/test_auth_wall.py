"""Unit tests for dast/triage/auth_wall.looks_like_auth_wall.

The classification is deliberately asymmetric — a false WALL triggers re-login
loops, a false CLEAR just fails one request — so the suite pins the regression
cases from the login audit (nav-bar "Login" links and Cloudflare script tags
reading as session-expired) alongside the positive signals.
"""

from __future__ import annotations

import pytest

from dast.triage.auth_wall import looks_like_auth_wall


@pytest.mark.parametrize("status", [401, 403, 407])
def test_auth_status_codes_are_always_a_wall(status):
    assert looks_like_auth_wall(status, "https://app.test/api/users", "") is True


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_to_login_url_is_a_wall(status):
    assert looks_like_auth_wall(status, "https://idp.test/login?next=/app", "") is True
    assert looks_like_auth_wall(status, "https://sso.test/signin", "") is True


def test_redirect_to_clean_url_is_not_a_wall():
    assert looks_like_auth_wall(302, "https://app.test/dashboard", "") is False


@pytest.mark.parametrize("body", [
    "Your session has expired. Please log in again.",
    "<html>Session Expired</html>",
    "You have been logged out",
    "please sign in to continue",
    "Authentication required",
    "Not authenticated",
    "token expired",
    "Access Denied: insufficient permissions",
])
def test_strong_body_phrases_are_a_wall(body):
    assert looks_like_auth_wall(200, "https://app.test/page", body) is True


def test_navbar_login_link_without_form_is_not_a_wall():
    """AUDIT REGRESSION: every site's nav bar contains the word Login — the old
    substring match turned any logged-in page into a 'session expired' wall and
    caused re-login on every run."""
    body = ('<html><head><script src="https://cdn.example.com/app.js"></script></head>'
            '<body><nav><a href="/login">Login</a> <a href="/about">About</a></nav>'
            '<main><h1>Dashboard</h1><p>Welcome back, your reports are ready.</p></main>'
            '</body></html>')
    assert looks_like_auth_wall(200, "https://app.test/dashboard", body) is False


def test_cloudflare_script_tag_is_not_a_challenge():
    """AUDIT REGRESSION: `cloudflare`/`challenge` substrings matched plain CDN
    script tags — a page that merely loads Cloudflare assets read as CAPTCHA."""
    body = ('<html><head>'
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/vue/3.4.0/vue.min.js">'
            '</script><script>const challenge = "interactive art";</script>'
            '</head><body><h1>Gallery</h1></body></html>')
    assert looks_like_auth_wall(200, "https://museum.test/exhibit", body) is False


def test_login_word_with_form_evidence_is_a_wall():
    body = ('<html><body><form action="/auth/login" method="post">'
            '<input name="email"><input type="password" name="password">'
            '<button>Login</button></form>'
            '<a href="/reset">Forgot your password?</a></body></html>')
    assert looks_like_auth_wall(200, "https://app.test/auth/login", body) is True


@pytest.mark.parametrize("body", [
    "Just a moment...",
    "Checking your browser before accessing",
    "Attention Required! | Cloudflare",
    '<div id="cf-chl-widget">loading</div>',
    "<div class=\"g-recaptcha\" data-sitekey=\"x\"></div>",
    "Verify you are a human",
])
def test_concrete_captcha_markers_are_a_wall(body):
    assert looks_like_auth_wall(200, "https://app.test/", body) is True


def test_clean_page_is_not_a_wall():
    assert looks_like_auth_wall(200, "https://app.test/api/users", '{"users": []}') is False
    assert looks_like_auth_wall(200, "https://app.test/", "") is False
    assert looks_like_auth_wall(404, "https://app.test/nope", "not found") is False
    assert looks_like_auth_wall(500, "https://app.test/boom", "traceback") is False
