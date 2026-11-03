"""Threaded loopback login-page fixture server for the login-difficulty harness.

Serves one login flow per difficulty tier plus a minimal JWT auth API. Bound to
127.0.0.1:0 (ephemeral port) on a daemon thread, so tests get a real origin with
real redirects/cookies/XHR without touching the network or the proxy scope.

Tiers (detail in README.md):
    T0  trivial single-page form
    T1  two-step: email -> Continue -> password revealed (same page, JS)
    T2  non-standard identifiers + <div role=button> submit
    T3  consent overlay + honeypot + placeholder-only + disabled submit
    T4  credential fields inside an <iframe>
    T5  CAPTCHA page (graceful-bail target)
    T6  SPA: POST /api/auth/login -> JWT in localStorage -> Bearer on /api/me
    T7  SPA with a short-lived JWT (exp refresh target)
    T8  hybrid: session cookie + CSRF + Bearer required together
    T9  SSO: app -> redirect to a second-origin IdP -> back authenticated
    T10 MFA: after password, an OTP challenge page
    T11 OAuth-style "Authorize" consent button before returning

The JWT here is a real HS256 token (hmac-signed) so ``/api/me`` can verify it and
``dast.ai.copilot.session._decode_jwt_exp`` can read its ``exp`` claim. The secret
is fixed and test-only.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Iterator, Optional, Tuple
from urllib.parse import parse_qs, urlparse

USERNAME = "pentester@test.local"
PASSWORD = "Frieren!2026"
SESSION_COOKIE = "fixture_session"
SESSION_VALUE = "authenticated-ok"
CSRF_COOKIE = "CSRF-TOKEN"
CSRF_VALUE = "csrf-fixture-token"

_JWT_SECRET = b"login-fixture-test-secret-not-a-real-key"


# --------------------------------------------------------------------------- JWT


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def issue_jwt(subject: str = USERNAME, ttl_seconds: int = 3600) -> str:
    """Mint an HS256 JWT with an ``exp`` claim ``ttl_seconds`` in the future."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": subject, "iat": int(time.time()), "exp": int(time.time()) + ttl_seconds}
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(payload).encode())}"
    signature = hmac.new(_JWT_SECRET, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(signature)}"


def verify_jwt(token: str) -> bool:
    """Verify an HS256 JWT's signature and ``exp``. Returns True when valid.

    Tolerates any malformed input by returning False rather than raising.
    """
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}"
        expected = hmac.new(_JWT_SECRET, signing_input.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(signature_b64)):
            return False
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        return False
    exp = payload.get("exp")
    return not (exp is not None and float(exp) < time.time())


# ------------------------------------------------------------------------- pages
# Each tier page posts to ``<tier>/submit`` (or an API route) and, on success, the
# server sets a session cookie and redirects to /dashboard. The credential check is
# centralised in ``_credentials_ok``.

_PAGE_HEAD = (
    "<!doctype html><html><head><meta charset='utf-8'>"
    "<title>{title}</title></head><body>"
)
_PAGE_FOOT = "</body></html>"


def _page(title: str, body: str) -> str:
    return _PAGE_HEAD.format(title=title) + body + _PAGE_FOOT


def _dashboard_page() -> str:
    return _page("Dashboard", "<h1 id='dashboard'>Welcome, you are logged in.</h1>")


_T0 = _page(
    "T0 Login",
    "<h1>Sign in</h1>"
    "<form method='post' action='/t0/submit'>"
    "<input type='email' name='email' placeholder='Email' required>"
    "<input type='password' name='password' placeholder='Password' required>"
    "<button type='submit'>Log In</button>"
    "</form>",
)

_T1 = _page(
    "T1 Two-step Login",
    "<h1>Sign in</h1>"
    "<form method='post' action='/t1/submit'>"
    "<input type='email' name='email' placeholder='Email'>"
    "<div id='pw-wrap' style='display:none'>"
    "<input type='password' name='password' placeholder='Password'></div>"
    "<button type='button' id='continue-btn'>Continue</button>"
    "<button type='submit' id='submit-btn' style='display:none'>Log In</button>"
    "</form>"
    "<script>document.getElementById('continue-btn').addEventListener('click',function(){"
    "document.getElementById('pw-wrap').style.display='block';"
    "document.getElementById('submit-btn').style.display='inline';"
    "this.style.display='none';});</script>",
)

# T2: no type=email, odd names, submit is a div with role=button driven by JS.
_T2 = _page(
    "T2 Login",
    "<h1>Sign in</h1>"
    "<form method='post' action='/t2/submit' id='f'>"
    "<input type='text' name='j_username' id='j_username' placeholder='User'>"
    "<input type='password' name='pwd' id='pwd' placeholder='Secret'>"
    "<div role='button' id='go' tabindex='0'>Sign in</div>"
    "</form>"
    "<script>document.getElementById('go').addEventListener('click',function(){"
    "document.getElementById('f').submit();});</script>",
)

# T3: a cookie-consent banner (visual noise), a honeypot field that must stay
# empty, and placeholder-only labels. The banner is docked to the bottom so it is
# not full-screen (a full-screen overlay would intercept pointer events and is a
# separate, harder tier). Required fields block the premature submit so the real
# password field is reached.
_T3 = _page(
    "T3 Login",
    "<div id='consent' style='position:fixed;left:0;right:0;bottom:0;height:40px;"
    "background:#222;color:#fff'>"
    "We use cookies. <button id='accept-cookies'>Accept</button></div>"
    "<h1>Sign in</h1>"
    "<form method='post' action='/t3/submit'>"
    "<input type='email' name='email' placeholder='Email' required>"
    "<input type='password' name='password' placeholder='Password' required>"
    # honeypot: must remain empty or the submit is treated as a bot.
    "<input type='text' name='website' id='website' "
    "style='position:absolute;left:-9999px' tabindex='-1' autocomplete='off'>"
    "<button type='submit' id='submit-btn'>Log In</button>"
    "</form>"
    "<script>"
    "document.getElementById('accept-cookies').addEventListener('click',function(){"
    "document.getElementById('consent').style.display='none';});"
    "</script>",
)

# T4: credential fields live inside an iframe (different browsing context).
_T4 = _page(
    "T4 Login",
    "<h1>Sign in</h1>"
    "<iframe src='/t4/frame' id='login-frame' width='400' height='300'></iframe>",
)
_T4_FRAME = _page(
    "T4 Frame",
    "<form method='post' action='/t4/submit'>"
    "<input type='email' name='email' placeholder='Email'>"
    "<input type='password' name='password' placeholder='Password'>"
    "<button type='submit'>Log In</button>"
    "</form>",
)

# T5: CAPTCHA signature that dast.profiles.flow.has_captcha recognises.
_T5 = _page(
    "T5 Login",
    "<h1>Sign in</h1>"
    "<form method='post' action='/t5/submit'>"
    "<input type='email' name='email' placeholder='Email'>"
    "<input type='password' name='password' placeholder='Password'>"
    "<div class='g-recaptcha' data-sitekey='fixture'></div>"
    "<p>Please confirm you are not a robot.</p>"
    "<button type='submit'>Log In</button>"
    "</form>"
    "<script src='https://www.google.com/recaptcha/api.js'></script>",
)

# T6/T7: SPA that authenticates via fetch and stores the JWT in localStorage.
def _spa_page(auth_path: str) -> str:
    return _page(
        "SPA Login",
        "<h1>Sign in</h1>"
        "<form id='f' onsubmit='return false'>"
        "<input type='email' name='email' id='email' placeholder='Email'>"
        "<input type='password' name='password' id='password' placeholder='Password'>"
        "<button type='submit' id='submit-btn'>Log In</button>"
        "</form><div id='app'></div>"
        "<script>"
        "document.getElementById('f').addEventListener('submit',async function(){"
        "const r=await fetch('" + auth_path + "',{method:'POST',"
        "headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({email:document.getElementById('email').value,"
        "password:document.getElementById('password').value})});"
        "if(r.ok){const d=await r.json();localStorage.setItem('access_token',d.access_token);"
        "document.getElementById('app').innerHTML="
        "\"<h1 id='dashboard'>Welcome, you are logged in.</h1>\";}"
        "});"
        "</script>",
    )


# T9 (app side): an email-first form that navigates (GET) to the IdP's authorize
# endpoint on a second origin, carrying the return URL. The IdP then collects the
# password and redirects back to the app's /dashboard with a session cookie.
def _t9_app(idp_base: str) -> str:
    return _page(
        "T9 App Login",
        "<h1>Sign in with SSO</h1>"
        "<form method='get' action='" + idp_base + "/idp/authorize'>"
        "<input type='email' name='email' placeholder='Email'>"
        "<input type='hidden' name='redirect_uri' value='RETURN'>"
        "<button type='submit'>Continue</button>"
        "</form>",
    )


_IDP_LOGIN = _page(
    "IdP Login",
    "<h1>Identity Provider</h1>"
    "<form method='post' action='/idp/submit'>"
    "<input type='email' name='email' placeholder='Email'>"
    "<input type='password' name='password' placeholder='Password'>"
    "<input type='hidden' name='redirect_uri' value='{redirect_uri}'>"
    "<button type='submit'>Sign In</button>"
    "</form>",
)

# T10: OTP/MFA challenge after password.
_T10 = _page(
    "T10 Login",
    "<h1>Sign in</h1>"
    "<form method='post' action='/t10/submit'>"
    "<input type='email' name='email' placeholder='Email' required>"
    "<input type='password' name='password' placeholder='Password' required>"
    "<button type='submit'>Log In</button>"
    "</form>",
)
_T10_MFA = _page(
    "MFA Challenge",
    "<h1>Two-factor authentication</h1>"
    "<form method='post' action='/t10/mfa'>"
    "<input type='text' name='code' placeholder='6-digit code' maxlength='6'>"
    "<button type='submit'>Verify</button>"
    "</form>",
)

# T11: OAuth-style authorize/consent button after password.
_T11 = _page(
    "T11 Login",
    "<h1>Sign in</h1>"
    "<form method='post' action='/t11/submit'>"
    "<input type='email' name='email' placeholder='Email' required>"
    "<input type='password' name='password' placeholder='Password' required>"
    "<button type='submit'>Log In</button>"
    "</form>",
)
_T11_AUTHORIZE = _page(
    "Authorize",
    "<h1>Authorize access</h1>"
    "<p>This application wants to access your account.</p>"
    "<form method='post' action='/t11/authorize'>"
    "<button type='submit' id='authorize-btn'>Authorize</button>"
    "</form>",
)


def _credentials_ok(email: str, password: str) -> bool:
    return email == USERNAME and password == PASSWORD


# ---------------------------------------------------------------------- handler


class _Handler(BaseHTTPRequestHandler):
    # Silence per-request logging noise in the test output.
    def log_message(self, *args: Any) -> None:  # noqa: D401
        return

    # -- helpers ----------------------------------------------------------------
    def _send_html(self, html: str, status: int = 200,
                   extra_headers: Optional[Dict[str, str]] = None) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: Dict[str, Any], status: int = 200,
                   extra_headers: Optional[Dict[str, str]] = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, set_session: bool = False) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        if set_session:
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}={SESSION_VALUE}; Path=/")
            self.send_header("Set-Cookie", f"{CSRF_COOKIE}={CSRF_VALUE}; Path=/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _read_form(self) -> Dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        content_type = (self.headers.get("Content-Type") or "").lower()
        if "application/json" in content_type:
            with contextlib.suppress(ValueError, json.JSONDecodeError):
                return {str(k): str(v) for k, v in json.loads(raw or "{}").items()}
            return {}
        parsed = parse_qs(raw)
        return {key: values[0] for key, values in parsed.items()}

    def _idp_base(self) -> str:
        server: LoginFixtureServer = self.server  # type: ignore[assignment]
        return server.idp_base or ""

    def _return_uri(self) -> str:
        server: LoginFixtureServer = self.server  # type: ignore[assignment]
        return f"http://127.0.0.1:{server.server_address[1]}/dashboard"

    # -- GET --------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)
        pages = {
            "/t0/login": _T0, "/t1/login": _T1, "/t2/login": _T2,
            "/t3/login": _T3, "/t4/login": _T4, "/t4/frame": _T4_FRAME,
            "/t5/login": _T5, "/t10/login": _T10, "/t10/mfa": _T10_MFA,
            "/t11/login": _T11, "/t11/authorize": _T11_AUTHORIZE,
            "/dashboard": _dashboard_page(),
        }
        if path in pages:
            self._send_html(pages[path])
            return
        if path in ("/t6/login", "/t7/login"):
            auth = "/api/auth/login" if path == "/t6/login" else "/api/auth/login?ttl=20"
            self._send_html(_spa_page(auth))
            return
        if path == "/t9/login":
            self._send_html(_t9_app(self._idp_base()).replace("RETURN", self._return_uri()))
            return
        if path == "/idp/authorize":
            redirect_uri = (query.get("redirect_uri") or [""])[0]
            self._send_html(_IDP_LOGIN.format(redirect_uri=redirect_uri))
            return
        if path == "/api/me":
            self._api_me()
            return
        self._send_html(_page("Not found", "<h1>404</h1>"), status=404)

    # -- POST -------------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        form = self._read_form()
        server: LoginFixtureServer = self.server  # type: ignore[assignment]
        server.posts.append((path, form))

        # T2 uses non-standard field names; normalise before validating.
        if path == "/t2/submit":
            self._finish_login({"email": form.get("j_username", ""),
                                "password": form.get("pwd", "")})
            return
        # Standard single/two-step tiers: validate and redirect to /dashboard.
        if path in ("/t0/submit", "/t1/submit", "/t4/submit"):
            self._finish_login(form)
            return
        if path == "/t3/submit":
            if form.get("website"):  # honeypot tripped
                self._send_html(_page("Blocked", "<h1>Bot detected</h1>"), status=403)
                return
            self._finish_login(form)
            return
        if path == "/t5/submit":
            # CAPTCHA tier: never succeeds through automation.
            self._send_html(_page("CAPTCHA", "<h1>Please solve the CAPTCHA</h1>"), status=403)
            return
        if path == "/t10/submit":
            if _credentials_ok(form.get("email", ""), form.get("password", "")):
                self._redirect("/t10/mfa")
            else:
                self._send_html(_page("Denied", "<h1>Invalid credentials</h1>"), status=401)
            return
        if path == "/t11/submit":
            if _credentials_ok(form.get("email", ""), form.get("password", "")):
                self._redirect("/t11/authorize")
            else:
                self._send_html(_page("Denied", "<h1>Invalid credentials</h1>"), status=401)
            return
        if path == "/t11/authorize":
            self._redirect("/dashboard", set_session=True)
            return
        if path == "/idp/submit":
            redirect_uri = form.get("redirect_uri") or self._return_uri()
            if _credentials_ok(form.get("email", ""), form.get("password", "")):
                self._redirect(redirect_uri, set_session=True)
            else:
                self._send_html(_page("Denied", "<h1>Invalid credentials</h1>"), status=401)
            return
        if path == "/api/auth/login":
            self._api_auth_login(form)
            return
        self._send_html(_page("Not found", "<h1>404</h1>"), status=404)

    def _finish_login(self, form: Dict[str, str]) -> None:
        if _credentials_ok(form.get("email", ""), form.get("password", "")):
            self._redirect("/dashboard", set_session=True)
        else:
            self._send_html(_page("Denied", "<h1>Invalid credentials</h1>"), status=401)

    def _api_auth_login(self, form: Dict[str, str]) -> None:
        if not _credentials_ok(form.get("email", ""), form.get("password", "")):
            self._send_json({"error": "invalid_credentials"}, status=401)
            return
        ttl_raw = parse_qs(urlparse(self.path).query).get("ttl", ["3600"])[0]
        try:
            ttl = int(ttl_raw)
        except ValueError:
            ttl = 3600
        token = issue_jwt(ttl_seconds=ttl)
        # T8 hybrid: also set the session + CSRF cookies.
        headers = {
            "Set-Cookie": f"{SESSION_COOKIE}={SESSION_VALUE}; Path=/",
        }
        self._send_json({"access_token": token, "token_type": "Bearer"},
                        extra_headers=headers)

    def _api_me(self) -> None:
        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Bearer ") or not verify_jwt(auth[7:].strip()):
            self._send_json({"error": "unauthorized"}, status=401)
            return
        self._send_json({"user": USERNAME, "authenticated": True})


class LoginFixtureServer(HTTPServer):
    """HTTPServer carrying per-instance test state (recorded POSTs, IdP base)."""

    def __init__(self, address: Tuple[str, int]) -> None:
        super().__init__(address, _Handler)
        self.posts: list[Tuple[str, Dict[str, str]]] = []
        self.idp_base: str = ""


@contextlib.contextmanager
def login_fixture(with_idp: bool = False) -> Iterator["LoginFixtureServer"]:
    """Start the fixture server (and optionally a second-origin IdP) on 127.0.0.1.

    Yields the main server; ``server.base_url`` gives the origin to target. When
    ``with_idp`` is True the same process also runs a second server on a different
    port (a distinct origin) used as the SSO identity provider for T9.
    """
    main = LoginFixtureServer(("127.0.0.1", 0))
    main_thread = threading.Thread(target=main.serve_forever, daemon=True)
    main_thread.start()
    idp: Optional[LoginFixtureServer] = None
    idp_thread: Optional[threading.Thread] = None
    if with_idp:
        idp = LoginFixtureServer(("127.0.0.1", 0))
        idp_thread = threading.Thread(target=idp.serve_forever, daemon=True)
        idp_thread.start()
        main.idp_base = f"http://127.0.0.1:{idp.server_address[1]}"
    # Attach a convenience attribute without upsetting type checkers.
    setattr(main, "base_url", f"http://127.0.0.1:{main.server_address[1]}")
    try:
        yield main
    finally:
        main.shutdown()
        main.server_close()
        if idp is not None:
            idp.shutdown()
            idp.server_close()
