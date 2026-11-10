"""High-fidelity synthetic login environments that imitate the DOM and flow of
real products, for measuring how the adaptive-login cascade copes with real-world
diversity (not just the isolated T0-T11 difficulty tiers).

Each environment mirrors the field names, ids, control structure and multi-step
flow of a known login product, wrapped in realistic page noise (a cookie-consent
banner, a decoy search form, nav links, hidden CSRF/telemetry inputs). All are
served on 127.0.0.1 - nothing hits the real product.

Environments:
    okta       identifier-first, two-step (username -> Next -> password)
    auth0      Universal Login, single page, "Continue" submit
    keycloak   single page, #kc-login submit, realm noise
    azure_ad   email -> Next -> password -> "Stay signed in?" consent (Yes)
    wordpress  wp-login: name=log / name=pwd, remember-me, #wp-submit
    django     admin: #id_username / #id_password, csrfmiddlewaretoken hidden

The two-step / consent flows are client-side (JS reveals the next section) so a
single POST endpoint validates, and the LLM fallback must click through the steps.
"""

from __future__ import annotations

import contextlib
import threading
from http.server import HTTPServer
from typing import Dict, Iterator, Tuple
from urllib.parse import urlparse

from tests.fixtures.login_pages.server import (
    PASSWORD,
    SESSION_COOKIE,
    SESSION_VALUE,
    USERNAME,
    _Handler,
    _dashboard_page,
    _page,
)

# env -> (username field name, password field name). Standard single/two-step
# flows validate through this map; sso_mfa is handled specially (OTP wall).
_FIELD_MAP: Dict[str, Tuple[str, str]] = {
    "okta": ("identifier", "credentials.passcode"),
    "auth0": ("username", "password"),
    "keycloak": ("username", "password"),
    "azure_ad": ("loginfmt", "passwd"),
    "wordpress": ("log", "pwd"),
    "django": ("username", "password"),
    "adfs": ("UserName", "Password"),
    "intl_ptbr": ("usuario", "senha"),
    "shadow_dom": ("email", "password"),
    "sso_mfa": ("email", "password"),
    "spa_json": ("email", "password"),
}

ENVIRONMENTS = tuple(_FIELD_MAP.keys())

_CONSENT_BANNER = (
    "<div id='onetrust-banner-sdk' style='position:fixed;left:0;right:0;bottom:0;"
    "background:#1b1b1b;color:#eee;padding:8px'>We value your privacy. "
    "<button id='onetrust-accept-btn-handler'>Accept All</button></div>"
)
_DECOY_SEARCH = (
    "<form role='search' action='/search' method='get'>"
    "<input type='search' name='q' placeholder='Search'>"
    "<button type='submit'>Go</button></form>"
)
_NAV = ("<nav><a href='/help'>Help</a> <a href='/privacy'>Privacy</a> "
        "<a href='/signup'>Create account</a></nav>")


def _noise(extra_hidden: str = "") -> str:
    return (_DECOY_SEARCH + _NAV + extra_hidden + _CONSENT_BANNER
            + "<script>document.getElementById('onetrust-accept-btn-handler')"
              ".addEventListener('click',function(){"
              "document.getElementById('onetrust-banner-sdk').style.display='none';});"
              "</script>")


def _okta_page() -> str:
    # Identifier-first: password section hidden until "Next" is clicked.
    return _page("Okta - Sign In", _noise()
        + "<div id='okta-sign-in'><h1>Sign In</h1>"
          "<form method='post' action='/env/okta/submit' id='form19'>"
          "<label for='okta-signin-username'>Username</label>"
          "<input id='okta-signin-username' name='identifier' type='text' autocomplete='username'>"
          "<div id='pw-section' style='display:none'>"
          "<label for='okta-signin-password'>Password</label>"
          "<input id='okta-signin-password' name='credentials.passcode' type='password'></div>"
          "<input type='hidden' name='stateToken' value='00xTOKEN'>"
          "<input id='okta-signin-submit' type='submit' value='Sign In' style='display:none'>"
          "<a id='okta-signin-next' role='button' href='#'>Next</a>"
          "</form></div>"
          "<script>document.getElementById('okta-signin-next').addEventListener('click',"
          "function(e){e.preventDefault();document.getElementById('pw-section').style.display='block';"
          "document.getElementById('okta-signin-submit').style.display='inline';this.style.display='none';});"
          "</script>")


def _auth0_page() -> str:
    return _page("Log in | Auth0", _noise()
        + "<main class='login'><div class='c-form'><h1>Welcome</h1>"
          "<form method='post' action='/env/auth0/submit' class='_form-login-id'>"
          "<div class='input-wrap'><label>Email address</label>"
          "<input inputmode='email' name='username' id='username' type='text' autocomplete='email'></div>"
          "<div class='input-wrap'><label>Password</label>"
          "<input name='password' id='password' type='password' autocomplete='current-password'></div>"
          "<input type='hidden' name='state' value='hKFo2SB'>"
          "<button type='submit' name='action' value='default' data-action-button-primary='true'>"
          "Continue</button>"
          "</form></div></main>")


def _keycloak_page() -> str:
    return _page("Sign in to your account", _noise()
        + "<div id='kc-form'><div id='kc-form-wrapper'>"
          "<form id='kc-form-login' method='post' action='/env/keycloak/submit'>"
          "<div class='form-group'><label for='username'>Username or email</label>"
          "<input tabindex='1' id='username' name='username' type='text' autofocus></div>"
          "<div class='form-group'><label for='password'>Password</label>"
          "<input tabindex='2' id='password' name='password' type='password'></div>"
          "<div class='form-group'><input tabindex='3' id='rememberMe' name='rememberMe' type='checkbox'>"
          "<label for='rememberMe'>Remember me</label></div>"
          "<input type='hidden' name='credentialId'>"
          "<input tabindex='4' id='kc-login' name='login' type='submit' value='Sign In'>"
          "</form></div></div>")


def _azure_page() -> str:
    # Email -> Next -> password -> "Stay signed in?" (KMSI) consent -> Yes.
    return _page("Sign in to your account", _noise()
        + "<div id='lightbox'><form name='f1' method='post' action='/env/azure_ad/submit'>"
          "<div id='loginHeader'>Sign in</div>"
          "<div id='email-view'>"
          "<input type='email' name='loginfmt' id='i0116' placeholder='Email, phone, or Skype'>"
          "<input type='submit' id='idSIButton9' value='Next'></div>"
          "<div id='pw-view' style='display:none'>"
          "<input type='password' name='passwd' id='i0118' placeholder='Password'>"
          "<input type='submit' id='idSubmit_ProofUp' value='Sign in'></div>"
          "<div id='kmsi-view' style='display:none'>"
          "<div>Stay signed in?</div>"
          "<input type='submit' id='idSIButton9_kmsi' name='DontShowAgain' value='Yes'></div>"
          "</form></div>"
          "<script>"
          "var f=document.forms['f1'];"
          "document.getElementById('idSIButton9').addEventListener('click',function(e){"
          "e.preventDefault();document.getElementById('email-view').style.display='none';"
          "document.getElementById('pw-view').style.display='block';});"
          "document.getElementById('idSubmit_ProofUp').addEventListener('click',function(e){"
          "e.preventDefault();document.getElementById('pw-view').style.display='none';"
          "document.getElementById('kmsi-view').style.display='block';});"
          "</script>")


def _wordpress_page() -> str:
    return _page("Log In ‹ Blog — WordPress", _noise()
        + "<div id='login'><h1><a href='/'>Blog</a></h1>"
          "<form name='loginform' id='loginform' method='post' action='/env/wordpress/submit'>"
          "<p><label for='user_login'>Username or Email Address</label>"
          "<input type='text' name='log' id='user_login' autocomplete='username'></p>"
          "<p><label for='user_pass'>Password</label>"
          "<input type='password' name='pwd' id='user_pass' autocomplete='current-password'></p>"
          "<p class='forgetmenot'><input name='rememberme' type='checkbox' id='rememberme' value='forever'>"
          "<label for='rememberme'>Remember Me</label></p>"
          "<input type='hidden' name='redirect_to' value='/dashboard'>"
          "<p class='submit'><input type='submit' name='wp-submit' id='wp-submit' value='Log In'></p>"
          "</form></div>")


def _django_page() -> str:
    return _page("Log in | Django site admin", _noise()
        + "<div id='container'><div id='header'><h1>Django administration</h1></div>"
          "<div id='content'><form action='/env/django/submit' method='post' id='login-form'>"
          "<input type='hidden' name='csrfmiddlewaretoken' value='abc123DEF'>"
          "<div class='form-row'><label for='id_username'>Username:</label>"
          "<input type='text' name='username' autofocus required id='id_username'></div>"
          "<div class='form-row'><label for='id_password'>Password:</label>"
          "<input type='password' name='password' required id='id_password'></div>"
          "<input type='hidden' name='next' value='/dashboard'>"
          "<div class='submit-row'><input type='submit' value='Log in'></div>"
          "</form></div></div>")


def _adfs_page() -> str:
    # ADFS form sign-in: #userNameInput (name=UserName), #passwordInput (name=Password),
    # submit is a <span id=submitButton> (role=button).
    return _page("Sign In", _noise()
        + "<div id='loginArea'><form method='post' id='loginForm' action='/env/adfs/submit'>"
          "<div id='userNameArea'><input id='userNameInput' name='UserName' type='email' "
          "placeholder='someone@example.com'></div>"
          "<div id='passwordArea'><input id='passwordInput' name='Password' type='password' "
          "placeholder='Password'></div>"
          "<span id='submitButton' role='button' tabindex='0' onclick='document.getElementById(\"loginForm\").submit()'>"
          "Sign in</span>"
          "</form></div>")


def _intl_ptbr_page() -> str:
    # Non-English (Brazilian Portuguese) labels and field names.
    return _page("Entrar", _noise()
        + "<div class='login-box'><h1>Acesse sua conta</h1>"
          "<form method='post' action='/env/intl_ptbr/submit'>"
          "<label for='usuario'>Usuário ou e-mail</label>"
          "<input id='usuario' name='usuario' type='text'>"
          "<label for='senha'>Senha</label>"
          "<input id='senha' name='senha' type='password'>"
          "<button type='submit'>Entrar</button>"
          "</form></div>")


def _shadow_dom_page() -> str:
    # Login form rendered inside an OPEN shadow root (a web component). The page
    # snapshot (document.querySelectorAll) does NOT pierce shadow DOM, but
    # Playwright locators DO - so the deterministic engine can still drive it.
    return _page("Shadow Login", _noise()
        + "<login-widget></login-widget>"
          "<script>"
          "class LoginWidget extends HTMLElement{connectedCallback(){"
          "const r=this.attachShadow({mode:'open'});"
          "r.innerHTML=\"<h1>Sign in</h1>"
          "<form method='post' action='/env/shadow_dom/submit'>"
          "<input name='email' type='email' placeholder='Email'>"
          "<input name='password' type='password' placeholder='Password'>"
          "<button type='submit'>Sign In</button></form>\";}}"
          "customElements.define('login-widget',LoginWidget);"
          "</script>")


def _sso_mfa_page() -> str:
    # Combo: standard email+password, then an OTP challenge (MFA wall).
    return _page("Single Sign-On", _noise()
        + "<div class='sso'><h1>Company SSO</h1>"
          "<form method='post' action='/env/sso_mfa/submit'>"
          "<input name='email' type='email' placeholder='Email'>"
          "<input name='password' type='password' placeholder='Password'>"
          "<button type='submit'>Sign In</button>"
          "</form></div>")


_SSO_MFA_OTP = _page("Two-step verification",
    "<h1>Enter the code we sent you</h1>"
    "<form method='post' action='/env/sso_mfa/verify'>"
    "<input name='code' type='text' inputmode='numeric' maxlength='6' placeholder='6-digit code'>"
    "<button type='submit'>Verify</button></form>")


def _spa_json_page() -> str:
    # SPA whose login form is in a CLOSED shadow root — Playwright locators and the
    # deterministic form-fill CANNOT pierce it ("no email field") — and which authenticates
    # via a JSON POST to /api/auth/login. Mirrors the SvelteKit shape: only the
    # DOM-independent spa_api strategy can solve it.
    return _page("SPA Login", _noise()
        + "<h1>Sign In</h1><p>Please sign in with your email address below:</p>"
          "<spa-login></spa-login>"
          "<script>"
          "class SpaLogin extends HTMLElement{connectedCallback(){"
          "const r=this.attachShadow({mode:'closed'});"
          "r.innerHTML=\"<form><input name='email' type='email' placeholder='Email'>"
          "<input name='password' type='password' placeholder='Password'>"
          "<button type='submit'>Continue</button></form>\";}}"
          "customElements.define('spa-login',SpaLogin);"
          "</script>")


_PAGE_BUILDERS = {
    "spa_json": _spa_json_page,
    "okta": _okta_page,
    "auth0": _auth0_page,
    "keycloak": _keycloak_page,
    "azure_ad": _azure_page,
    "wordpress": _wordpress_page,
    "django": _django_page,
    "adfs": _adfs_page,
    "intl_ptbr": _intl_ptbr_page,
    "shadow_dom": _shadow_dom_page,
    "sso_mfa": _sso_mfa_page,
}


class _EnvHandler(_Handler):
    """Serves /env/<name>/login and /env/<name>/submit plus /dashboard, reusing the
    base handler's HTML/redirect helpers."""

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/dashboard":
            self._send_html(_dashboard_page())
            return
        if path == "/env/sso_mfa/otp":
            self._send_html(_SSO_MFA_OTP)
            return
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "env" and parts[2] == "login":
            builder = _PAGE_BUILDERS.get(parts[1])
            if builder:
                self._send_html(builder())
                return
        self._send_html(_page("Not found", "<h1>404</h1>"), status=404)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        server: "EnvFixtureServer" = self.server  # type: ignore[assignment]
        # SPA JSON-API login endpoint (the spa_json env): a JSON POST, authenticated by body
        # fields, returning {redirectTo} + a session cookie — the shape the spa_api strategy
        # drives. Handle BEFORE _read_form() so the JSON body is not consumed as a form.
        if path == "/api/auth/login":
            import json as _json
            try:
                length = int(self.headers.get("content-length", 0) or 0)
                data = _json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                data = {}
            server.posts.append((path, data))
            if data.get("email") == USERNAME and data.get("password") == PASSWORD:
                body = _json.dumps({"redirectTo": "/dashboard", "redirectReport": None}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"{SESSION_COOKIE}={SESSION_VALUE}; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                body = _json.dumps({"error": "invalid credentials"}).encode()
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            return
        form = self._read_form()
        server.posts.append((path, form))
        # sso_mfa combo: correct credentials lead to an OTP wall, not a session.
        if path == "/env/sso_mfa/submit":
            uf, pf = _FIELD_MAP["sso_mfa"]
            if form.get(uf) == USERNAME and form.get(pf) == PASSWORD:
                self.send_response(302)
                self.send_header("Location", "/env/sso_mfa/otp")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send_html(_page("Denied", "<h1>Invalid credentials</h1>"), status=401)
            return
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "env" and parts[2] == "submit":
            env = parts[1]
            mapping = _FIELD_MAP.get(env)
            if mapping:
                user_field, pass_field = mapping
                if form.get(user_field) == USERNAME and form.get(pass_field) == PASSWORD:
                    self.send_response(302)
                    self.send_header("Location", "/dashboard")
                    self.send_header("Set-Cookie", f"{SESSION_COOKIE}={SESSION_VALUE}; Path=/")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._send_html(_page("Denied", "<h1>Invalid credentials</h1>"), status=401)
                return
        self._send_html(_page("Not found", "<h1>404</h1>"), status=404)


class EnvFixtureServer(HTTPServer):
    def __init__(self, address: Tuple[str, int]) -> None:
        super().__init__(address, _EnvHandler)
        self.posts: list[Tuple[str, Dict[str, str]]] = []


@contextlib.contextmanager
def env_fixture() -> Iterator["EnvFixtureServer"]:
    """Start the high-fidelity environment server on 127.0.0.1."""
    server = EnvFixtureServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    setattr(server, "base_url", f"http://127.0.0.1:{server.server_address[1]}")
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def env_login_url(base_url: str, env: str) -> str:
    return f"{base_url}/env/{env}/login"
