# Login-difficulty harness

Can Frieren log in the way an operator would: find the fields, fill them, submit,
and land authenticated, across login pages of escalating difficulty?

This harness serves a catalogue of local login pages (`tests/fixtures/login_pages/`)
and drives Frieren's login machinery against each tier, recording where it succeeds
and where it hits a wall.

## Engines under test

The cascade runs **deterministic-first, LLM-fallback** - the real operating model,
implemented in `dast.browser.login_cascade.adaptive_login`:

1. **Deterministic** - `dast.browser.agent_browser.AgentBrowser.login()` (fixed
   selector lists, two-step/SSO/MFA handling) and the copilot's bearer-token
   capture/injection (`dast.ai.copilot.session`). No model, no tokens. Runs in CI.
2. **LLM-driven fallback** - only when the deterministic engine cannot authenticate,
   the model drives the `browser_*` primitives (`snapshot -> reason -> fill/click/
   wait`) like a human. The decider is injectable: CI tests use a scripted decider
   (token-free, `test_login_difficulty_cascade.py`); the real model is exercised by
   the opt-in eval `tests/evals/login_adaptive_eval.py` (spends tokens).

MFA/OTP and CAPTCHA are NOT escalated to the LLM - they are human walls, reported
(not brute-forced).

### Exposure (MCP + API)

The capability is reachable three ways, from one implementation:

- **Agent / MCP tool**: `browser_login_adaptive` (`dast/tools/login_tools.py`) -
  auto-advertised over MCP.
- **HTTP API**: `POST /api/login/adaptive` (`dast/proxy/api/login_adaptive_routes.py`)
  with `{url, email, password, success_url_suffix?}`, hard scope-gated.
- **Direct**: `adaptive_login(browser, url, email, password, ...)`.

## Tiers

| Tier | Challenge | Deterministic | LLM fallback |
|------|-----------|---------------|--------------|
| T0 | trivial single-page form | pass | - |
| T1 | two-step: email -> Continue -> password | pass | - |
| T2 | non-standard identifiers (`j_username`/`pwd`, `<div role=button>`) | **pass** (engine improved) | - |
| T3 | consent banner + honeypot + placeholder-only labels | pass | - |
| T4 | credential fields inside an `<iframe>` | xfail (gap) | **cannot** (snapshot is main-frame only) |
| T5 | CAPTCHA signature | detected via `has_captcha`, clean bail | not escalated |
| T6 | SPA -> JWT in localStorage -> Bearer on `/api/me` | pass | - |
| T7 | short-lived JWT -> relies on 401 refresh | pass | - |
| T8 | hybrid cookie + CSRF + Bearer together | pass | - |
| T9 | SSO redirect to a second-origin IdP and back | pass | - |
| T10 | MFA / OTP challenge after password | mfa_bail (detected, no false success) | not escalated |
| T11 | OAuth-style "Authorize" consent button | xfail (stops on consent screen) | **solves it** |

T2 is now solved by the deterministic engine (see engine improvements below). The
remaining deterministic `xfail` tiers are genuine gaps, marked `strict` so they
flip to a failure the moment the engine learns to handle them. T11 is cleared by
the LLM fallback (verified against a real model in `login_adaptive_eval`). T4 is a
deeper limitation: the page snapshot only sees the main frame, so the LLM cannot
reach iframe fields - fixing it needs frame-aware primitives, not a smarter prompt.

> Snapshot note: running the real-model eval surfaced that the browser snapshot did
> not expose `[role=button]` controls (so the model could not click T2's
> `<div role=button>` submit). `agent_browser.py`'s snapshot was widened to include
> `input[type=button]` and any `[role=button]`, which is what lets the fallback
> clear T2.

## What each tier maps to in the code

- T0/T1/T3/T9/T10/T11 -> `AgentBrowser.login()` field discovery, two-step, SSO
  redirect detection, and MFA detection (`_MFA_INDICATORS`).
- T2/T4 -> the fixed `_EMAIL_SELECTORS` / `_SUBMIT_SELECTORS` / `_PASSWORD_SELECTORS`
  and main-frame-only querying.
- T5 -> `dast.profiles.flow.has_captcha`.
- T6/T7/T8 -> `CopilotSession._capture_bearer_tokens` + `_apply_session_auth`
  (host-family matching, JWT `exp` awareness, CSRF/Cookie/Bearer injection).

## Running

```bash
# deterministic bearer + captcha tiers (fast, no browser, runs in CI)
uv run pytest tests/unit/test_login_difficulty_bearer.py

# adaptive-login MCP tool + API route wiring (fast, no browser, runs in CI)
uv run pytest tests/unit/test_tools_registry.py -k adaptive_login
uv run pytest tests/unit/test_login_adaptive_routes.py

# deterministic browser tiers (needs Chromium; ~70s; skipped if unavailable)
uv run pytest tests/integration/test_login_difficulty_browser.py

# the cascade: deterministic-first, scripted LLM fallback (needs Chromium; token-free)
uv run pytest tests/integration/test_login_difficulty_cascade.py

# opt-in: the cascade with a REAL model (needs Chromium + AI provider; spends tokens)
uv run python -m tests.evals.login_adaptive_eval --tiers t2,t11,t4

# opt-in: real model against product-clone environments, N runs each (success rates)
uv run python -m tests.evals.login_env_eval --repeats 5
```

## Real-world environments (fidelity)

Beyond the isolated T0-T11 tiers, `environments.py` serves high-fidelity clones of
real products' login pages - matching their field names, ids, control structure and
multi-step flow, wrapped in realistic page noise (a OneTrust-style consent banner, a
decoy header search form, nav links, hidden CSRF/telemetry inputs):

| Env | Mirrors | Flow | Solved by (real-model eval, 5/5 each) |
|-----|---------|------|----------------------------------------|
| `okta` | Okta Sign-In Widget | identifier-first: username -> Next -> password | deterministic |
| `auth0` | Auth0 Universal Login | single page, "Continue" submit | deterministic |
| `keycloak` | Keycloak realm login | single page, `#kc-login` submit | deterministic |
| `azure_ad` | Microsoft/Azure AD | email -> Next -> password -> "Stay signed in?" (Yes) | **LLM** (consent) |
| `wordpress` | wp-login.php | single page, `name=log` / `name=pwd`, remember-me | deterministic |
| `django` | Django admin | single page, `#id_username` / `#id_password`, CSRF hidden | deterministic |
| `adfs` | ADFS form sign-in | single page, `name=UserName` / `name=Password`, `<span role=button>` submit | deterministic |
| `intl_ptbr` | Non-English (pt-BR) | single page, `name=usuario` / `name=senha`, "Entrar" | **LLM** (non-English) |
| `shadow_dom` | Web-component login | form inside an open shadow root | deterministic (pierced) |
| `sso_mfa` | SSO + MFA combo | email+password -> OTP challenge | deterministic (MFA bail, no login) |

Last real-model run (`login_env_eval.py --repeats 5`): **50/50 (100%)** across all 10
environments. The cascade spent LLM tokens on only the two genuinely adaptive cases
(Azure consent, Portuguese field names); the deterministic engine handled the other
eight (seven logins + the MFA bail) for free. The eval reports the success RATE (the
model is non-deterministic, so one pass is not proof).

### Engine improvements this surfaced (in `agent_browser.py`)

Running real clones exposed concrete gaps that clean synthetic forms hid - each was
fixed in the deterministic engine so it clears the common cases without the LLM:
- **username selectors** broadened to real field names (`identifier`, `loginfmt`,
  `log`, `UserName`, `user`, `j_username`, `autocomplete=username`, case-insensitive).
- **scored submit control** (`_PICK_SUBMIT_JS`): prefers the sign-in button in the
  password/email form, penalises Search/Go/Cancel, reaches `<div/span role=button>`
  controls, and **pierces open shadow roots** - so a header search box or a web
  component no longer derails it.
- **single-page early fill**: the password is filled before the first submit (forms
  without HTML5 `required` used to post an empty password), then the result is
  classified one-shot (logged in / MFA wall / not authenticated).
- **snapshot** (`_SNAPSHOT_JS`) now exposes `[role=button]` controls and each form's
  `id`/`name`, so the LLM fallback can target the login form on a noisy page. The
  decider prompt also tells the model to pick the sign-in control (never Search/Go).

Remaining honest limitation: the `_SNAPSHOT_JS` used by the LLM does not pierce
shadow DOM or iframes, so an LLM-only path cannot see those fields. The deterministic
Playwright locators do pierce shadow DOM (hence `shadow_dom` is solved), but iframe
fields (tier T4) remain unreachable by either path.

The fixture server binds to `127.0.0.1:0` on a daemon thread (plus a second origin
for the T9 IdP). Nothing leaves the loopback interface and nothing enters the proxy
scope. The JWT is a test-only HS256 token so `/api/me` can verify it and the bearer
capture can read its `exp`.
