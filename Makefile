.PHONY: install setup sso sso-configure proxy validate test test-fast test-integration evals check lint secrets-scan help \
        desktop desktop-install desktop-dist desktop-dist-mac desktop-dist-win desktop-dist-linux \
        desktop-test bump-version

# AWS_PROFILE can be overridden: make sso AWS_PROFILE=my-profile
# If not set, reads from .env (AWS_PROFILE=...) or falls back to the default chain.
AWS_PROFILE ?= $(shell grep -E '^AWS_PROFILE=' .env 2>/dev/null | cut -d= -f2)
export AWS_PROFILE

# ---- Setup ----------------------------------------------------------------

install:
	@echo "[1/5] Installing Python dependencies..."
	uv sync
	@echo "[2/5] Installing Playwright Chromium..."
	uv run playwright install chromium
	@echo "[3/5] Checking .env..."
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "  Created .env from .env.example — edit it to add your AWS credentials"; \
	else \
		echo "  .env already exists"; \
	fi
	@echo "[4/5] Verifying key imports..."
	uv run python -c "import playwright, boto3, fastapi, dns; print('  All imports OK')"
	@echo "[5/5] Installing git secret-scan hooks (pre-commit + pre-push)..."
	uv run pre-commit install --install-hooks
	uv run pre-commit install --hook-type pre-push

setup: install
	@echo ""
	@echo "Setup complete."
	@echo ""
	@echo "Next steps:"
	@echo "  1. Edit .env — set AWS_PROFILE to your SSO profile name"
	@echo "     (or set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY for static creds)"
	@echo "  2. First time using SSO? Run 'make sso-configure' to set up the profile"
	@echo "  3. Run 'make sso' to authenticate (required each session)"
	@echo "  4. Run 'make proxy' to start the proxy + dashboard"
	@echo "  5. Open http://127.0.0.1:8088 in your browser"
	@echo "  6. Install the CA cert: download from http://127.0.0.1:8088/ca.crt"
	@echo "     then add it to your browser/OS trust store"

sso-configure:
	@echo "Configuring AWS SSO profile..."
	@echo "You will be prompted for: SSO start URL, SSO region, account ID, role name."
	@echo "When asked for profile name, use the same value as AWS_PROFILE in your .env"
	aws configure sso

sso:
	@if [ -z "$(AWS_PROFILE)" ]; then \
		echo "ERROR: AWS_PROFILE is not set."; \
		echo "Set it in .env (AWS_PROFILE=your-profile) or run: make sso AWS_PROFILE=your-profile"; \
		echo "First time? Run 'make sso-configure' to create the profile."; \
		exit 1; \
	fi
	aws sso login --profile $(AWS_PROFILE)

# ---- Proxy ----------------------------------------------------------------

proxy:
	uv run dast-ai --debug proxy \
		$(if $(PROXY_PORT),--proxy-port $(PROXY_PORT)) \
		$(if $(DASHBOARD_PORT),--dashboard-port $(DASHBOARD_PORT)) \
		$(if $(AUTH_URL),--auth-url $(AUTH_URL)) \
		$(if $(USERNAME),--username $(USERNAME)) \
		$(if $(PASSWORD),--password $(PASSWORD))

# ---- Validate report against live target ----------------------------------
# Auth options (pick one):
#   COOKIE="name=value"                       cookie from browser DevTools
#   BROWSE=1                                  open browser for manual login
#   AUTH_URL=... USERNAME=... PASSWORD=...    headless login with credentials
#
# Source code context (optional — improves agent accuracy):
#   SOURCE=/path/to/project                   local path
#   SOURCE=https://gitlab.com/org/repo        GitLab URL
#   GITLAB_TOKEN=glpat-...                    for private repos
#
# Examples:
#   make validate REPORT=report.md TARGET=https://app.example.com BROWSE=1
#   make validate REPORT=report.md TARGET=https://app.example.com COOKIE=".AspNetCore.Cookies=abc"
#   make validate REPORT=report.md TARGET=https://app.example.com AUTH_URL=https://app/login USERNAME=u PASSWORD=p
#   make validate REPORT=report.md TARGET=https://app.example.com BROWSE=1 SOURCE=/path/to/project
#   make validate REPORT=report.md TARGET=https://app.example.com BROWSE=1 SOURCE=https://gitlab.com/org/repo GITLAB_TOKEN=glpat-...
#   make validate REPORT=report.md TARGET=https://app.example.com COOKIE="..." ONLY="idor nosql" SOURCE=/path/to/project

validate:
	@if [ -z "$(REPORT)" ]; then echo "ERROR: REPORT is required. Usage: make validate REPORT=path/to/report.md TARGET=https://..."; exit 1; fi
	@if [ -z "$(TARGET)" ]; then echo "ERROR: TARGET is required. Usage: make validate REPORT=path/to/report.md TARGET=https://..."; exit 1; fi
	uv run python scripts/validate_report.py \
		--report "$(REPORT)" \
		--target "$(TARGET)" \
		$(if $(COOKIE),--cookie "$(COOKIE)") \
		$(if $(BROWSE),--browse) \
		$(if $(AUTH_URL),--auth-url "$(AUTH_URL)") \
		$(if $(USERNAME),--username "$(USERNAME)") \
		$(if $(PASSWORD),--password "$(PASSWORD)") \
		$(if $(ONLY),--only $(ONLY)) \
		$(if $(OUTPUT),--output "$(OUTPUT)") \
		$(if $(CONFIDENCE),--confidence $(CONFIDENCE)) \
		$(if $(SOURCE),--source "$(SOURCE)") \
		$(if $(GITLAB_TOKEN),--gitlab-token "$(GITLAB_TOKEN)") \
		$(if $(LOGIN_TIMEOUT),--login-timeout $(LOGIN_TIMEOUT))

# ---- Desktop (Electron launcher) ------------------------------------------
# Native desktop window for the proxy + dashboard (Burp-style). The launcher
# only spawns `dast-ai proxy` and renders the dashboard — no scan logic lives
# in Electron. See desktop/README.md.
#
# Requires Node.js + npm. First run 'make desktop-install', then 'make desktop'.
#
# Port overrides pass through to the backend:
#   make desktop PROXY_PORT=9090 DASHBOARD_PORT=9099

DESKTOP_DIR := desktop

desktop-install:
	@command -v npm >/dev/null 2>&1 || { \
		echo "ERROR: npm not found. Install Node.js (https://nodejs.org) first."; exit 1; }
	@echo "Installing Electron desktop dependencies (~200MB, first run only)..."
	cd $(DESKTOP_DIR) && npm install
	@echo "Ensuring Electron binary is installed (handles blocked lifecycle scripts)..."
	cd $(DESKTOP_DIR) && npm run setup-electron

desktop:
	@command -v npm >/dev/null 2>&1 || { \
		echo "ERROR: npm not found. Install Node.js (https://nodejs.org) first."; exit 1; }
	@if [ ! -d "$(DESKTOP_DIR)/node_modules" ]; then \
		echo "Dependencies not installed. Run 'make desktop-install' first."; exit 1; fi
	@# Guarantee the Electron binary is present (idempotent — no-op if already good)
	cd $(DESKTOP_DIR) && npm run setup-electron
	cd $(DESKTOP_DIR) && \
		$(if $(PROXY_PORT),PROXY_PORT=$(PROXY_PORT)) \
		$(if $(DASHBOARD_PORT),DASHBOARD_PORT=$(DASHBOARD_PORT)) \
		npm start

desktop-test:
	@if [ ! -d "$(DESKTOP_DIR)/node_modules" ]; then \
		echo "Dependencies not installed. Run 'make desktop-install' first."; exit 1; fi
	cd $(DESKTOP_DIR) && npm test

# Package a distributable. desktop-dist builds an unpacked dir for the current
# OS; the per-OS targets build installers/portables. See desktop/README.md for
# the Phase 1 caveat (packages the launcher, not a self-contained backend).
desktop-dist:
	cd $(DESKTOP_DIR) && npm run dist

desktop-dist-mac:
	cd $(DESKTOP_DIR) && npm run dist:mac

desktop-dist-win:
	cd $(DESKTOP_DIR) && npm run dist:win

desktop-dist-linux:
	cd $(DESKTOP_DIR) && npm run dist:linux

# ---- Tests ----------------------------------------------------------------

test:
	uv run pytest tests/unit/ -v

test-fast:
	uv run pytest tests/unit/ -q

lint:
	@echo "Linting UI (JS syntax + duplicate declarations)..."
	node scripts/lint_ui.js
	@echo "Linting Python (ruff: dead code, unused imports/locals — see [tool.ruff] in pyproject.toml)..."
	uv run ruff check .
	@echo "Linting Python (imports)..."
	uv run python -c "from dast.proxy.runner import ProxyRunner; from dast.proxy.api.browser_routes import make_router; from dast.proxy.api.proxy_routes import make_router; print('  Python imports OK')"

test-integration:
	@echo "Running integration tests (proxy must already be running)..."
	uv run python scripts/test_integration.py

# ---- Secret scanning ------------------------------------------------------
# On-demand full-repo scan for secrets / internal data. Runs the same checks as
# the git hooks and CI. gitleaks and trufflehog must be installed
# (brew install gitleaks trufflehog).
secrets-scan:
	@echo "Running gitleaks (full history)..."
	gitleaks detect --config .gitleaks.toml --no-banner
	@echo "Running trufflehog (verified secrets)..."
	trufflehog git file://. --only-verified --fail --no-update --exclude-detectors=lob
	@echo "Running internal-data guard on tracked files..."
	git ls-files | xargs uv run python scripts/check_no_internal_data.py

# ---- LLM evals ------------------------------------------------------------
# Opt-in decision-quality harness for the planner + red-team validator. Calls
# the real Bedrock model (needs AWS creds, costs tokens) — not part of 'make test'.
# Optional: SUITE=planner|red_team  MIN_ACCURACY=0.9 (fail if below)
evals:
	uv run python -m tests.evals.run_evals \
		$(if $(SUITE),--suite $(SUITE)) \
		$(if $(MIN_ACCURACY),--min-accuracy $(MIN_ACCURACY))

check:
	@echo "Checking passive rule count..."
	uv run python -c "from dast.plugins.passive_scanner import _load_all_rules; print(len(_load_all_rules()), 'passive rules')"
	@echo "Checking payload counts..."
	uv run python -c "\
from dast.payloads.loader import _load; \
files = ['xss','sqli','ssrf','lfi','ssti','llm_injection','cmdi','xxe','jwt','nosql','prototype_pollution']; \
[print(f+':', sum(len(v) for v in _load(f+'.yaml').get('payloads',{}).values()), 'payloads') for f in files]"
	@echo "Checking DNS (dnspython)..."
	uv run python -c "import dns.resolver; print('dnspython OK')"

# ---- Versioning ------------------------------------------------------------
# The version is duplicated in pyproject.toml, desktop/package.json, CLAUDE.md,
# and docs/ARCHITECTURE.md — this bumps all 4 atomically instead of by hand.
# Usage: make bump-version VERSION=0.9.0
bump-version:
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make bump-version VERSION=x.y.z"; exit 1; fi
	uv run python scripts/bump_version.py $(VERSION)

# ---- Help -----------------------------------------------------------------

help:
	@echo "DAST-AI"
	@echo ""
	@echo "  make setup          Install deps, create .env, verify imports"
	@echo "  make sso-configure  Create AWS SSO profile (first time only)"
	@echo "  make sso            AWS SSO login"
	@echo "  make proxy          Start proxy + dashboard"
	@echo "  make desktop-install Install Electron deps (first run only, ~200MB)"
	@echo "  make desktop        Start the native desktop app (Burp-style window)"
	@echo "  make desktop-dist-mac/win/linux  Build a distributable app"
	@echo "  make desktop-test   Run the desktop launcher's e2e test (real Electron + backend)"
	@echo "  make validate       Validate a report against a live target (AI-driven, no proxy needed)"
	@echo "  make test       Run unit tests (verbose)"
	@echo "  make test-fast  Run unit tests (quiet)"
	@echo "  make evals      Run LLM decision-quality evals (opt-in, uses Bedrock/tokens)"
	@echo "  make lint       JS syntax + duplicate vars + Python import check"
	@echo "  make check      Verify rule/payload counts and imports"
	@echo "  make bump-version VERSION=x.y.z  Sync the version across pyproject.toml/package.json/docs"
	@echo ""
	@echo "Optional variables:"
	@echo "  PROXY_PORT=8080  DASHBOARD_PORT=8088"
	@echo "  AUTH_URL=https://app/login  USERNAME=...  PASSWORD=..."
	@echo "  make validate REPORT=report.md TARGET=https://app.example.com BROWSE=1"
	@echo "  make validate REPORT=report.md TARGET=https://... COOKIE=\"name=val\""
	@echo "  make validate REPORT=... TARGET=... BROWSE=1 SOURCE=/path/to/project"
	@echo "  make validate REPORT=... TARGET=... BROWSE=1 SOURCE=https://gitlab.com/org/repo GITLAB_TOKEN=glpat-..."
