# Frieren DAST-AI Desktop

A native desktop launcher for Frieren DAST-AI, so it runs as a standalone application
instead of requiring a terminal + separate browser.

## What this is (and is not)

The Electron process here is **only a launcher and a window**. It does not
contain any scan logic. On start it:

1. spawns the Python backend (`uv run dast-ai proxy`) as a child process,
2. waits until the dashboard port (`8088`) is accepting connections,
3. renders the existing dashboard in a native window (Chromium),
4. provides a tray icon and kills the backend cleanly on quit.

Every proxy / MITM / VulnAgent / AI-coordinator behaviour is identical to
running `uv run dast-ai proxy` in a terminal — same Chromium engine the
dashboard is already tested against, so WebSocket streaming and rendering
behave exactly as they do today.

## Phase 1 — dev launcher (this folder)

Assumes `uv` is installed on the machine and the repo is checked out. Zero
Python bundling. Use it to validate the desktop UX.

```bash
cd desktop
npm install
npm start
```

The backend inherits your shell environment, so AWS credentials
(`AWS_PROFILE` / `AWS_ACCESS_KEY_ID` etc.) must be set the same way you set
them for `uv run dast-ai proxy`.

### Port overrides

```bash
PROXY_PORT=9090 DASHBOARD_PORT=9099 npm start
```

### Electron binary install (blocked lifecycle scripts)

If npm is configured to block package lifecycle scripts (npm's `allow-scripts`
feature), Electron's `postinstall` never runs and no binary is downloaded — you
get `Error: Electron failed to install correctly` on `npm start`. On macOS the
bundled `extract-zip` can also fail silently on the `.app` bundle's symlinks,
leaving a half-extracted `dist/` with an empty `path.txt`.

`npm run setup-electron` (in `scripts/setup-electron.js`) fixes both: it runs
Electron's official installer, verifies the extraction completed, and falls back
to the system `unzip` if not. It is idempotent and runs automatically as part of
`make desktop-install` and `make desktop`, so normally you never call it by hand.

To fix a broken install manually:

```bash
cd desktop && npm run setup-electron
```

## Testing

`npm test` (or `make desktop-test` from the repo root) runs an end-to-end test
against the real Electron binary and the real Python backend: it launches the
app on non-default ports, waits for it to spawn the backend and load the
dashboard into the window, and asserts the window title and that no console
error occurred. Uses Playwright's `_electron` API — installed as a devDependency
alongside `electron`/`electron-builder`.

```bash
npm test
```

## Building a distributable

`electron-builder` produces platform bundles. **Note:** the Phase 1 build
still assumes `uv` + the checked-out repo are present at runtime — it packages
the *launcher*, not the Python backend. A fully self-contained binary (no `uv`,
no repo) is Phase 2 and requires bundling Python + mitmproxy + Playwright's
Chromium, which is a separate effort.

```bash
npm run dist:mac      # macOS .dmg + .zip
npm run dist:win      # Windows portable .exe (no install — matches the "run without installing" ask)
npm run dist:linux    # Linux AppImage (single-file, no install)
```

Portable `.exe` and `.AppImage` are the "executable without installing"
targets: a single file the user double-clicks.

## Phase 2 — self-contained binary (not yet done)

To ship a binary that needs neither `uv` nor the repo:

- bundle the Python runtime + deps with PyInstaller (watch out for
  mitmproxy's dynamic imports, boto3 data files, and Playwright's Chromium
  download — each needs explicit handling),
- point `main.js` at the bundled executable instead of `spawn("uv", ...)`,
- code-sign / notarize on macOS to avoid Gatekeeper warnings.
