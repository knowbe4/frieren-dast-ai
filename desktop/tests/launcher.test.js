// End-to-end test for the Electron desktop launcher (main.js).
//
// This launcher spawns the real Python backend (`uv run dast-ai proxy`) and
// renders the dashboard in a native BrowserWindow — it has no scan logic of
// its own, so the thing worth regression-testing is exactly the seam it owns:
// does it actually spawn the backend, wait for the port, and load the real
// dashboard into the window without crashing or hanging.
//
// Runs the real Electron binary (via Playwright's _electron) against the real
// backend (via `uv run dast-ai proxy`, unmocked) on non-default ports so it
// never collides with a dev instance. AWS/Bedrock calls made by the backend's
// own startup (AI status prefetch) are allowed to happen for real — this is
// an integration test of the launcher, not a unit test, and the backend
// already degrades gracefully when AI is unavailable.
//
// Requires `uv` on PATH and network-less operation is fine (backend degrades
// to AI-unavailable). Skips cleanly if the Electron binary isn't installed
// (e.g. a fresh checkout before `npm install` finished extracting it).

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const net = require("node:net");

const { _electron: electron } = require("playwright");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const MAIN_JS = path.join(__dirname, "..", "main.js");

const PROXY_PORT = 18080;
const DASHBOARD_PORT = 18088;

function electronBinaryAvailable() {
  try {
    // Resolving electron's own module gives us its executable path file.
    const electronPkgPath = require.resolve("electron");
    const pathTxt = path.join(path.dirname(electronPkgPath), "path.txt");
    return fs.existsSync(pathTxt) && fs.readFileSync(pathTxt, "utf8").trim().length > 0;
  } catch {
    return false;
  }
}

function isPortFree(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", () => resolve(false));
    server.once("listening", () => server.close(() => resolve(true)));
    server.listen(port, "127.0.0.1");
  });
}

const SKIP = !electronBinaryAvailable();

let electronApp = null;

test("desktop launcher spawns the real backend and loads the dashboard", { skip: SKIP }, async (t) => {
  if (SKIP) {
    t.skip("Electron binary not installed — run `npm install` in desktop/ first");
    return;
  }

  const proxyFree = await isPortFree(PROXY_PORT);
  const dashFree = await isPortFree(DASHBOARD_PORT);
  assert.ok(proxyFree, `port ${PROXY_PORT} must be free before this test runs`);
  assert.ok(dashFree, `port ${DASHBOARD_PORT} must be free before this test runs`);

  electronApp = await electron.launch({
    args: [MAIN_JS],
    cwd: path.dirname(MAIN_JS),
    env: {
      ...process.env,
      PROXY_PORT: String(PROXY_PORT),
      DASHBOARD_PORT: String(DASHBOARD_PORT),
    },
    timeout: 60_000,
  });

  const errors = [];
  electronApp.on("window", (window) => {
    window.on("pageerror", (exc) => errors.push(String(exc)));
    window.on("console", (msg) => {
      if (msg.type() === "error") errors.push(msg.text());
    });
  });

  // The launcher shows loading.html immediately, then swaps to the real
  // dashboard once the backend port is accepting connections (up to ~30s:
  // 100 retries * 300ms in main.js's waitForPort).
  const window = await electronApp.firstWindow({ timeout: 15_000 });

  await window.waitForFunction(
    () => typeof window !== "undefined" && document.title.length > 0,
    { timeout: 45_000 },
  ).catch(() => {});

  // Poll until the window has actually navigated to the dashboard URL (not
  // still on loading.html) — loadDashboard() only fires after the backend
  // port responds, so this is the real end-to-end signal.
  const dashboardUrl = `http://127.0.0.1:${DASHBOARD_PORT}/`;
  let loaded = false;
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    const currentWindow = electronApp.windows()[0];
    if (currentWindow && currentWindow.url() === dashboardUrl) {
      loaded = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 300));
  }

  assert.ok(loaded, `window never navigated to ${dashboardUrl} (backend may not have started)`);

  const activeWindow = electronApp.windows()[0];
  const title = await activeWindow.title();
  assert.equal(title, "Frieren DAST-AI");

  // The dashboard's own JS ran without throwing — same signal the UI e2e
  // test checks for the web build, now inside the actual desktop shell.
  assert.deepEqual(errors, []);
});

after(async () => {
  if (electronApp) {
    await electronApp.close().catch(() => {});
  }
});
