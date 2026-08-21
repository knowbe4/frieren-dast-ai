// Frieren DAST-AI desktop launcher (Phase 1 — dev launcher).
//
// This Electron process does NOT contain any scan logic. It only:
//   1. spawns the Python backend (`uv run dast-ai proxy`) as a child process
//   2. waits until the dashboard port is accepting connections
//   3. renders the dashboard in a native BrowserWindow
//   4. provides a tray icon and clean shutdown (kills the backend on quit)
//
// All proxy/MITM/scan/AI work happens in the Python backend, unchanged.

const { app, BrowserWindow, Tray, Menu, shell, dialog, nativeImage } = require("electron");
const { spawn } = require("child_process");
const net = require("net");
const path = require("path");

// Set the app name before anything else reads it. In dev (`npm start`) the
// process runs inside Electron.app, so without this the macOS application menu
// and the "About"/"Quit" items would read "Electron" instead of the product
// name.
app.setName("Frieren DAST-AI");

// App icon — used for the window, the macOS dock, and the tray. Bundled via the
// electron-builder "files" list so it resolves both in dev and when packaged.
const ICON_PATH = path.join(__dirname, "build", "icon.png");
const appIcon = nativeImage.createFromPath(ICON_PATH);

// ---------------------------------------------------------------------------
// Config — overridable via environment
// ---------------------------------------------------------------------------
// Preferred ports (env override or defaults). These are only a starting point:
// resolvePorts() picks a free port if the preferred one is already taken, so a
// stale backend left over from a previous run (or a second project on the same
// machine) can never make us bind — or worse, silently attach to — a port we
// don't own. Mutable because the resolved values may differ from the preferred.
let DASHBOARD_PORT = parseInt(process.env.DASHBOARD_PORT || "8088", 10);
let PROXY_PORT = parseInt(process.env.PROXY_PORT || "8080", 10);
let DASHBOARD_URL = `http://127.0.0.1:${DASHBOARD_PORT}`;
// The backend lives one level up from desktop/. Run it via uv so the launcher
// needs no bundled Python (Phase 1 assumes uv is installed on the machine).
const REPO_ROOT = path.resolve(__dirname, "..");

let backendProcess = null;
let mainWindow = null;
let tray = null;
let backendReady = false;
let isQuitting = false;

// ---------------------------------------------------------------------------
// Port resolution — never bind (or attach to) a port we don't own
// ---------------------------------------------------------------------------
// True only if we can bind the port ourselves right now. A port held by a
// stale backend answers connections, so a plain "can I connect?" probe would
// wrongly report it usable and we'd attach to that old process — exactly the
// bug where the desktop showed a previous run's session.
function isPortFree(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", () => resolve(false));
    server.once("listening", () => server.close(() => resolve(true)));
    server.listen(port, "127.0.0.1");
  });
}

// Ask the OS for a free ephemeral port (bind to 0, read the assigned port).
function getEphemeralPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

// Return the preferred port if free, otherwise a free ephemeral one. `exclude`
// guards against handing out the same port twice when both fall back.
async function resolvePort(preferred, label, exclude = null) {
  if (preferred !== exclude && (await isPortFree(preferred))) return preferred;
  let port = await getEphemeralPort();
  while (port === exclude) port = await getEphemeralPort();
  console.log(
    `[frieren-desktop] ${label} port ${preferred} is busy — using free port ${port} instead.`
  );
  return port;
}

// Resolve both ports before anything reads them, and rebuild DASHBOARD_URL.
async function resolvePorts() {
  PROXY_PORT = await resolvePort(PROXY_PORT, "proxy");
  DASHBOARD_PORT = await resolvePort(DASHBOARD_PORT, "dashboard", PROXY_PORT);
  DASHBOARD_URL = `http://127.0.0.1:${DASHBOARD_PORT}`;
}

// ---------------------------------------------------------------------------
// Backend lifecycle
// ---------------------------------------------------------------------------
function startBackend() {
  const args = [
    "run", "dast-ai", "proxy",
    "--proxy-port", String(PROXY_PORT),
    "--dashboard-port", String(DASHBOARD_PORT),
  ];
  backendProcess = spawn("uv", args, {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      // Tell the backend not to open a system-browser tab — we render it here.
      DAST_DESKTOP: "1",
    },
    // Inherit stdio so backend logs surface in the launcher terminal during dev.
    stdio: ["ignore", "inherit", "inherit"],
    // `uv run` forks the actual Python proxy as a grandchild. On POSIX, put the
    // whole thing in its own process group (detached) so stopBackend() can
    // signal the ENTIRE group — signalling just `uv` orphans the proxy, which
    // keeps holding the proxy/dashboard ports (the "address already in use"
    // we saw). On Windows there are no process groups; taskkill /T handles it.
    detached: process.platform !== "win32",
  });

  backendProcess.on("error", (err) => {
    dialog.showErrorBox(
      "Failed to start Frieren DAST-AI backend",
      `Could not launch 'uv run dast-ai proxy'.\n\n` +
        `Make sure 'uv' is installed and on your PATH.\n\nError: ${err.message}`
    );
    app.quit();
  });

  backendProcess.on("exit", (code, signal) => {
    backendProcess = null;
    // If the backend dies unexpectedly (not during our own quit), surface it.
    if (!isQuitting && code !== 0 && code !== null) {
      dialog.showErrorBox(
        "Frieren DAST-AI backend stopped",
        `The backend process exited unexpectedly (code ${code}, signal ${signal}).`
      );
      app.quit();
    }
  });
}

function stopBackend() {
  if (!backendProcess) return;
  const proc = backendProcess;
  backendProcess = null;
  const pid = proc.pid;
  if (process.platform === "win32") {
    // No POSIX process groups on Windows — kill the whole tree by PID.
    spawn("taskkill", ["/pid", String(pid), "/T", "/F"]);
    return;
  }
  // Graceful path: SIGINT the DIRECT child (`uv`) only, not the whole group.
  // `uv run` forwards the signal to the Python proxy, which then shuts itself
  // down in order — including closing its own Playwright driver cleanly. If we
  // instead SIGINT the whole group, the driver dies at the same instant Python
  // tries to close it, producing a "Connection closed while reading from the
  // driver" traceback. So graceful stays targeted; the group is only for the
  // forced backstop below.
  try {
    proc.kill("SIGINT");
  } catch {
    /* already exited */
  }
  // Backstop: if the backend ignores SIGINT (wedged / signal not forwarded),
  // SIGKILL the ENTIRE process group after a short grace period so no orphan
  // can keep the proxy/dashboard ports pinned. SIGKILL can't be caught, so it
  // never produces a shutdown traceback.
  setTimeout(() => {
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      /* already exited — nothing to do */
    }
  }, 4000).unref();
}

// ---------------------------------------------------------------------------
// Wait for the dashboard port to accept connections
// ---------------------------------------------------------------------------
function waitForPort(port, { retries = 100, intervalMs = 300 } = {}) {
  return new Promise((resolve, reject) => {
    let attempts = 0;
    const tryConnect = () => {
      const socket = net.connect(port, "127.0.0.1");
      socket.once("connect", () => {
        socket.destroy();
        resolve();
      });
      socket.once("error", () => {
        socket.destroy();
        attempts += 1;
        if (attempts >= retries) {
          reject(new Error(`Dashboard port ${port} not ready after ${retries} attempts`));
        } else {
          setTimeout(tryConnect, intervalMs);
        }
      });
    };
    tryConnect();
  });
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    title: "Frieren DAST-AI",
    icon: appIcon,
    backgroundColor: "#1a1a1a",
    show: false,
    webPreferences: {
      // The dashboard is our own trusted app; no Node integration needed in it.
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  // Show a loading screen while the backend boots.
  mainWindow.loadFile(path.join(__dirname, "loading.html"));
  mainWindow.once("ready-to-show", () => mainWindow.show());

  // Keyboard reload (F5 and Cmd/Ctrl+R). Works without an application menu and
  // in packaged builds — before-input-event fires for every key the page sees.
  mainWindow.webContents.on("before-input-event", (event, input) => {
    if (input.type !== "keyDown") return;
    const isCmdOrCtrlR = (input.meta || input.control) && input.key.toLowerCase() === "r";
    if (input.key === "F5" || isCmdOrCtrlR) {
      event.preventDefault();
      reloadDashboard();
    }
  });

  // Open external links (docs, target apps) in the system browser, not in-app.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (!url.startsWith(DASHBOARD_URL)) {
      shell.openExternal(url);
      return { action: "deny" };
    }
    return { action: "allow" };
  });

  mainWindow.on("close", (event) => {
    // A programmatic quit (tray "Quit", app.quit(), or the e2e harness) has
    // already set isQuitting — let it through so shutdown can proceed.
    if (isQuitting) return;
    // A user-initiated window close (the X button) must confirm first, then
    // fully quit — which stops the backend and frees the proxy/dashboard
    // ports. We do NOT hide to the tray: the user expects X to close the app.
    event.preventDefault();
    const choice = dialog.showMessageBoxSync(mainWindow, {
      type: "question",
      buttons: ["Cancel", "Quit"],
      defaultId: 1,
      cancelId: 0,
      title: "Quit Frieren DAST-AI",
      message: "Quit Frieren DAST-AI?",
      detail: "This stops the proxy and the dashboard. Any unsaved session data will be lost.",
    });
    if (choice === 1) {
      isQuitting = true;
      app.quit();
    }
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

function loadDashboard() {
  if (mainWindow) {
    mainWindow.loadURL(DASHBOARD_URL);
    backendReady = true;
    rebuildTrayMenu();
  }
}

// Refresh the dashboard in the native window — the desktop equivalent of hitting
// F5 / Cmd+R in a browser. Needed because the launcher sets no application menu,
// so otherwise there is no way to re-fetch the page after, e.g., switching the
// AI provider (the connection badge re-polls on its own, but a manual reload is
// still the expected escape hatch). A plain reload re-fetches the current page;
// if we somehow left the loading screen up, load the dashboard URL instead.
function reloadDashboard() {
  if (!mainWindow || !backendReady) return;
  const currentUrl = mainWindow.webContents.getURL();
  if (currentUrl.startsWith(DASHBOARD_URL)) {
    mainWindow.webContents.reload();
  } else {
    mainWindow.loadURL(DASHBOARD_URL);
  }
}

// ---------------------------------------------------------------------------
// Tray
// ---------------------------------------------------------------------------
function createTray() {
  // Downscale the app icon to a tray-appropriate size; fall back to an empty
  // image if the icon file is somehow missing so the tray still initialises.
  const trayIcon = appIcon.isEmpty()
    ? nativeImage.createEmpty()
    : appIcon.resize({ width: 22, height: 22 });
  tray = new Tray(trayIcon);
  tray.setToolTip("Frieren DAST-AI");
  rebuildTrayMenu();
}

function rebuildTrayMenu() {
  if (!tray) return;
  const menu = Menu.buildFromTemplate([
    {
      label: backendReady ? "Open Dashboard" : "Starting backend...",
      enabled: backendReady,
      click: () => {
        if (!mainWindow) createWindow();
        loadDashboard();
        mainWindow.show();
        mainWindow.focus();
      },
    },
    {
      label: "Open in system browser",
      enabled: backendReady,
      click: () => shell.openExternal(DASHBOARD_URL),
    },
    {
      label: "Reload dashboard",
      enabled: backendReady,
      accelerator: "CmdOrCtrl+R",
      click: () => reloadDashboard(),
    },
    { type: "separator" },
    {
      label: `Proxy: 127.0.0.1:${PROXY_PORT}`,
      enabled: false,
    },
    {
      label: `Dashboard: 127.0.0.1:${DASHBOARD_PORT}`,
      enabled: false,
    },
    { type: "separator" },
    {
      label: "Quit Frieren DAST-AI",
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ]);
  tray.setContextMenu(menu);
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------
app.whenReady().then(async () => {
  // macOS dock icon (packaged builds use the .icns; this covers `npm start` dev runs).
  if (process.platform === "darwin" && app.dock && !appIcon.isEmpty()) {
    app.dock.setIcon(appIcon);
  }

  // Resolve free ports BEFORE createTray/createWindow/startBackend, all of
  // which read PROXY_PORT/DASHBOARD_PORT/DASHBOARD_URL.
  await resolvePorts();

  createTray();
  createWindow();
  startBackend();

  try {
    await waitForPort(DASHBOARD_PORT);
    loadDashboard();
  } catch (err) {
    dialog.showErrorBox(
      "Frieren DAST-AI failed to start",
      `The dashboard did not come up in time.\n\n${err.message}`
    );
    app.quit();
  }

  app.on("activate", () => {
    // macOS dock click — recreate the window if it was closed.
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
      if (backendReady) loadDashboard();
    } else if (mainWindow) {
      mainWindow.show();
    }
  });
});

// Keep the app alive when all windows are closed (tray-resident), except we
// still quit fully once the user chooses Quit.
app.on("window-all-closed", () => {
  // Do nothing — the tray keeps the app running until explicit Quit.
});

app.on("before-quit", () => {
  isQuitting = true;
  stopBackend();
});

app.on("quit", () => {
  stopBackend();
});
