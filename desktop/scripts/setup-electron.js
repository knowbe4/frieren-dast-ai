#!/usr/bin/env node
// Ensures the Electron binary is present and path.txt points at it.
//
// Why this exists: some npm configurations block package lifecycle scripts
// (npm's allow-scripts feature), so Electron's own postinstall never runs and
// no binary is downloaded. Even when we run Electron's install.js manually, its
// bundled `extract-zip` can fail silently on the symlinks inside the macOS
// `.app` bundle, leaving a half-extracted dist/ with an empty path.txt.
//
// This script:
//   1. runs Electron's official install.js (downloads + caches the zip),
//   2. verifies the extraction actually completed (dist/version + path.txt),
//   3. if not, extracts the cached zip with the system `unzip` and writes
//      path.txt itself.
//
// It is idempotent: a correct install is detected and left untouched.

const { execFileSync, execSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const electronDir = path.join(__dirname, "..", "node_modules", "electron");
const distDir = path.join(electronDir, "dist");
const pathTxt = path.join(electronDir, "path.txt");
const versionFile = path.join(distDir, "version");
const { version } = require(path.join(electronDir, "package.json"));
const { productName: PRODUCT_NAME } = require(path.join(__dirname, "..", "package.json")).build;

function platformExecutable() {
  switch (os.platform()) {
    case "darwin":
      return "Electron.app/Contents/MacOS/Electron";
    case "win32":
      return "electron.exe";
    default:
      return "electron";
  }
}

function isInstalled() {
  try {
    if (fs.readFileSync(versionFile, "utf-8").replace(/^v/, "") !== version) {
      return false;
    }
    if (fs.readFileSync(pathTxt, "utf-8") !== platformExecutable()) {
      return false;
    }
    return fs.existsSync(path.join(distDir, platformExecutable()));
  } catch {
    return false;
  }
}

function cachedZipPath() {
  // @electron/get stores the zip under ~/Library/Caches/electron (macOS),
  // ~/.cache/electron (Linux), or %LOCALAPPDATA%\electron\Cache (Windows).
  const home = os.homedir();
  const roots = [
    path.join(home, "Library", "Caches", "electron"),
    path.join(home, ".cache", "electron"),
    process.env.LOCALAPPDATA
      ? path.join(process.env.LOCALAPPDATA, "electron", "Cache")
      : null,
  ].filter(Boolean);

  const arch = process.arch;
  const zipName = `electron-v${version}-${os.platform()}-${arch}.zip`;

  for (const root of roots) {
    if (!fs.existsSync(root)) continue;
    for (const sub of fs.readdirSync(root)) {
      const candidate = path.join(root, sub, zipName);
      if (fs.existsSync(candidate)) return candidate;
    }
  }
  return null;
}

function fallbackExtract() {
  const zip = cachedZipPath();
  if (!zip) {
    throw new Error(
      "Electron zip not found in cache — cannot fall back to system unzip."
    );
  }
  if (os.platform() === "win32") {
    throw new Error(
      "Electron install failed and no Windows unzip fallback is implemented. " +
        "Delete node_modules/electron and reinstall."
    );
  }
  fs.rmSync(distDir, { recursive: true, force: true });
  fs.mkdirSync(distDir, { recursive: true });
  // System unzip handles the .app symlinks that extract-zip trips over.
  execSync(`unzip -q "${zip}" -d "${distDir}"`, { stdio: "inherit" });
  fs.writeFileSync(pathTxt, platformExecutable());
}

// On macOS, dev runs (`npm start` / `make desktop`) launch the raw downloaded
// Electron.app directly — there is no electron-builder pass to apply
// `build.productName`. The menu bar, Dock, and Cmd+Tab switcher all read the
// bundle's CFBundleName/CFBundleDisplayName, not app.setName() (that only
// affects app.getName() inside the JS runtime), so without patching the
// plist the app always shows as "Electron" in dev even though main.js calls
// app.setName(). Packaged builds are unaffected — electron-builder rewrites
// the plist itself during packaging.
const infoPlist = path.join(distDir, "Electron.app", "Contents", "Info.plist");

function isRenamed() {
  try {
    const name = execFileSync("/usr/libexec/PlistBuddy", [
      "-c",
      "Print :CFBundleName",
      infoPlist,
    ]).toString().trim();
    return name === PRODUCT_NAME;
  } catch {
    return false;
  }
}

function renameBundle() {
  for (const key of ["CFBundleName", "CFBundleDisplayName"]) {
    execFileSync("/usr/libexec/PlistBuddy", [
      "-c",
      `Set :${key} ${PRODUCT_NAME}`,
      infoPlist,
    ]);
  }
  // The plist edit invalidates the bundle's ad-hoc signature — macOS refuses
  // to launch (or silently misbehaves) with a stale seal, so re-sign it.
  execFileSync("codesign", [
    "--force",
    "--deep",
    "--sign",
    "-",
    path.join(distDir, "Electron.app"),
  ]);
  console.log(`Renamed Electron.app bundle to "${PRODUCT_NAME}".`);
}

function main() {
  if (isInstalled()) {
    console.log(`Electron ${version} already installed correctly.`);
  } else {
    installElectron();
  }

  if (os.platform() === "darwin" && !isRenamed()) {
    renameBundle();
  }
}

function installElectron() {
  // Try Electron's own installer first (downloads + caches the zip).
  try {
    execFileSync("node", [path.join(electronDir, "install.js")], {
      stdio: "inherit",
    });
  } catch (err) {
    console.warn(`Electron install.js failed: ${err.message}`);
  }

  if (isInstalled()) {
    console.log(`Electron ${version} installed.`);
    return;
  }

  // install.js ran but extraction was incomplete — extract with system unzip.
  console.log("Extraction incomplete — falling back to system unzip...");
  fallbackExtract();

  if (!isInstalled()) {
    throw new Error(
      "Electron still not installed correctly after unzip fallback."
    );
  }
  console.log(`Electron ${version} installed via unzip fallback.`);
}

main();
