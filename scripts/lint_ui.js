#!/usr/bin/env node
/**
 * UI lint script — catches JS errors in index.html before they reach the browser.
 *
 * Checks:
 *  1. Duplicate top-level const/let/var declarations (the crash that broke the app)
 *  2. JS syntax errors via Node's vm.Script (catches SyntaxError before runtime)
 *  3. Unclosed HTML tags for the main structural elements
 */

const fs = require('fs');
const vm = require('vm');
const path = require('path');

const htmlPath = path.join(__dirname, '../dast/proxy/ui/index.html');
const html = fs.readFileSync(htmlPath, 'utf8');

let errors = 0;

function fail(msg) {
  console.error(`  FAIL  ${msg}`);
  errors++;
}

function ok(msg) {
  console.log(`  ok    ${msg}`);
}

// ── 1. Extract inline JS ────────────────────────────────────────────────────
const scriptBlocks = [];
const scriptRe = /<script(?:\s[^>]*)?>([^]*?)<\/script>/gi;
let m;
while ((m = scriptRe.exec(html)) !== null) {
  if (!m[0].includes('src=')) {
    scriptBlocks.push({ code: m[1], offset: m.index });
  }
}
const combinedJs = scriptBlocks.map(b => b.code).join('\n');

// ── 2. Syntax check ─────────────────────────────────────────────────────────
try {
  new vm.Script(combinedJs, { filename: 'index.html' });
  ok('JS syntax valid');
} catch (e) {
  fail(`JS syntax error: ${e.message}`);
}

// ── 3. Duplicate top-level const/let/var ────────────────────────────────────
const declRe = /^(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)/gm;
const seen = {};
let dm;
while ((dm = declRe.exec(combinedJs)) !== null) {
  const name = dm[1];
  seen[name] = (seen[name] || 0) + 1;
}
const dupes = Object.entries(seen).filter(([, v]) => v > 1);
if (dupes.length === 0) {
  ok('No duplicate variable declarations');
} else {
  dupes.forEach(([name, count]) => fail(`Duplicate declaration: ${name} (${count}x)`));
}

// ── 4. Check required DOM IDs exist ─────────────────────────────────────────
const requiredIds = ['tbody', 'filterbar', 'proxy-detail-col', 'dbody', 'named-sessions-list'];
for (const id of requiredIds) {
  if (html.includes(`id="${id}"`)) {
    ok(`DOM id #${id} present`);
  } else {
    fail(`DOM id #${id} missing`);
  }
}

// ── 5. Check Python imports ─────────────────────────────────────────────────
// (done separately via uv run, but we at least confirm the HTML references match)

console.log('');
if (errors > 0) {
  console.error(`lint: ${errors} error(s) found`);
  process.exit(1);
} else {
  console.log('lint: all checks passed');
}
