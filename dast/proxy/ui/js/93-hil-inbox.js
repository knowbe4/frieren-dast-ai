// ── Human-in-the-loop inbox (needs-human aggregator) ─────────────────────────
// The Copilot panel is the single place where automated exploration meets human
// help. This inbox folds in every mechanism that pauses for a human, so a
// pending prompt is reachable from any tab (via the count badge on the Copilot
// tab) even when its own contextual surface is off-screen. Each source keeps its
// own resume contract; all events share the same pause/resolve vocabulary here.
//
// Sources:
//   * triage — the headless Vuln Validator (approve / auth / question). Its ONLY
//     surface: it had no UI at all before this inbox.
//   * mcp    — MCP request approval (out-of-scope call). Also shown as a global
//     blocking modal (67-mcp-approval.js); this card is the cross-tab mirror.
//   * login  — login-flow replay paused on a captcha/MFA wall. Also banners in
//     the Login Profiles panel (66-login-profiles.js).
//
// All three resolve through their own existing endpoints — no backend change.
// The copilot's own in-turn pause keeps rendering inline in #cp-pause, untouched.

const _hilItems = {};   // "source:id" -> { source, id, kind, payload }

// Per-source wiring: how to build the resume request (and, where supported, the
// open-browser request) for a card. A table, not branching logic, so a new
// human-in-loop mechanism is one row.
const _HIL_SOURCES = {
  triage: {
    label: 'Vuln Validator',
    resumeReq: (item, kind, value) => ({
      url: `/api/vuln-validator/resume/${encodeURIComponent(item.id)}`,
      body: { kind, value },
    }),
    openBrowserReq: (item) => ({
      url: `/api/vuln-validator/open-browser/${encodeURIComponent(item.id)}`,
    }),
  },
  mcp: {
    label: 'MCP client',
    // Singleton pause (no id); decision maps straight onto the approval endpoint.
    resumeReq: (_item, _kind, value) => ({
      url: '/api/mcp/approval-resume',
      body: { decision: (value && value.decision) || 'deny' },
    }),
  },
  login: {
    label: 'Login replay',
    // Shared resume gate — no id, no body; the human solved it in the open browser.
    resumeReq: () => ({ url: '/api/login-flow/resume', body: {} }),
  },
};

function _hilKey(source, id) { return source + ':' + id; }
function _hilCount() { return Object.keys(_hilItems).length; }

function _hilSet(source, id, kind, payload) {
  _hilItems[_hilKey(source, id)] = { source, id: String(id), kind, payload: payload || {} };
  hilRender();
}

function _hilDel(source, id) {
  delete _hilItems[_hilKey(source, id)];
  hilRender();
}

// Generic auto-reconnecting subscription. On (re)connect a server may re-push
// in-flight pauses, so a late-loading UI still sees an outstanding prompt.
function _hilWsConnect(path, onMsg) {
  try {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}${path}`);
    ws.onmessage = (ev) => {
      let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
      onMsg(m);
    };
    ws.onclose = () => setTimeout(() => _hilWsConnect(path, onMsg), 3000);
    ws.onerror = () => { /* onclose reconnects */ };
  } catch (e) { setTimeout(() => _hilWsConnect(path, onMsg), 3000); }
}

function hilConnectTriage() {
  _hilWsConnect('/ws/agent-triage', (m) => {
    if (m.type === 'pause' && m.job_id) {
      _hilSet('triage', m.job_id, m.kind, m.payload || {});
    } else if (m.type === 'resumed' && m.job_id) {
      _hilDel('triage', m.job_id);
    }
  });
}

function hilConnectMcp() {
  _hilWsConnect('/ws/mcp-approval', (m) => {
    if (m.type === 'approval_needed') {
      _hilSet('mcp', 'current', 'approve', {
        url: m.url || '', host: m.host || '', method: m.method || 'GET', port: m.port,
      });
    } else if (m.type === 'approval_resolved') {
      _hilDel('mcp', 'current');
    }
  });
}

function hilConnectLogin() {
  _hilWsConnect('/ws/login', (m) => {
    if (m.type === 'needs_human') {
      _hilSet('login', m.slug || 'current', 'captcha', { slug: m.slug || '', reason: m.reason || '' });
    } else if (m.type === 'replay_done') {
      _hilDel('login', m.slug || 'current');
    } else if (m.type === 'resumed') {
      // The login resume gate is shared and this event carries no slug — clear
      // every pending login captcha.
      let changed = false;
      for (const key of Object.keys(_hilItems)) {
        if (key.indexOf('login:') === 0) { delete _hilItems[key]; changed = true; }
      }
      if (changed) hilRender();
    }
  });
}

function hilRender() {
  hilUpdateBadge();
  const el = document.getElementById('cp-hil-inbox');
  if (!el) return;
  const items = Object.values(_hilItems);
  if (!items.length) { el.style.display = 'none'; el.innerHTML = ''; return; }
  el.style.display = '';
  el.innerHTML =
    `<div style="font-size:10px;font-weight:600;color:var(--yellow);text-transform:uppercase;letter-spacing:.3px;margin-bottom:6px">Needs human (${items.length})</div>` +
    items.map(hilCard).join('');
}

// A small count badge on the Copilot tab so a pending prompt is visible from any
// tab (some sources have no other cross-tab surface).
function hilUpdateBadge() {
  const tab = document.getElementById('mt-copilot');
  if (!tab) return;
  let badge = document.getElementById('cp-inbox-badge');
  const n = _hilCount();
  if (!n) { if (badge) badge.remove(); return; }
  if (!badge) {
    badge = document.createElement('span');
    badge.id = 'cp-inbox-badge';
    badge.style.cssText = 'margin-left:6px;background:var(--yellow);color:#000;border-radius:8px;' +
      'padding:0 6px;font-size:9px;font-weight:700';
    tab.appendChild(badge);
  }
  badge.textContent = String(n);
}

function hilCard(item) {
  const src = _HIL_SOURCES[item.source] || { label: item.source };
  const payload = item.payload || {};
  const id = esc(item.id);
  const source = esc(item.source);
  const header =
    `<div style="font-size:10px;color:var(--txt2);margin-bottom:6px">${esc(src.label)}` +
    (item.source === 'triage' ? ` · job ${id}` : '') +
    ` · <span style="color:var(--yellow);text-transform:uppercase">${esc(item.kind)}</span></div>`;

  let body;
  if (item.kind === 'approve') {
    const viaClause = payload.tool
      ? ` via <code style="color:var(--orange)">${esc(payload.tool)}</code>` : '';
    body =
      `<div style="font-size:10px;color:var(--txt2);margin-bottom:4px">
         Wants to send a <code style="color:var(--orange)">${esc(payload.method || 'GET')}</code>${viaClause}
         to an out-of-scope target:
       </div>
       <code style="display:block;font-size:10px;background:var(--bg2);padding:6px 8px;border-radius:3px;
             word-break:break-all;margin-bottom:10px">${esc(payload.url || payload.host || '')}</code>
       <div style="display:flex;gap:8px;flex-wrap:wrap">
         <button class="tbtn del" onclick="hilResume('${source}','${id}','approve',{decision:'deny'})">Deny</button>
         <button class="tbtn" onclick="hilResume('${source}','${id}','approve',{decision:'allow_once'})">Allow once</button>
         <button class="tbtn pri" onclick="hilResume('${source}','${id}','approve',{decision:'always_host'})">Always allow host</button>
       </div>`;
  } else if (item.kind === 'auth') {
    body =
      `<div style="font-size:10px;color:var(--txt2);margin-bottom:10px">
         The target returned an auth wall (HTTP ${esc(String(payload.status || ''))}) on
         <code style="color:var(--orange)">${esc(payload.host || payload.url || '')}</code>.
         Open a browser, log in, then click "Login done" — captured session cookies are handed back.
       </div>
       <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
         <button class="tbtn pri" onclick="hilOpenBrowser('${source}','${id}')">Open Browser</button>
         <button class="tbtn" id="hil-login-done-${id}" onclick="hilLoginDone('${source}','${id}')" disabled>Login done — retry</button>
         <button class="tbtn del" onclick="hilResume('${source}','${id}','auth',{cookies:{}})">Skip (no session)</button>
         <span id="hil-auth-msg-${id}" style="font-size:10px;color:var(--txt2)"></span>
       </div>`;
  } else if (item.kind === 'question') {
    body =
      `<div style="font-size:11px;color:var(--txt);margin-bottom:8px;white-space:pre-wrap">${esc(payload.question || 'The agent needs a value from you.')}</div>
       <textarea id="hil-q-${id}" rows="2" placeholder="Your answer..."
         style="width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--bdr);color:var(--txt);
                padding:6px 8px;border-radius:4px;font-size:12px;font-family:inherit;resize:vertical;margin-bottom:8px"></textarea>
       <div style="display:flex;gap:8px">
         <button class="tbtn pri" onclick="hilQuestionSubmit('${source}','${id}')">Submit answer</button>
       </div>`;
  } else if (item.kind === 'captcha') {
    body =
      `<div style="font-size:10px;color:var(--txt2);margin-bottom:10px">
         Login replay for profile <code style="color:var(--orange)">${esc(payload.slug || '')}</code>
         paused: ${esc(payload.reason || 'a human action is needed')}. Solve it in the open
         browser window, then click Continue.
       </div>
       <div style="display:flex;gap:8px">
         <button class="tbtn pri" onclick="hilResume('${source}','${id}','captcha',{})">Continue — I solved it</button>
       </div>`;
  } else {
    body = `<div style="font-size:10px;color:var(--txt2)">Unsupported pause kind: ${esc(item.kind)}</div>`;
  }

  return `<div style="background:#3a2d00;border:1px solid #7a6000;border-radius:4px;padding:10px 12px;margin-bottom:8px">
      ${header}${body}
    </div>`;
}

async function hilResume(source, id, kind, value) {
  const src = _HIL_SOURCES[source];
  if (!src) return;
  const item = _hilItems[_hilKey(source, id)] || { id };
  const req = src.resumeReq(item, kind, value);
  try {
    const r = await fetch(req.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body || {}),
    });
    const d = await r.json().catch(() => ({}));
    if (d && d.error) { showToast(d.error, true); return; }
    // The resolve WS event clears the card; drop it optimistically too so the UI
    // feels immediate even if the socket lags.
    delete _hilItems[_hilKey(source, id)];
    hilRender();
  } catch (e) { showToast('Resume failed', true); }
}

async function hilOpenBrowser(source, id) {
  const src = _HIL_SOURCES[source];
  const msgEl = document.getElementById(`hil-auth-msg-${id}`);
  const doneBtn = document.getElementById(`hil-login-done-${id}`);
  if (!src || !src.openBrowserReq) return;
  const item = _hilItems[_hilKey(source, id)] || { id };
  if (msgEl) msgEl.textContent = 'Opening browser...';
  try {
    const r = await fetch(src.openBrowserReq(item).url, { method: 'POST' });
    const d = await r.json();
    if (d.ok) {
      if (msgEl) msgEl.textContent = `Browser open at ${d.target_url || ''}. Log in, then click "Login done".`;
      if (doneBtn) doneBtn.disabled = false;
    } else if (msgEl) {
      msgEl.textContent = d.error || 'Failed to open browser';
    }
  } catch (e) { if (msgEl) msgEl.textContent = 'Request failed'; }
}

// Collect Set-Cookie values captured by the proxy for the auth-wall domain and
// hand them back as the session. Mirrors the copilot's login handoff.
function _hilCollectCookies(targetDomain) {
  const cookies = {};
  if (!targetDomain || typeof order === 'undefined' || typeof entries === 'undefined') return cookies;
  for (const eid of order) {
    const entry = entries[eid];
    if (!entry || !entry.host) continue;
    if (!entry.host.includes(targetDomain) && !targetDomain.includes(entry.host)) continue;
    const setCookie = (entry.response_headers && entry.response_headers['set-cookie']) || '';
    if (!setCookie) continue;
    for (const part of setCookie.split(';')) {
      const eq = part.trim().indexOf('=');
      if (eq > 0) {
        const name = part.trim().slice(0, eq).trim();
        const val = part.trim().slice(eq + 1).trim();
        if (name && val && !['path', 'domain', 'expires', 'samesite', 'secure', 'httponly'].includes(name.toLowerCase())) {
          cookies[name] = val;
        }
      }
    }
  }
  return cookies;
}

async function hilLoginDone(source, id) {
  const item = _hilItems[_hilKey(source, id)];
  const msgEl = document.getElementById(`hil-auth-msg-${id}`);
  const doneBtn = document.getElementById(`hil-login-done-${id}`);
  if (doneBtn) doneBtn.disabled = true;
  let domain = '';
  try {
    const url = (item && item.payload && item.payload.url) || '';
    if (url) domain = new URL(url).hostname;
  } catch (e) { /* fall through with empty domain */ }
  const cookies = _hilCollectCookies(domain);
  if (msgEl) msgEl.textContent = `Sending ${Object.keys(cookies).length} cookies...`;
  await hilResume(source, id, 'auth', { cookies });
}

async function hilQuestionSubmit(source, id) {
  const textarea = document.getElementById(`hil-q-${id}`);
  const text = textarea ? textarea.value.trim() : '';
  await hilResume(source, id, 'question', { text });
}

hilConnectTriage();
hilConnectMcp();
hilConnectLogin();
hilRender();
