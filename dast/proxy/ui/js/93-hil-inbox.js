// ── Human-in-the-loop inbox (needs-human aggregator) ─────────────────────────
// The Copilot panel is the single place where automated exploration meets human
// help. This inbox folds in the OTHER mechanisms that pause for a human but have
// no surface of their own. Step 1: the Vuln Validator (agentic triage), whose
// approve / auth / question pauses were previously reachable only over the
// HTTP/MCP API with no UI at all — a headless capability nobody could unblock.
//
// Each pending pause renders as an answerable card and resolves through the
// mechanism's own existing resume endpoint (no backend change). The copilot's
// own in-turn pause keeps rendering inline in #cp-pause — this does not touch it.
// A badge on the Copilot tab surfaces pending prompts from any tab.

let _hilWs = null;
const _hilItems = {};   // "source:id" -> { source, id, kind, payload }

// Resume wiring per source. A table, not branching logic, so step 2 (MCP
// approval, login captcha) only adds rows here.
const _HIL_SOURCES = {
  triage: {
    label: 'Vuln Validator',
    resume:      (id) => `/api/vuln-validator/resume/${encodeURIComponent(id)}`,
    openBrowser: (id) => `/api/vuln-validator/open-browser/${encodeURIComponent(id)}`,
  },
};

function _hilKey(source, id) { return source + ':' + id; }
function _hilCount() { return Object.keys(_hilItems).length; }

// The triage stream speaks the same pause/resumed vocabulary as the copilot,
// keyed by job_id. On (re)connect the server re-pushes in-flight pauses, so a
// late-loading UI still sees an outstanding prompt.
function hilConnectWs() {
  try {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    _hilWs = new WebSocket(`${proto}://${location.host}/ws/agent-triage`);
    _hilWs.onmessage = (ev) => {
      let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
      if (m.type === 'pause' && m.job_id) {
        _hilItems[_hilKey('triage', m.job_id)] = {
          source: 'triage', id: m.job_id, kind: m.kind, payload: m.payload || {},
        };
        hilRender();
      } else if (m.type === 'resumed' && m.job_id) {
        delete _hilItems[_hilKey('triage', m.job_id)];
        hilRender();
      }
    };
    _hilWs.onclose = () => { _hilWs = null; setTimeout(hilConnectWs, 3000); };
    _hilWs.onerror = () => { /* onclose reconnects */ };
  } catch (e) { _hilWs = null; }
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
// tab (the triage agent has no other surface).
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
    `<div style="font-size:10px;color:var(--txt2);margin-bottom:6px">${esc(src.label)} · job ${id} · ` +
    `<span style="color:var(--yellow);text-transform:uppercase">${esc(item.kind)}</span></div>`;

  let body;
  if (item.kind === 'approve') {
    body =
      `<div style="font-size:10px;color:var(--txt2);margin-bottom:4px">
         Wants to send a <code style="color:var(--orange)">${esc(payload.method || 'GET')}</code>
         via <code style="color:var(--orange)">${esc(payload.tool || 'tool')}</code> to an out-of-scope host:
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
  try {
    const r = await fetch(src.resume(id), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind, value }),
    });
    const d = await r.json();
    if (d && d.error) { showToast(d.error, true); return; }
    // The 'resumed' WS event clears the card; drop it optimistically too so the
    // UI feels immediate even if the socket lags.
    delete _hilItems[_hilKey(source, id)];
    hilRender();
  } catch (e) { showToast('Resume failed', true); }
}

async function hilOpenBrowser(source, id) {
  const src = _HIL_SOURCES[source];
  const msgEl = document.getElementById(`hil-auth-msg-${id}`);
  const doneBtn = document.getElementById(`hil-login-done-${id}`);
  if (!src || !src.openBrowser) return;
  if (msgEl) msgEl.textContent = 'Opening browser...';
  try {
    const r = await fetch(src.openBrowser(id), { method: 'POST' });
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

hilConnectWs();
hilRender();
