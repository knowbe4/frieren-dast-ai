// ── Exploration Copilot (conversational agent) ──────────────────────────────
// Chat surface for dast/ai/copilot: the operator sends a message, the copilot
// drives the shared tool layer and replies, and the thread continues. It streams
// its live tool activity over /ws/copilot and renders the same two human-in-the-
// loop pauses as the vuln validator (approve an out-of-scope host / hand off a
// login), plus a "blocked" badge when it hands the turn back needing help.

let _cpActive = null;      // active session_id
let _cpPollTimer = null;
let _cpWs = null;
let _cpPauseSig = null;     // last-rendered pause identity; guards live DOM (see cpRender)

const _CP_INPROGRESS = ['running', 'starting', 'paused', 'paused_approve',
  'paused_auth', 'paused_guidance'];

function cpOnOpen() {
  _cpPauseSig = null;  // force a pause re-render — the tab DOM may be fresh
  cpConnectWs();
  cpLoadSessions();
  cpLoadHypotheses();
  cpLoadProfiles();
  if (_cpActive) cpRefresh(_cpActive);
  else cpRender(null);
}

// ── Autonomous orchestrator run ──────────────────────────────────────────────
// Populate the login-profile dropdown so an autonomous run can preseed auth.
async function cpLoadProfiles() {
  const sel = document.getElementById('cp-auto-profile');
  if (!sel) return;
  try {
    const data = await (await fetch('/api/profiles')).json();
    const profiles = (data && data.profiles) || [];
    const current = sel.value;
    sel.innerHTML = '<option value="">none</option>' +
      profiles.map(p =>
        `<option value="${esc(p.slug)}">${esc(p.name || p.slug)}${p.session_set ? '' : ' (no session)'}</option>`
      ).join('');
    if (current) sel.value = current;
  } catch (e) { /* profiles are best-effort */ }
}

async function cpStartAutonomous() {
  const objective = (document.getElementById('cp-auto-objective') || {}).value || '';
  const msgEl = document.getElementById('cp-auto-msg');
  if (!objective.trim()) { if (msgEl) msgEl.textContent = 'Objective is required'; return; }

  const hostsRaw = (document.getElementById('cp-auto-hosts') || {}).value || '';
  const focus_hosts = hostsRaw.split(',').map(h => h.trim()).filter(Boolean);
  const profile_slug = (document.getElementById('cp-auto-profile') || {}).value || '';
  const num = (id, fallback) => {
    const v = parseInt(((document.getElementById(id) || {}).value || '').trim(), 10);
    return Number.isFinite(v) ? v : fallback;
  };
  const budget = {
    max_tool_calls: num('cp-auto-tools', 150),
    max_wall_clock_seconds: num('cp-auto-mins', 30) * 60,
    max_stuck_turns: num('cp-auto-stuck', 3),
    allow_scope_escalation: !!(document.getElementById('cp-auto-escalate') || {}).checked,
  };

  const btn = document.getElementById('cp-auto-start');
  if (btn) btn.disabled = true;
  if (msgEl) msgEl.textContent = 'Starting...';
  try {
    const r = await fetch('/api/copilot/autonomous', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        objective: objective.trim(), focus_hosts,
        profile_slug: profile_slug || undefined, budget,
      }),
    });
    const d = await r.json();
    if (!r.ok || d.error) { if (msgEl) msgEl.textContent = d.error || 'Failed to start'; return; }
    if (msgEl) msgEl.textContent = '';
    await cpSelectSession(d.session_id);
    cpStartPoll(d.session_id);
  } catch (e) {
    if (msgEl) msgEl.textContent = 'Request failed';
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function cpAutoControl(sid, action) {
  try {
    const r = await fetch(`/api/copilot/autonomous/${sid}/${action}`, { method: 'POST' });
    const d = await r.json();
    if (!r.ok || d.error) { showToast(d.error || `Could not ${action} the run`, true); return; }
    cpRefresh(sid);
  } catch (e) { showToast(`Could not ${action} the run`, true); }
}

async function cpAnswerGuidance(sid, action) {
  const box = document.getElementById('cp-guidance-answer');
  const answer = box ? box.value.trim() : '';
  await cpResume(sid, 'guidance', { answer, action });
}

// ── App-context hypotheses (fold-in) ─────────────────────────────────────────
// The app-context analyser raises vulnerability hypotheses per host. Rather than
// firing a blind scan, each one opens a conversation so the copilot understands
// the endpoint first, then attempts a proof or reports why it does not hold.
const _CP_PRIO_RANK = { high: 0, medium: 1, low: 2 };

async function cpLoadHypotheses() {
  const el = document.getElementById('cp-hypotheses');
  if (!el) return;
  try {
    const ctx = await (await fetch('/api/ai/app-context')).json();
    const rows = [];
    for (const host of Object.keys(ctx || {})) {
      for (const h of (ctx[host].vuln_hypotheses || [])) rows.push({ host, ...h });
    }
    rows.sort((a, b) => (_CP_PRIO_RANK[a.priority] ?? 3) - (_CP_PRIO_RANK[b.priority] ?? 3));
    if (!rows.length) { el.style.display = 'none'; el.innerHTML = ''; return; }
    const prioColor = { high: 'var(--red)', medium: 'var(--orange)', low: 'var(--txt2)' };
    el.style.display = '';
    el.innerHTML =
      `<div style="font-size:10px;font-weight:600;color:var(--txt2);text-transform:uppercase;letter-spacing:.3px;margin-bottom:6px">Hypotheses to explore (${rows.length})</div>` +
      rows.slice(0, 12).map(h => `
        <div style="display:flex;align-items:baseline;gap:8px;padding:3px 0;border-top:1px solid var(--bdr)">
          <span style="color:${prioColor[h.priority] || 'var(--txt2)'};font-size:9px;text-transform:uppercase;width:40px;flex-shrink:0">${esc(h.priority || '')}</span>
          <span style="color:var(--orange);font-family:monospace;font-size:10px;width:84px;flex-shrink:0">${esc(h.attack_type || '')}</span>
          <span style="color:var(--txt);font-family:monospace;font-size:10px;white-space:nowrap">${esc(h.endpoint || '')}</span>
          ${h.parameter && h.parameter !== '*' ? `<span style="color:var(--blue);font-size:10px">[${esc(h.parameter)}]</span>` : ''}
          <span style="color:var(--txt2);font-size:10px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(h.rationale || '')}</span>
          <button onclick='exploreHypothesis(${JSON.stringify(h.host)},${JSON.stringify(h.attack_type)},${JSON.stringify(h.endpoint)},${JSON.stringify(h.parameter || '')},${JSON.stringify(h.rationale || '')})'
                  style="font-size:9px;padding:1px 7px;background:var(--blue);color:#fff;border:none;border-radius:3px;cursor:pointer;flex-shrink:0">Explore</button>
        </div>`).join('');
  } catch (e) { /* ignore — hypotheses are best-effort */ }
}

async function exploreHypothesis(host, attackType, endpoint, parameter, rationale) {
  try {
    const r = await fetch('/api/copilot/explore-hypothesis', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        host, attack_type: attackType, endpoint,
        parameter: parameter || '', rationale: rationale || '',
      }),
    });
    const d = await r.json();
    if (!r.ok || d.error) { showToast(d.error || 'Could not start exploration'); return; }
    switchMain('copilot');
    await cpSelectSession(d.session_id);
  } catch (e) { showToast('Could not start exploration'); }
}

function cpNewChat() {
  _cpActive = null;
  if (_cpPollTimer) { clearInterval(_cpPollTimer); _cpPollTimer = null; }
  const input = document.getElementById('cp-input');
  if (input) { input.value = ''; input.focus(); }
  cpRender(null);
  cpLoadSessions();
}

async function cpSend() {
  const input = document.getElementById('cp-input');
  const msgEl = document.getElementById('cp-send-msg');
  const text = input ? input.value.trim() : '';
  if (!text) return;

  const body = { message: text };
  if (_cpActive) body.session_id = _cpActive;

  cpSetComposerBusy(true);
  if (msgEl) msgEl.textContent = 'Sending...';
  try {
    const r = await fetch('/api/copilot/message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (!r.ok || d.error) {
      if (msgEl) msgEl.textContent = d.error || 'Request failed';
      cpSetComposerBusy(false);
      return;
    }
    if (msgEl) msgEl.textContent = '';
    if (input) input.value = '';
    _cpActive = d.session_id;
    cpConnectWs();
    cpStartPoll(d.session_id);
    cpRefresh(d.session_id);
    cpLoadSessions();
  } catch (e) {
    if (msgEl) msgEl.textContent = 'Request failed';
    cpSetComposerBusy(false);
  }
}

function cpSetComposerBusy(busy) {
  const btn = document.getElementById('cp-send-btn');
  const cancel = document.getElementById('cp-cancel-btn');
  if (btn) btn.disabled = busy;
  if (cancel) cancel.style.display = busy ? '' : 'none';
}

function cpStartPoll(sid) {
  if (_cpPollTimer) clearInterval(_cpPollTimer);
  _cpPollTimer = setInterval(() => cpRefresh(sid), 1500);
}

async function cpRefresh(sid) {
  if (!sid || sid !== _cpActive) return;
  try {
    const r = await fetch(`/api/copilot/session/${sid}`);
    if (!r.ok) return;
    const session = await r.json();
    cpRender(session);
    if (!_CP_INPROGRESS.includes(session.status)) {
      if (_cpPollTimer) { clearInterval(_cpPollTimer); _cpPollTimer = null; }
      cpSetComposerBusy(false);
      cpLoadSessions();
    } else {
      cpSetComposerBusy(true);
    }
  } catch (e) { /* ignore transient poll errors */ }
}

// Live WebSocket — nudges a refresh of the active session so the trace feels live
// between poll ticks. The server session is the source of truth.
function cpConnectWs() {
  if (_cpWs && (_cpWs.readyState === 0 || _cpWs.readyState === 1)) return;
  try {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    _cpWs = new WebSocket(`${proto}://${location.host}/ws/copilot`);
    _cpWs.onmessage = (ev) => {
      let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
      if (m && m.session_id && m.session_id === _cpActive) cpRefresh(m.session_id);
    };
    _cpWs.onclose = () => { _cpWs = null; };
    _cpWs.onerror = () => { /* onclose clears it */ };
  } catch (e) { _cpWs = null; }
}

async function cpLoadSessions() {
  const el = document.getElementById('cp-session-list');
  if (!el) return;
  try {
    const r = await fetch('/api/copilot/sessions');
    const sessions = await r.json();
    if (!sessions.length) {
      el.innerHTML = '<div style="padding:12px 14px;color:var(--txt2);font-size:11px">No conversations yet</div>';
      return;
    }
    el.innerHTML = sessions.map(s => {
      const active = _cpActive === s.session_id ? 'background:var(--sel);' : '';
      const dot = cpStatusColor(s.status);
      return `<div onclick="cpSelectSession('${esc(s.session_id)}')"
                   style="padding:8px 12px;cursor:pointer;border-bottom:1px solid var(--bdr);${active}">
        <div style="display:flex;gap:6px;align-items:center">
          <span style="width:7px;height:7px;border-radius:50%;background:${dot};flex-shrink:0"></span>
          <span style="font-size:11px;color:var(--txt);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(s.session_id)}</span>
          <span style="font-size:9px;color:var(--txt2);margin-left:auto">${s.message_count || 0} msg</span>
        </div>
        <div style="font-size:9px;color:var(--txt2);margin-top:2px;text-transform:uppercase;letter-spacing:.3px">${esc(s.status || 'idle')}</div>
      </div>`;
    }).join('');
  } catch (e) { /* ignore */ }
}

async function cpSelectSession(sid) {
  _cpActive = sid;
  cpConnectWs();
  await cpRefresh(sid);
  cpLoadSessions();
  try {
    const session = await (await fetch(`/api/copilot/session/${sid}`)).json();
    if (_CP_INPROGRESS.includes(session.status)) cpStartPoll(sid);
  } catch (e) { /* ignore */ }
}

function cpStatusColor(st) {
  return st === 'blocked' ? 'var(--yellow)' :
         st === 'error' ? 'var(--orange)' :
         (st || '').indexOf('paused') === 0 ? 'var(--yellow)' :
         st === 'running' ? 'var(--acc2)' : 'var(--green)';
}

// ── Conversation rendering ───────────────────────────────────────────────────
function cpRender(session) {
  const el = document.getElementById('cp-messages');
  const statusEl = document.getElementById('cp-status');
  const pauseEl = document.getElementById('cp-pause');
  if (!el) return;

  if (!session || !session.session_id) {
    el.innerHTML = `<div class="empty" style="margin:auto;text-align:center;color:var(--txt2);max-width:440px;line-height:1.6">
        Ask the copilot to explore or exploit something in scope.<br>
        It drives the same tools the scanner uses, reports findings with evidence,
        and tells you when it is blocked so you can unblock it and it continues.
      </div>`;
    if (statusEl) statusEl.textContent = '';
    if (pauseEl) pauseEl.innerHTML = '';
    return;
  }

  const st = session.status || 'idle';
  const inProgress = _CP_INPROGRESS.includes(st);
  if (statusEl) {
    const label = { running: 'working...', paused_approve: 'paused — approval needed',
      paused_auth: 'paused — login needed', blocked: 'blocked — needs you',
      error: 'error', idle: 'ready' }[st] || st;
    statusEl.textContent = label;
    statusEl.style.color = cpStatusColor(st);
  }

  cpRenderAutonomous(session);

  const bubbles = (session.messages || []).map(m => cpBubble(m)).join('');
  const blocked = session.last_reply && session.last_reply.blocked_reason && !inProgress
    ? cpBlockedBadge(session.last_reply.blocked_reason) : '';
  const activity = cpRenderActivity(session, inProgress);

  el.innerHTML = bubbles + blocked + activity;
  cpEnsurePulse();
  el.scrollTop = el.scrollHeight;

  // Only rewrite the pause panel when the pause identity actually changes. The
  // poll loop and WS nudges re-render on every tick during a paused_* status; if
  // we rebuilt the panel each time we'd clobber live DOM state the operator set
  // mid-pause (e.g. the "Login done" button enabled by Open Browser, and the
  // auth status message) — which is exactly what left the button greyed out.
  if (pauseEl) {
    const sig = session.pause
      ? `${session.session_id}:${session.pause.kind}:${JSON.stringify(session.pause.payload || {})}`
      : null;
    if (sig !== _cpPauseSig) {
      pauseEl.innerHTML = session.pause ? cpRenderPause(session) : '';
      _cpPauseSig = sig;
    }
  }
}

// Render the live autonomous-run status + controls into the run panel. Only shows
// for sessions started as an autonomous run (session.autonomous present).
function cpRenderAutonomous(session) {
  const el = document.getElementById('cp-auto-status');
  if (!el) return;
  const auto = session && session.autonomous;
  if (!auto) { el.innerHTML = ''; return; }
  const st = auto.status || '';
  const running = ['starting', 'running', 'paused'].includes(st);
  const paused = st === 'paused';
  const sid = esc(session.session_id);
  const color = cpStatusColor(st);
  const controls = running
    ? `<div style="display:flex;gap:6px;margin-top:6px;flex-wrap:wrap">
         ${paused
           ? `<button class="tbtn" onclick="cpAutoControl('${sid}','resume')">Resume</button>`
           : `<button class="tbtn" onclick="cpAutoControl('${sid}','pause')">Pause</button>`}
         <button class="tbtn del" onclick="cpAutoControl('${sid}','stop')">Stop</button>
         <button class="tbtn" onclick="cpRefreshSession('${sid}', this)">Refresh Session</button>
       </div>`
    : `<div style="display:flex;gap:6px;margin-top:6px">
         <button class="tbtn" onclick="cpRefreshSession('${sid}', this)">Refresh Session</button>
       </div>`;
  el.innerHTML = `
    <div style="background:var(--bg2);border:1px solid var(--bdr);border-radius:4px;padding:8px 10px;margin-top:4px">
      <div style="display:flex;gap:8px;align-items:center;font-size:10px">
        <span style="width:7px;height:7px;border-radius:50%;background:${color};flex-shrink:0"></span>
        <span style="font-weight:600;text-transform:uppercase;letter-spacing:.3px;color:${color}">${esc(st || 'idle')}</span>
        ${auto.detail ? `<span style="color:var(--txt2)">— ${esc(auto.detail)}</span>` : ''}
      </div>
      <div style="font-size:10px;color:var(--txt2);margin-top:4px">
        ${auto.turns || 0} turns · ${auto.tool_calls || 0}/${(auto.config || {}).max_tool_calls || '?'} tool calls · ${auto.seconds_remaining || 0}s left
      </div>
      ${controls}
    </div>`;
}

function cpBubble(m) {
  const isOp = m.role === 'operator';
  const align = isOp ? 'flex-end' : 'flex-start';
  const bg = isOp ? 'var(--acc)' : 'var(--bg2)';
  const border = isOp ? 'var(--acc)' : 'var(--bdr)';
  const who = isOp ? 'you' : 'copilot';
  return `<div style="display:flex;justify-content:${align}">
      <div style="max-width:78%;background:${bg};border:1px solid ${border};border-radius:8px;padding:8px 12px">
        <div style="font-size:9px;color:var(--txt2);text-transform:uppercase;letter-spacing:.4px;margin-bottom:3px">${who}</div>
        <div style="font-size:12px;color:var(--txt);line-height:1.55;white-space:pre-wrap;word-break:break-word">${esc(m.content || '')}</div>
      </div>
    </div>`;
}

async function cpRefreshSession(sid, btnEl) {
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = 'Refreshing...'; }
  try {
    const r = await fetch(`/api/copilot/refresh-session/${encodeURIComponent(sid)}`, { method: 'POST' });
    const d = await r.json();
    if (!r.ok || !d.ok) {
      if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Refresh Session'; }
      alert(d.error || 'Session refresh failed');
      return;
    }
    const msg = d.cookies_refreshed > 0
      ? `Session refreshed — ${d.cookies_refreshed} cookie(s) updated for: ${(d.hosts_updated || []).join(', ')}`
      : 'No cookies found in proxy jar yet. Log in through the browser first, then try again.';
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Refresh Session'; }
    alert(msg);
  } catch (e) {
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Refresh Session'; }
    alert('Session refresh failed: ' + e.message);
  }
}

function cpBlockedBadge(reason) {
  const sid = _cpActive ? esc(_cpActive) : '';
  const refreshBtn = sid
    ? `<button class="tbtn" style="font-size:9px;padding:2px 8px"
         onclick="cpRefreshSession('${sid}', this)">Refresh Session</button>`
    : '';
  return `<div style="align-self:flex-start;display:flex;align-items:center;gap:6px;margin-left:2px">
      <span style="font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;color:var(--yellow);
                   border:1px solid #7a6000;background:#3a2d00;border-radius:3px;padding:2px 7px">blocked: ${esc(reason)}</span>
      ${refreshBtn}
    </div>`;
}

// The live tool activity for the session: a pulsing indicator while a turn runs,
// plus a collapsible log of the tool steps and observations.
function cpRenderActivity(session, inProgress) {
  const trace = session.trace || [];
  const steps = trace.filter(ev => ev.type === 'step');
  const latest = steps.length ? steps[steps.length - 1] : null;

  const live = inProgress
    ? `<div style="display:flex;align-items:center;gap:8px;color:var(--acc2);font-size:11px;padding:2px">
         <div style="width:8px;height:8px;border-radius:50%;background:var(--acc2);animation:cp-pulse 1s infinite"></div>
         <span>${esc((latest && latest.thought) || 'working...')}</span>
       </div>`
    : '';

  const items = trace.map(ev => cpTraceEvent(ev)).filter(Boolean).join('');
  const log = items
    ? `<details style="font-size:10px;color:var(--txt2)">
         <summary style="cursor:pointer;padding:2px 0">Tool activity (${steps.length} step${steps.length === 1 ? '' : 's'})</summary>
         <div style="display:flex;flex-direction:column;gap:5px;margin-top:6px">${items}</div>
       </details>`
    : '';

  return (live || log) ? `<div style="display:flex;flex-direction:column;gap:6px;margin-top:2px">${live}${log}</div>` : '';
}

function cpTraceEvent(ev) {
  if (ev.type === 'step') {
    return `<div style="border-left:2px solid var(--orange);padding:3px 9px;background:var(--bg2);border-radius:0 3px 3px 0">
        <div style="display:flex;gap:6px;align-items:center">
          <span style="font-size:9px;color:var(--txt2)">step ${ev.step}</span>
          <span style="font-size:9px;font-weight:600;text-transform:uppercase;color:var(--orange)">${esc(ev.action || '')}</span>
        </div>
        ${ev.thought ? `<div style="font-size:10px;color:var(--txt);margin-top:2px">${esc(ev.thought)}</div>` : ''}
      </div>`;
  }
  if (ev.type === 'observation') {
    return `<details style="margin-left:9px">
        <summary style="cursor:pointer;font-size:9px;color:var(--txt2)">observation (step ${ev.step})</summary>
        <pre style="margin-top:4px;padding:7px;background:#0a0a1a;border:1px solid var(--bdr);border-radius:3px;
             font-size:10px;overflow:auto;white-space:pre-wrap;color:#7ef7a0;max-height:160px">${esc(ev.observation || '')}</pre>
      </details>`;
  }
  return '';
}

// ── Pause rendering + resolution (approve / auth) ────────────────────────────
function cpRenderPause(session) {
  const kind = session.pause.kind;
  const payload = session.pause.payload || {};
  const sid = esc(session.session_id);

  if (kind === 'approve') {
    return `<div style="background:#3a2d00;border:1px solid #7a6000;border-radius:4px;padding:12px 14px;margin:8px 0">
        <div style="font-size:11px;color:var(--yellow);font-weight:600;margin-bottom:6px">Out-of-scope host — authorize?</div>
        <div style="font-size:10px;color:var(--txt2);margin-bottom:4px">
          The copilot wants to send a <code style="color:var(--orange)">${esc(payload.method || 'GET')}</code>
          via <code style="color:var(--orange)">${esc(payload.tool || 'tool')}</code> to a host that is not in scope:
        </div>
        <code style="display:block;font-size:10px;background:var(--bg2);padding:6px 8px;border-radius:3px;
              word-break:break-all;margin-bottom:10px">${esc(payload.url || payload.host || '')}</code>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="tbtn del" onclick="cpResume('${sid}','approve',{decision:'deny'})">Deny</button>
          <button class="tbtn" onclick="cpResume('${sid}','approve',{decision:'allow_once'})">Allow once</button>
          <button class="tbtn pri" onclick="cpResume('${sid}','approve',{decision:'always_host'})">Always allow host</button>
        </div>
      </div>`;
  }

  if (kind === 'guidance') {
    return `<div style="background:#3a2d00;border:1px solid #7a6000;border-radius:4px;padding:12px 14px;margin:8px 0">
        <div style="font-size:11px;color:var(--yellow);font-weight:600;margin-bottom:6px">The copilot needs your help to continue</div>
        <div style="font-size:11px;color:var(--txt);line-height:1.5;margin-bottom:8px;white-space:pre-wrap;word-break:break-word">${esc(payload.message || 'It is blocked and asked for guidance.')}</div>
        <textarea id="cp-guidance-answer" rows="2" placeholder="Answer (e.g. a value it needs, or how to proceed)..."
          style="width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--bdr);color:var(--txt);padding:7px 9px;border-radius:4px;font-size:12px;font-family:inherit;resize:vertical;margin-bottom:8px"></textarea>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="tbtn pri" onclick="cpAnswerGuidance('${sid}','continue')">Answer &amp; continue</button>
          <button class="tbtn" onclick="cpAnswerGuidance('${sid}','pause')">Answer &amp; pause</button>
          <button class="tbtn del" onclick="cpAnswerGuidance('${sid}','abort')">Abort run</button>
        </div>
      </div>`;
  }

  if (kind === 'auth') {
    return `<div style="background:#3a2d00;border:1px solid #7a6000;border-radius:4px;padding:12px 14px;margin:8px 0">
        <div style="font-size:11px;color:var(--yellow);font-weight:600;margin-bottom:6px">Login required</div>
        <div style="font-size:10px;color:var(--txt2);margin-bottom:10px">
          The target returned an auth wall (HTTP ${esc(String(payload.status || ''))}). Open a browser, log in,
          then click "Login done" — the captured session cookies are handed to the copilot to retry.
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="tbtn pri" onclick="cpOpenBrowser('${sid}')">Open Browser</button>
          <button class="tbtn" id="cp-login-done-btn" onclick="cpLoginDone('${sid}')" disabled>Login done — retry</button>
          <button class="tbtn del" onclick="cpResume('${sid}','auth',{cookies:{}})">Skip (no session)</button>
          <span id="cp-auth-msg" style="font-size:10px;color:var(--txt2);align-self:center"></span>
        </div>
      </div>`;
  }

  return '';
}

async function cpResume(sid, kind, value) {
  try {
    const r = await fetch(`/api/copilot/resume/${sid}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind, value }),
    });
    const d = await r.json();
    if (d.error) { showToast(d.error, true); return; }
    cpRefresh(sid);
  } catch (e) {
    showToast('Resume failed', true);
  }
}

async function cpOpenBrowser(sid) {
  const msgEl = document.getElementById('cp-auth-msg');
  const doneBtn = document.getElementById('cp-login-done-btn');
  if (msgEl) msgEl.textContent = 'Opening browser...';
  try {
    const r = await fetch(`/api/copilot/open-browser/${sid}`, { method: 'POST' });
    const d = await r.json();
    if (d.ok) {
      if (msgEl) msgEl.textContent = `Browser open at ${d.target_url || ''}. Log in, then click "Login done".`;
      if (doneBtn) doneBtn.disabled = false;
    } else {
      if (msgEl) msgEl.textContent = d.error || 'Failed to open browser';
    }
  } catch (e) {
    if (msgEl) msgEl.textContent = 'Request failed';
  }
}

// Hand the browser session to the copilot. The Set-Cookie responses from the
// login you did in the opened browser were ingested into the proxy's cookie jar
// (not into the header-less UI entry list), so the SERVER collects them for the
// paused host — we just ask it to. Mirrors the vuln-validator handoff.
async function cpLoginDone(sid) {
  const msgEl = document.getElementById('cp-auth-msg');
  const doneBtn = document.getElementById('cp-login-done-btn');
  if (doneBtn) doneBtn.disabled = true;
  if (msgEl) msgEl.textContent = 'Handing session to the copilot...';
  await cpResume(sid, 'auth', { from_jar: true, cookies: {} });
}

async function cpCancel() {
  if (!_cpActive) return;
  try {
    await fetch(`/api/copilot/cancel/${_cpActive}`, { method: 'POST' });
  } catch (e) { /* ignore */ }
  if (_cpPollTimer) { clearInterval(_cpPollTimer); _cpPollTimer = null; }
  cpSetComposerBusy(false);
  cpRefresh(_cpActive);
  cpLoadSessions();
}

function cpEnsurePulse() {
  if (document.getElementById('cp-pulse-style')) return;
  const s = document.createElement('style');
  s.id = 'cp-pulse-style';
  s.textContent = '@keyframes cp-pulse { 0%,100%{opacity:1} 50%{opacity:.3} }';
  document.head.appendChild(s);
}
