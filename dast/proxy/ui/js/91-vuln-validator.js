// ── Vuln Validator (AI/agentic mode) ────────────────────────────────────────
// The manual (single-shot) surface stays in 90-h1-interactions.js. This file adds
// the AI mode: it drives /api/vuln-validator/*, streams the agent's live trace over
// /ws/agent-triage, and renders the three human-in-the-loop pauses (approve / auth /
// question). vvSetMode toggles which surface the shared submit form talks to.

let _vvMode = 'manual';          // 'manual' | 'ai'
let _vvActiveJob = null;
let _vvPollTimer = null;
let _vvWs = null;

const _VV_TERMINAL = ['confirmed', 'not_confirmed', 'needs_manual', 'error', 'cancelled'];

function vvSetMode(mode) {
  _vvMode = mode === 'ai' ? 'ai' : 'manual';
  const isAi = _vvMode === 'ai';

  // Toggle the segmented control's active button.
  const mBtn = document.getElementById('vv-mode-manual');
  const aBtn = document.getElementById('vv-mode-ai');
  if (mBtn) mBtn.classList.toggle('pri', !isAi);
  if (aBtn) aBtn.classList.toggle('pri', isAi);

  // Swap the right-hand panel and hide manual-only inputs in AI mode.
  const manualResult = document.getElementById('vv-manual-result');
  const aiResult = document.getElementById('vv-ai-result');
  if (manualResult) manualResult.style.display = isAi ? 'none' : 'flex';
  if (aiResult) aiResult.style.display = isAi ? 'flex' : 'none';
  const manualOnly = document.getElementById('vv-manual-only');
  if (manualOnly) manualOnly.style.display = isAi ? 'none' : '';

  const hint = document.getElementById('vv-mode-hint');
  if (hint) hint.textContent = isAi
    ? 'Agentic reproduction: the AI iterates over the tool layer to exploit the issue, pausing for you on an out-of-scope host, an auth wall, or a question it cannot answer.'
    : 'Single-shot reproduction: parse the report and validate it once.';

  vvLoadJobs();
}

// Shared submit button — dispatch to the manual or the AI surface.
function vvValidate() {
  if (_vvMode === 'ai') return vvSubmit();
  return h1Submit();
}

// Shared "Recent validations" list — dispatch to the matching backend.
function vvLoadJobs() {
  if (_vvMode === 'ai') return vvLoadAgentJobs();
  return h1LoadJobs();
}

async function vvSubmit() {
  const text = document.getElementById('h1-report-text').value.trim();
  const msg = document.getElementById('h1-submit-msg');
  const btn = document.getElementById('h1-submit-btn');
  if (!text) { if (msg) msg.textContent = 'Paste a report first'; return; }

  btn.disabled = true;
  if (msg) msg.textContent = 'Starting agent...';

  const body = {
    report_text: text,
    override_url: document.getElementById('h1-override-url').value.trim(),
  };

  try {
    const r = await fetch('/api/vuln-validator/validate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body),
    });
    const d = await r.json();
    btn.disabled = false;
    if (d.error) { if (msg) msg.textContent = d.error; return; }
    if (msg) msg.textContent = '';
    _vvActiveJob = d.job_id;
    vvConnectWs();
    vvRefreshActive(d.job_id);
    vvStartPoll(d.job_id);
    vvLoadAgentJobs();
  } catch (e) {
    btn.disabled = false;
    if (msg) msg.textContent = 'Request failed';
  }
}

function vvStartPoll(job_id) {
  if (_vvPollTimer) clearInterval(_vvPollTimer);
  _vvPollTimer = setInterval(() => vvRefreshActive(job_id), 1500);
}

async function vvRefreshActive(job_id) {
  if (!job_id || job_id !== _vvActiveJob) return;
  try {
    const r = await fetch(`/api/vuln-validator/status/${job_id}`);
    if (!r.ok) return;
    const job = await r.json();
    vvRenderTrace(job);
    if (_VV_TERMINAL.includes(job.status)) {
      if (_vvPollTimer) { clearInterval(_vvPollTimer); _vvPollTimer = null; }
      vvLoadAgentJobs();
    }
  } catch (e) { /* ignore transient poll errors */ }
}

// Live WebSocket — nudges a refresh of the active job so the trace feels live
// between poll ticks. The server-side trace is the source of truth (status
// returns the full trace), so a nudge never double-renders.
function vvConnectWs() {
  if (_vvWs && (_vvWs.readyState === 0 || _vvWs.readyState === 1)) return;
  try {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    _vvWs = new WebSocket(`${proto}://${location.host}/ws/agent-triage`);
    _vvWs.onmessage = (ev) => {
      let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
      if (m && m.job_id && m.job_id === _vvActiveJob) vvRefreshActive(m.job_id);
    };
    _vvWs.onclose = () => { _vvWs = null; };
    _vvWs.onerror = () => { /* onclose will clear it */ };
  } catch (e) { _vvWs = null; }
}

async function vvLoadAgentJobs() {
  const el = document.getElementById('h1-job-list');
  if (!el) return;
  try {
    const r = await fetch('/api/vuln-validator/jobs');
    const jobs = await r.json();
    if (!jobs.length) {
      el.innerHTML = '<div style="padding:12px 14px;color:var(--txt2)">No agent runs yet</div>';
      return;
    }
    el.innerHTML = jobs.map(j => {
      const st = j.status;
      const col = st === 'confirmed' ? 'var(--red)' :
                  st === 'not_confirmed' ? 'var(--green)' :
                  st.indexOf('paused') === 0 ? 'var(--yellow)' :
                  st === 'error' ? 'var(--orange)' :
                  _VV_TERMINAL.includes(st) ? 'var(--txt2)' : 'var(--acc2)';
      const active = _vvActiveJob === j.job_id ? 'background:var(--sel);' : '';
      return `<div onclick="vvSelectJob('${esc(j.job_id)}')"
                   style="padding:7px 14px;cursor:pointer;border-bottom:1px solid var(--bdr);${active}">
        <div style="display:flex;gap:6px;align-items:center">
          <span style="color:${col};font-size:10px;font-weight:600;text-transform:uppercase">${esc(st)}</span>
          <span style="font-size:10px;color:var(--orange)">${esc(j.vuln_type || '?')}</span>
          <span style="font-size:9px;color:var(--txt2);margin-left:auto">${esc(j.job_id)}</span>
        </div>
        <div style="font-size:10px;color:var(--txt2);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
          ${esc(j.summary || j.proof_url || '(no url)')}
        </div>
      </div>`;
    }).join('');
  } catch (e) { /* ignore */ }
}

async function vvSelectJob(job_id) {
  _vvActiveJob = job_id;
  vvConnectWs();
  await vvRefreshActive(job_id);
  vvLoadAgentJobs();
  const r = await fetch(`/api/vuln-validator/status/${job_id}`);
  const job = await r.json();
  if (!_VV_TERMINAL.includes(job.status)) vvStartPoll(job_id);
}

// ── Trace + pause rendering ─────────────────────────────────────────────────
function vvRenderTrace(job) {
  const el = document.getElementById('vv-trace-panel');
  if (!el) return;
  if (!job || !job.job_id) {
    el.innerHTML = '<div style="color:var(--txt2);padding:40px;text-align:center">No run selected</div>';
    return;
  }

  const st = job.status;
  const stColor = st === 'confirmed' ? 'var(--red)' :
                  st === 'not_confirmed' ? 'var(--green)' :
                  st.indexOf('paused') === 0 ? 'var(--yellow)' :
                  st === 'error' ? 'var(--orange)' :
                  _VV_TERMINAL.includes(st) ? 'var(--txt2)' : 'var(--acc2)';
  const stLabel = {
    parsing:         'Parsing report...',
    running:         'Agent running...',
    paused_approve:  'Paused — approval needed',
    paused_auth:     'Paused — authentication needed',
    paused_question: 'Paused — question for you',
    confirmed:       'CONFIRMED — Vulnerability reproduced',
    not_confirmed:   'NOT CONFIRMED — Could not reproduce',
    needs_manual:    'Manual review needed',
    error:           'Error',
    cancelled:       'Cancelled',
  }[st] || st;

  const inProgress = !_VV_TERMINAL.includes(st);
  const cancellable = inProgress;

  const header = `
    <div style="margin-bottom:14px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
        ${inProgress ? '<div style="width:8px;height:8px;border-radius:50%;background:var(--acc2);animation:pulse 1s infinite"></div>' : ''}
        <span style="font-size:13px;font-weight:600;color:${stColor}">${esc(stLabel)}</span>
        <span style="font-size:10px;color:var(--orange);padding:1px 6px;background:var(--bg3);border-radius:3px">${esc(job.vuln_type || '?')}</span>
        <span style="font-size:9px;color:var(--txt2);margin-left:auto">${esc(job.job_id)}</span>
        ${cancellable ? `<button class="tbtn del" style="font-size:9px;padding:1px 7px" onclick="vvCancel('${esc(job.job_id)}')">Cancel</button>` : ''}
      </div>
      ${job.proof_url ? `<div style="font-size:10px;color:var(--acc2);word-break:break-all">${esc(job.proof_url)}</div>` : ''}
    </div>`;

  const trace = (job.trace || []).map(ev => vvRenderTraceEvent(ev)).filter(Boolean).join('');
  const traceHtml = trace
    ? `<div style="display:flex;flex-direction:column;gap:6px">${trace}</div>`
    : '<div style="font-size:10px;color:var(--txt2)">Waiting for the first step...</div>';

  const pauseHtml = job.pause ? vvRenderPause(job) : '';
  const verdictHtml = (job.verdict && _VV_TERMINAL.includes(st)) ? vvRenderVerdict(job.verdict) : '';

  el.innerHTML = header + pauseHtml + verdictHtml + traceHtml;
  vvEnsurePulse();

  // Keep the newest step in view while the run is live.
  if (inProgress) el.scrollTop = el.scrollHeight;
}

function vvRenderTraceEvent(ev) {
  const type = ev.type;
  if (type === 'step') {
    const action = ev.action || '';
    const aColor = action === 'finish' ? 'var(--green)' :
                   action === 'auth' ? 'var(--yellow)' :
                   action === 'ask_human' ? 'var(--acc2)' : 'var(--orange)';
    return `<div style="border-left:2px solid ${aColor};padding:4px 10px;background:var(--bg2);border-radius:0 3px 3px 0">
        <div style="display:flex;gap:6px;align-items:center">
          <span style="font-size:9px;color:var(--txt2)">step ${ev.step}</span>
          <span style="font-size:9px;font-weight:600;text-transform:uppercase;color:${aColor}">${esc(action)}</span>
        </div>
        ${ev.thought ? `<div style="font-size:11px;color:var(--txt);margin-top:2px">${esc(ev.thought)}</div>` : ''}
      </div>`;
  }
  if (type === 'observation') {
    return `<details style="margin-left:10px">
        <summary style="cursor:pointer;font-size:9px;color:var(--txt2)">observation (step ${ev.step})</summary>
        <pre style="margin-top:4px;padding:8px;background:#0a0a1a;border:1px solid var(--bdr);border-radius:3px;
             font-size:10px;overflow:auto;white-space:pre-wrap;color:#7ef7a0;max-height:180px">${esc(ev.observation || '')}</pre>
      </details>`;
  }
  return '';   // verdict/pause/resumed are rendered from job.pause/job.verdict
}

function vvRenderVerdict(v) {
  if (!v) return '';
  const parts = [];
  if (v.evidence) parts.push(`
    <div style="margin-bottom:8px">
      <div style="font-size:10px;color:var(--txt2);text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px">Evidence</div>
      <div style="background:var(--bg2);border:1px solid var(--bdr);border-radius:3px;padding:10px 12px;
                  font-size:11px;line-height:1.6;white-space:pre-wrap;word-break:break-word">${esc(v.evidence)}</div>
    </div>`);
  if (v.reasoning) parts.push(`
    <div style="margin-bottom:8px;font-size:11px;color:var(--txt2);line-height:1.5">${esc(v.reasoning)}</div>`);
  const sev = v.severity ? `<span style="font-size:10px;color:var(--red);padding:1px 6px;background:var(--bg3);border-radius:3px">${esc(v.severity)}</span>` : '';
  return `<div style="margin-bottom:14px">${sev ? `<div style="margin-bottom:6px">${sev}</div>` : ''}${parts.join('')}</div>`;
}

function vvRenderPause(job) {
  const kind = job.pause.kind;
  const payload = job.pause.payload || {};
  const jid = esc(job.job_id);

  if (kind === 'approve') {
    return `
      <div style="background:#3a2d00;border:1px solid #7a6000;border-radius:4px;padding:12px 14px;margin-bottom:14px">
        <div style="font-size:11px;color:var(--yellow);font-weight:600;margin-bottom:6px">Out-of-scope host — authorize?</div>
        <div style="font-size:10px;color:var(--txt2);margin-bottom:4px">
          The agent wants to send a <code style="color:var(--orange)">${esc(payload.method || 'GET')}</code>
          via <code style="color:var(--orange)">${esc(payload.tool || 'tool')}</code> to a host that is not in scope:
        </div>
        <code style="display:block;font-size:10px;background:var(--bg2);padding:6px 8px;border-radius:3px;
              word-break:break-all;margin-bottom:10px">${esc(payload.url || payload.host || '')}</code>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="tbtn del" onclick="vvResume('${jid}','approve',{decision:'deny'})">Deny</button>
          <button class="tbtn" onclick="vvResume('${jid}','approve',{decision:'allow_once'})">Allow once</button>
          <button class="tbtn pri" onclick="vvResume('${jid}','approve',{decision:'always_host'})">Always allow host</button>
        </div>
      </div>`;
  }

  if (kind === 'auth') {
    return `
      <div style="background:#3a2d00;border:1px solid #7a6000;border-radius:4px;padding:12px 14px;margin-bottom:14px">
        <div style="font-size:11px;color:var(--yellow);font-weight:600;margin-bottom:6px">Login required</div>
        <div style="font-size:10px;color:var(--txt2);margin-bottom:10px">
          The target returned an auth wall (HTTP ${esc(String(payload.status || ''))}). Open a browser, log in,
          then click "Login done" — the captured session cookies are handed to the agent to retry.
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="tbtn pri" onclick="vvOpenBrowser('${jid}')">Open Browser</button>
          <button class="tbtn" id="vv-login-done-btn" onclick="vvLoginDone('${jid}')" disabled>Login done — retry</button>
          <button class="tbtn del" onclick="vvResume('${jid}','auth',{cookies:{}})">Skip (no session)</button>
          <span id="vv-auth-msg" style="font-size:10px;color:var(--txt2);align-self:center"></span>
        </div>
      </div>`;
  }

  if (kind === 'question') {
    return `
      <div style="background:#1a2a3a;border:1px solid #2a5a8a;border-radius:4px;padding:12px 14px;margin-bottom:14px">
        <div style="font-size:11px;color:#7eb8f7;font-weight:600;margin-bottom:6px">The agent needs your input</div>
        <div style="font-size:11px;color:var(--txt);margin-bottom:8px;line-height:1.5">${esc(payload.question || '')}</div>
        <div style="display:flex;gap:8px">
          <input id="vv-question-input" placeholder="Type your answer..."
            onkeydown="if(event.key==='Enter')vvAnswerQuestion('${jid}')"
            style="flex:1;background:var(--bg);border:1px solid var(--bdr);color:var(--txt);
                   padding:5px 8px;border-radius:3px;font-size:11px;font-family:inherit">
          <button class="tbtn pri" onclick="vvAnswerQuestion('${jid}')">Send</button>
        </div>
      </div>`;
  }

  return '';
}

// ── Pause resolution ─────────────────────────────────────────────────────────
async function vvResume(job_id, kind, value) {
  try {
    const r = await fetch(`/api/vuln-validator/resume/${job_id}`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ kind, value }),
    });
    const d = await r.json();
    if (d.error) { showToast(d.error, true); return; }
    vvRefreshActive(job_id);
  } catch (e) {
    showToast('Resume failed', true);
  }
}

function vvAnswerQuestion(job_id) {
  const input = document.getElementById('vv-question-input');
  const text = input ? input.value.trim() : '';
  vvResume(job_id, 'question', { text });
}

async function vvOpenBrowser(job_id) {
  const msgEl = document.getElementById('vv-auth-msg');
  const doneBtn = document.getElementById('vv-login-done-btn');
  if (msgEl) msgEl.textContent = 'Opening browser...';
  try {
    const r = await fetch(`/api/vuln-validator/open-browser/${job_id}`, { method: 'POST' });
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

// Collect Set-Cookie values captured by the proxy for the target domain and hand
// them to the agent as the session. Mirrors the manual h1LoginDone flow.
async function vvLoginDone(job_id) {
  const msgEl = document.getElementById('vv-auth-msg');
  const doneBtn = document.getElementById('vv-login-done-btn');
  if (doneBtn) doneBtn.disabled = true;
  if (msgEl) msgEl.textContent = 'Collecting session cookies...';

  const job = await (await fetch(`/api/vuln-validator/status/${job_id}`)).json();
  const targetDomain = job.target_url ? (() => { try { return new URL(job.target_url).hostname; } catch (e) { return ''; } })() : '';

  const cookies = {};
  if (targetDomain && typeof order !== 'undefined' && typeof entries !== 'undefined') {
    for (const eid of order) {
      const entry = entries[eid];
      if (!entry || !entry.host) continue;
      if (!entry.host.includes(targetDomain) && !targetDomain.includes(entry.host)) continue;
      const setCookie = entry.response_headers?.['set-cookie'] || '';
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
  }

  if (msgEl) msgEl.textContent = `Sending ${Object.keys(cookies).length} cookies to the agent...`;
  await vvResume(job_id, 'auth', { cookies });
}

async function vvCancel(job_id) {
  try {
    await fetch(`/api/vuln-validator/cancel/${job_id}`, { method: 'POST' });
  } catch (e) { /* ignore */ }
  if (_vvPollTimer) { clearInterval(_vvPollTimer); _vvPollTimer = null; }
  vvRefreshActive(job_id);
  vvLoadAgentJobs();
}

function vvEnsurePulse() {
  if (document.getElementById('h1-pulse-style')) return;
  const s = document.createElement('style');
  s.id = 'h1-pulse-style';
  s.textContent = '@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }';
  document.head.appendChild(s);
}

// Default the segmented control to Manual on load. This script is included near
// the end of <body>, so DOMContentLoaded may already have fired — apply directly
// in that case, otherwise wait for it.
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => vvSetMode('manual'));
} else {
  vvSetMode('manual');
}
