// ── H1 Validator ───────────────────────────────────────────────────────────
let _h1Images = [];   // [{name, b64}]
let _h1PollTimer = null;
let _h1ActiveJob = null;

function h1AddImages(input) {
  const files = Array.from(input.files).slice(0, 4 - _h1Images.length);
  const promises = files.map(f => new Promise(resolve => {
    const reader = new FileReader();
    reader.onload = e => {
      // Strip the data:image/...;base64, prefix
      const b64 = e.target.result.split(',')[1];
      _h1Images.push({ name: f.name, b64 });
      resolve();
    };
    reader.readAsDataURL(f);
  }));
  Promise.all(promises).then(() => {
    document.getElementById('h1-img-count').textContent =
      _h1Images.length ? `${_h1Images.length} image(s) attached` : 'No images';
    document.getElementById('h1-img-clear').style.display = _h1Images.length ? '' : 'none';
  });
  input.value = '';
}

function h1ClearImages() {
  _h1Images = [];
  document.getElementById('h1-img-count').textContent = 'No images';
  document.getElementById('h1-img-clear').style.display = 'none';
}

async function h1Submit() {
  const text = document.getElementById('h1-report-text').value.trim();
  if (!text) { document.getElementById('h1-submit-msg').textContent = 'Paste a report first'; return; }

  const btn = document.getElementById('h1-submit-btn');
  const msg = document.getElementById('h1-submit-msg');
  btn.disabled = true;
  msg.textContent = 'Submitting...';

  const body = {
    report_text: text,
    override_url: document.getElementById('h1-override-url').value.trim(),
    override_domain: document.getElementById('h1-override-domain').value.trim(),
    images: _h1Images.map(i => i.b64),
  };

  try {
    const r = await fetch('/api/h1/validate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (d.error) {
      msg.textContent = d.error;
      btn.disabled = false;
      return;
    }
    msg.textContent = '';
    btn.disabled = false;
    _h1ActiveJob = d.job_id;
    h1RenderResult({ job_id: d.job_id, status: 'parsing', vuln_type: '', proof_url: '', summary: '' });
    h1StartPoll(d.job_id);
    h1LoadJobs();
  } catch(e) {
    msg.textContent = 'Request failed';
    btn.disabled = false;
  }
}

function h1StartPoll(job_id) {
  if (_h1PollTimer) clearInterval(_h1PollTimer);
  _h1PollTimer = setInterval(async () => {
    const r = await fetch(`/api/h1/status/${job_id}`);
    const d = await r.json();
    h1RenderResult(d);
    if (['confirmed','not_confirmed','error','cancelled','needs_manual'].includes(d.status)) {
      clearInterval(_h1PollTimer); _h1PollTimer = null;
      h1LoadJobs();
    }
  }, 1500);
}

async function h1LoadJobs() {
  try {
    const r = await fetch('/api/h1/jobs');
    const jobs = await r.json();
    const el = document.getElementById('h1-job-list');
    if (!jobs.length) { el.innerHTML = '<div style="padding:12px 14px;color:var(--txt2)">No jobs yet</div>'; return; }
    el.innerHTML = jobs.map(j => {
      const st = j.status;
      const col = st === 'confirmed' ? 'var(--red)' :
                  st === 'not_confirmed' ? 'var(--green)' :
                  st === 'needs_auth' || st === 'awaiting_auth' ? 'var(--yellow)' :
                  st === 'error' ? 'var(--orange)' : 'var(--txt2)';
      const active = _h1ActiveJob === j.job_id ? 'background:var(--sel);' : '';
      return `<div onclick="h1SelectJob('${esc(j.job_id)}')"
                   style="padding:7px 14px;cursor:pointer;border-bottom:1px solid var(--bdr);${active}">
        <div style="display:flex;gap:6px;align-items:center">
          <span style="color:${col};font-size:10px;font-weight:600;text-transform:uppercase">${esc(st)}</span>
          <span style="font-size:10px;color:var(--orange)">${esc(j.vuln_type||'?')}</span>
          <span style="font-size:9px;color:var(--txt2);margin-left:auto">${j.job_id}</span>
        </div>
        <div style="font-size:10px;color:var(--txt2);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
          ${esc(j.summary || j.proof_url || '(no url)')}
        </div>
      </div>`;
    }).join('');
  } catch(e) { /* ignore */ }
}

async function h1SelectJob(job_id) {
  _h1ActiveJob = job_id;
  if (_h1PollTimer) { clearInterval(_h1PollTimer); _h1PollTimer = null; }
  const r = await fetch(`/api/h1/status/${job_id}`);
  const d = await r.json();
  h1RenderResult(d);
  if (['parsing','validating','analysing_images','awaiting_auth'].includes(d.status)) {
    h1StartPoll(job_id);
  }
}

function h1RenderResult(job) {
  const el = document.getElementById('h1-result-panel');
  if (!job || !job.job_id) { el.innerHTML = '<div style="color:var(--txt2);padding:40px;text-align:center">No result</div>'; return; }

  const st = job.status;
  const stColor = st === 'confirmed'     ? 'var(--red)'   :
                  st === 'not_confirmed' ? 'var(--green)'  :
                  st === 'needs_auth' || st === 'awaiting_auth' ? 'var(--yellow)' :
                  st === 'error'         ? 'var(--orange)' :
                  'var(--txt2)';

  const stLabel = {
    parsing:         'Parsing report...',
    analysing_images:'Analysing images...',
    validating:      'Validating...',
    needs_auth:      'Authentication required',
    awaiting_auth:   'Waiting for login...',
    confirmed:       'CONFIRMED — Vulnerability is real',
    not_confirmed:   'NOT CONFIRMED — Could not reproduce',
    needs_manual:    'Manual review needed',
    error:           'Error',
    cancelled:       'Cancelled',
  }[st] || st;

  const res = job.result || {};
  const inProgress = ['parsing','analysing_images','validating','awaiting_auth'].includes(st);
  // Cancel is only meaningful before the job reaches a terminal state — that is
  // when task.cancel() actually aborts running work. On a finished job it was a
  // no-op that merely relabelled the result, so we hide it there.
  const cancellable = !['confirmed','not_confirmed','needs_manual','error','cancelled'].includes(st);

  // SSRF OOB waiting panel — shown while polling interactsh
  let oobSection = '';
  if (st === 'validating' && job.oob_url) {
    const safeOob = esc(job.oob_url);
    oobSection = `
      <div style="background:#0d2a0d;border:1px solid #2a6a2a;border-radius:4px;padding:12px 14px;margin:10px 0">
        <div style="font-size:11px;color:#7ef07e;font-weight:600;margin-bottom:6px">Waiting for OOB callback (interactsh)</div>
        <div style="font-size:10px;color:var(--txt2);margin-bottom:8px">
          Polling <strong style="color:var(--txt)">${safeOob}</strong> for 120s.<br>
          Re-trigger the SSRF on the target using this URL as the callback — it will auto-confirm when the hit arrives.
        </div>
        <div style="display:flex;gap:6px;align-items:center">
          <code style="font-size:10px;background:var(--bg2);padding:3px 7px;border-radius:3px;flex:1;overflow:auto;white-space:nowrap">${safeOob}</code>
          <button class="tbtn" onclick="navigator.clipboard.writeText('${safeOob}')">Copy</button>
        </div>
      </div>`;
  }

  let authSection = '';
  if (st === 'needs_auth') {
    authSection = `
      <div style="background:#3a2d00;border:1px solid #7a6000;border-radius:4px;padding:12px 14px;margin:12px 0">
        <div style="font-size:11px;color:var(--yellow);font-weight:600;margin-bottom:6px">Login required to validate</div>
        <div style="font-size:10px;color:var(--txt2);margin-bottom:10px">
          The target requires authentication. Click "Open Browser" to launch a browser session,
          log in manually, then click "Login done — retry".
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="tbtn pri" onclick="h1OpenBrowser('${esc(job.job_id)}')">Open Browser</button>
          <button class="tbtn" id="h1-login-done-btn" onclick="h1LoginDone('${esc(job.job_id)}')" disabled>Login done — retry</button>
          <span id="h1-auth-msg" style="font-size:10px;color:var(--txt2);align-self:center"></span>
        </div>
      </div>`;
  } else if (st === 'needs_manual') {
    authSection = `
      <div style="background:#1a2a3a;border:1px solid #2a5a8a;border-radius:4px;padding:12px 14px;margin:12px 0">
        <div style="font-size:11px;color:#7eb8f7;font-weight:600;margin-bottom:6px">Manual confirmation required</div>
        <div style="font-size:10px;color:var(--txt2)">
          Automatic validation could not reach sufficient confidence. Follow the steps in the evidence below to confirm manually.
        </div>
      </div>`;
  }

  let screenshotSection = '';
  if (res.screenshot_b64) {
    // Strip any non-base64 chars before embedding to prevent attribute injection
    const safeB64 = String(res.screenshot_b64).replace(/[^A-Za-z0-9+/=]/g, '');
    screenshotSection = `
      <details style="margin-top:10px">
        <summary style="cursor:pointer;font-size:10px;color:var(--txt2)">Screenshot</summary>
        <img src="data:image/png;base64,${safeB64}" style="max-width:100%;margin-top:6px;border:1px solid var(--bdr);border-radius:3px">
      </details>`;
  }

  let requestSection = '';
  if (res.raw_request || res.raw_response) {
    requestSection = `
      <details style="margin-top:8px">
        <summary style="cursor:pointer;font-size:10px;color:var(--txt2)">HTTP Request / Response</summary>
        ${res.raw_request ? `<pre style="margin-top:6px;padding:8px;background:#0a0a1a;border:1px solid var(--bdr);
              border-radius:3px;font-size:10px;overflow:auto;white-space:pre-wrap;color:#7eb8f7;max-height:200px">${esc(res.raw_request)}</pre>` : ''}
        ${res.raw_response ? `<pre style="margin-top:4px;padding:8px;background:#0a1a0a;border:1px solid var(--bdr);
              border-radius:3px;font-size:10px;overflow:auto;white-space:pre-wrap;color:#7ef7a0;max-height:200px">${esc(res.raw_response)}</pre>` : ''}
      </details>`;
  }

  const checksHtml = (res.checks_run || []).length
    ? `<div style="margin-top:6px;font-size:10px;color:var(--txt2)">Checks: ${res.checks_run.map(c => `<code style="color:var(--orange)">${esc(c)}</code>`).join(' → ')}</div>`
    : '';

  el.innerHTML = `
    <div style="margin-bottom:14px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
        ${inProgress ? `<div style="width:8px;height:8px;border-radius:50%;background:var(--acc2);animation:pulse 1s infinite"></div>` : ''}
        <span style="font-size:13px;font-weight:600;color:${stColor}">${esc(stLabel)}</span>
        <span style="font-size:10px;color:var(--orange);padding:1px 6px;background:var(--bg3);border-radius:3px">${esc(job.vuln_type||'?')}</span>
        <span style="font-size:9px;color:var(--txt2);margin-left:auto">${job.job_id}</span>
        ${cancellable ? `<button class="tbtn del" style="font-size:9px;padding:1px 7px" onclick="h1Cancel('${esc(job.job_id)}')">Cancel</button>` : ''}
      </div>
      ${job.summary ? `<div style="font-size:11px;color:var(--txt2);margin-bottom:4px">${esc(job.summary)}</div>` : ''}
      ${job.proof_url ? `<div style="font-size:10px;color:var(--acc2);word-break:break-all">${esc(job.proof_url)}</div>` : ''}
      ${job.payload ? `<div style="margin-top:4px;font-size:10px;color:var(--txt2)">Payload: <code style="color:var(--orange)">${esc(job.payload)}</code></div>` : ''}
    </div>

    ${oobSection}
    ${authSection}

    ${res.evidence ? `
      <div style="margin-bottom:10px">
        <div style="font-size:10px;color:var(--txt2);text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px">Evidence</div>
        <div style="background:var(--bg2);border:1px solid var(--bdr);border-radius:3px;padding:10px 12px;
                    font-size:11px;line-height:1.6;white-space:pre-wrap;word-break:break-word">${esc(res.evidence)}</div>
      </div>` : ''}

    ${checksHtml}
    ${screenshotSection}
    ${requestSection}
  `;

  // Style pulse animation if not already in <style>
  if (!document.getElementById('h1-pulse-style')) {
    const s = document.createElement('style');
    s.id = 'h1-pulse-style';
    s.textContent = '@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }';
    document.head.appendChild(s);
  }
}

async function h1OpenBrowser(job_id) {
  const msgEl = document.getElementById('h1-auth-msg');
  const doneBtn = document.getElementById('h1-login-done-btn');
  if (msgEl) msgEl.textContent = 'Opening browser...';
  try {
    const r = await fetch(`/api/h1/open-browser/${job_id}`, { method: 'POST' });
    const d = await r.json();
    if (d.ok) {
      if (msgEl) msgEl.textContent = `Browser open at ${d.target_url || ''}. Log in then click "Login done".`;
      if (doneBtn) doneBtn.disabled = false;
      // Start collecting cookies from the proxy session
      _h1CollectCookies(job_id);
    } else {
      if (msgEl) msgEl.textContent = d.error || 'Failed to open browser';
    }
  } catch(e) {
    if (msgEl) msgEl.textContent = 'Request failed';
  }
}

// Collect cookies from recently-captured proxy entries for the target domain
function _h1CollectCookies(job_id) {
  // The proxy has already captured traffic; cookies are attached to entries.
  // We pass them when the user signals login is done.
  window._h1PendingJobId = job_id;
}

async function h1LoginDone(job_id) {
  const msgEl = document.getElementById('h1-auth-msg');
  const doneBtn = document.getElementById('h1-login-done-btn');
  if (doneBtn) doneBtn.disabled = true;
  if (msgEl) msgEl.textContent = 'Sending session cookies...';

  // Collect Set-Cookie values from proxy entries for this domain
  const job = await (await fetch(`/api/h1/status/${job_id}`)).json();
  const targetDomain = job.target_url ? new URL(job.target_url).hostname : '';

  // Pull cookies from recent proxy entries for matching domain
  const cookies = {};
  if (targetDomain) {
    for (const eid of order) {
      const entry = entries[eid];
      if (!entry || !entry.host) continue;
      if (!entry.host.includes(targetDomain) && !targetDomain.includes(entry.host)) continue;
      const setCookie = entry.response_headers?.['set-cookie'] || '';
      if (setCookie) {
        for (const part of setCookie.split(';')) {
          const eq = part.trim().indexOf('=');
          if (eq > 0) {
            const name = part.trim().slice(0, eq).trim();
            const val  = part.trim().slice(eq + 1).trim();
            if (name && val && !['path','domain','expires','samesite','secure','httponly'].includes(name.toLowerCase())) {
              cookies[name] = val;
            }
          }
        }
      }
    }
  }

  try {
    const r = await fetch(`/api/h1/browser-ready/${job_id}`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ cookies }),
    });
    const d = await r.json();
    if (d.ok) {
      if (msgEl) msgEl.textContent = `Session sent (${Object.keys(cookies).length} cookies). Re-validating...`;
      h1StartPoll(job_id);
    } else {
      if (msgEl) msgEl.textContent = d.error || 'Failed';
      if (doneBtn) doneBtn.disabled = false;
    }
  } catch(e) {
    if (msgEl) msgEl.textContent = 'Request failed';
    if (doneBtn) doneBtn.disabled = false;
  }
}

async function h1Cancel(job_id) {
  await fetch(`/api/h1/cancel/${job_id}`, { method: 'POST' });
  if (_h1PollTimer) { clearInterval(_h1PollTimer); _h1PollTimer = null; }
  h1LoadJobs();
}

// ── Interactions ───────────────────────────────────────────────────────────
let _interactionsSelectedId = null;
let _interactionsSelectedCbIdx = null;  // keep the open raw callback across refreshes
let _interactionsSessions = {};

function _interactionsBadgeSet() {
  const badge = document.getElementById('interactions-badge');
  if (badge) badge.style.display = '';
}

function _interactionsBadgeClear() {
  const badge = document.getElementById('interactions-badge');
  if (badge) badge.style.display = 'none';
}

function _interactionsRelTime(ts) {
  if (!ts) return '';
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 60)   return diff + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  return Math.floor(diff / 3600) + 'h ago';
}

// Duration between two epoch-second timestamps, as a short "Xs / Xm / Xh"
// label. Used to freeze a stopped session's age at the moment it was stopped
// instead of letting the "ago" counter keep climbing.
function _interactionsDuration(fromTs, toTs) {
  if (!fromTs || !toTs) return '';
  const diff = Math.max(0, Math.floor(toTs - fromTs));
  if (diff < 60)   return diff + 's';
  if (diff < 3600) return Math.floor(diff / 60) + 'm';
  return Math.floor(diff / 3600) + 'h';
}

function _interactionsCbTypeColor(type) {
  if (type === 'http') return 'var(--blue)';
  if (type === 'dns')  return 'var(--green)';
  return 'var(--txt2)';
}

// The raw callback is an interactsh JSON blob whose embedded HTTP/DNS payloads
// carry literal "\r\n" escapes that render as one unreadable line. Turn it into
// a human-readable interaction: a summary header, then the decoded request /
// response with real line breaks. Falls back to pretty JSON, then to the raw
// text — never throws, never loses the original.
function _interactionsFormatRaw(raw) {
  if (!raw) return '(empty)';
  let obj;
  try {
    obj = JSON.parse(raw);
  } catch (e) {
    return raw;   // not JSON — show verbatim
  }

  const proto = (obj.protocol || '').toLowerCase();
  const lines = [];
  const add = (label, val) => { if (val) lines.push(label.padEnd(12) + ' ' + val); };

  add('Protocol', (obj.protocol || 'unknown').toUpperCase());
  add('Remote', obj['remote-address']);
  add('Timestamp', obj.timestamp);
  if (proto === 'dns') add('Query type', obj['q-type']);

  // interactsh escapes CRLF as the two-character sequence "\r\n" (and "\n"/"\t")
  // inside raw-request/raw-response/raw. Decode to real whitespace so headers
  // and bodies read as an actual HTTP message.
  const decode = (s) => String(s)
    .replace(/\\r\\n/g, '\n')
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\n')
    .replace(/\\t/g, '\t');

  const req  = obj['raw-request'];
  const resp = obj['raw-response'];
  const bare = obj.raw;

  const sections = [lines.join('\n')];
  if (req)  sections.push('--- Request ---\n' + decode(req).trimEnd());
  if (resp) sections.push('--- Response ---\n' + decode(resp).trimEnd());
  if (!req && !resp && bare) sections.push('--- Raw ---\n' + decode(bare).trimEnd());

  // Nothing structured to show? fall back to pretty JSON.
  if (sections.length === 1 && !lines.length) {
    return JSON.stringify(obj, null, 2);
  }
  return sections.join('\n\n');
}

// Manual refresh — reload sessions and the selected session's callbacks from
// the server on demand, without waiting for the 3s auto-poll tick. The
// interactsh polling itself is server-side; this just re-pulls the latest.
async function interactionsRefresh(btn) {
  if (btn) btn.disabled = true;
  try {
    await interactionsLoadSessions();
    if (_interactionsSelectedId) {
      try {
        const r = await fetch('/api/interactions/' + _interactionsSelectedId);
        const s = await r.json();
        if (s && s.session_id) {
          _interactionsSessions[s.session_id] = s;
          _interactionsRenderCallbacks(s.session_id);
        }
      } catch(e) { /* ignore */ }
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function interactionsCreate() {
  const btn = document.querySelector('#extras-sub-interactions .tbtn.pri');
  if (btn) btn.disabled = true;
  try {
    const r = await fetch('/api/interactions/new', { method: 'POST' });
    const d = await r.json().catch(() => ({}));
    if (r.status === 503) {
      showToast('OOB service unavailable — no interactsh server could be reached. Check network/proxy and retry.', true);
      return;
    }
    if (d.error) { showToast(d.error, true); return; }
    if (!d.oob_url) { showToast('Session created but no callback URL was returned. Try again.', true); return; }
    showToast('Interaction URL ready: ' + d.oob_url);
    await interactionsLoadSessions();
    _interactionsSelectSession(d.session_id);
  } catch(e) {
    showToast('Could not reach the server to create an OOB session. Check that the proxy is running.', true);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function interactionsLoadSessions() {
  try {
    const r = await fetch('/api/interactions');
    const sessions = await r.json();
    const listEl = document.getElementById('interactions-session-list');
    if (!listEl) return;
    _interactionsSessions = {};
    sessions.forEach(s => { _interactionsSessions[s.session_id] = s; });

    if (!sessions.length) {
      listEl.innerHTML = '<div class="empty">No sessions yet — click Generate URL to start.</div>';
      return;
    }

    listEl.innerHTML = sessions.map(s => {
      const isSelected = s.session_id === _interactionsSelectedId;
      const cbCount = (s.callbacks || []).length;
      const activeDot = s.active
        ? '<span style="display:inline-block;width:7px;height:7px;border-radius:50%;' +
          'background:var(--green);animation:pulse 1s infinite;margin-right:6px;flex-shrink:0"></span>'
        : '<span style="display:inline-block;width:7px;height:7px;border-radius:50%;' +
          'background:var(--bdr);margin-right:6px;flex-shrink:0"></span>';
      const bg = isSelected ? 'background:var(--sel);' : '';
      const cbBadge = cbCount > 0
        ? '<span style="font-size:9px;font-weight:700;padding:1px 6px;border-radius:8px;' +
          'background:#3d0000;color:var(--red);flex-shrink:0">' + cbCount + '</span>'
        : '<span style="font-size:9px;color:var(--txt2);flex-shrink:0">0</span>';
      // For a stopped session freeze the age at the moment it stopped ("ran 34s")
      // instead of a live "ago" counter that keeps climbing after it is dead.
      const timeLabel = (!s.active && s.stopped_at)
        ? 'ran ' + _interactionsDuration(s.created_at, s.stopped_at)
        : _interactionsRelTime(s.created_at);
      const timeColor = (!s.active) ? 'var(--txt3, var(--txt2))' : 'var(--txt2)';

      const actionBtn = s.active
        ? '<button class="tbtn" style="font-size:9px;padding:2px 8px;flex-shrink:0" ' +
          'title="Stop polling, keep received callbacks" ' +
          'onclick="event.stopPropagation();interactionsStop(\'' + esc(s.session_id) + '\')">Stop</button>'
        : '<span style="font-size:9px;color:var(--txt2);flex-shrink:0;' +
          'padding:2px 4px;text-transform:uppercase;letter-spacing:.4px" ' +
          'title="Polling stopped">stopped</span>';

      // Keep the destructive Remove well clear of Stop (a divider + margin) so a
      // mis-click cannot discard callbacks when the operator meant to stop.
      const removeBtn =
        '<span style="width:1px;height:16px;background:var(--bdr);flex-shrink:0;margin:0 2px"></span>' +
        '<button class="tbtn del" style="font-size:11px;line-height:1;padding:2px 7px;flex-shrink:0" ' +
        'title="Remove session and discard its callbacks" ' +
        'onclick="event.stopPropagation();interactionsDelete(\'' + esc(s.session_id) + '\')">&times;</button>';

      return '<div onclick="interactionsSelectSessionClick(\'' + esc(s.session_id) + '\')" ' +
             'style="padding:7px 12px;cursor:pointer;border-bottom:1px solid var(--bdr);' +
             'display:flex;align-items:center;gap:8px;' + bg + '">' +
             activeDot +
             '<code style="flex:1;font-size:10px;color:var(--txt);overflow:hidden;' +
             'text-overflow:ellipsis;white-space:nowrap">' + esc(s.oob_url) + '</code>' +
             '<button class="tbtn" style="font-size:9px;padding:2px 8px;flex-shrink:0" ' +
             'onclick="event.stopPropagation();interactionsCopyUrl(\'' + esc(s.oob_url) + '\')">Copy</button>' +
             '<span style="font-size:10px;color:' + timeColor + ';white-space:nowrap;flex-shrink:0">' +
             timeLabel + '</span>' +
             cbBadge +
             actionBtn +
             removeBtn +
             '</div>';
    }).join('');
  } catch(e) { /* ignore */ }
}

function interactionsSelectSessionClick(session_id) {
  _interactionsSelectSession(session_id);
}

function _interactionsSelectSession(session_id) {
  if (_interactionsSelectedId !== session_id) _interactionsSelectedCbIdx = null;
  _interactionsSelectedId = session_id;
  interactionsLoadSessions();
  _interactionsRenderCallbacks(session_id);
}

function _interactionsRenderCallbacks(session_id) {
  const titleEl  = document.getElementById('interactions-cb-title');
  const listEl   = document.getElementById('interactions-cb-list');
  const rawPanel = document.getElementById('interactions-raw-panel');
  if (!listEl) return;

  const session = _interactionsSessions[session_id];
  if (!session) {
    if (titleEl) titleEl.textContent = 'Callbacks';
    listEl.innerHTML = '<div class="empty">Select a session to see its callbacks.</div>';
    if (rawPanel) rawPanel.style.display = 'none';
    _interactionsSelectedCbIdx = null;
    return;
  }

  if (titleEl) titleEl.textContent = 'Callbacks for ' + session.oob_url;

  const callbacks = session.callbacks || [];
  if (!callbacks.length) {
    listEl.innerHTML = '<div class="empty">No callbacks yet — trigger the SSRF/XXE/injection to receive interactions.</div>';
    if (rawPanel) rawPanel.style.display = 'none';
    _interactionsSelectedCbIdx = null;
    return;
  }

  const rows = callbacks.map((cb, idx) =>
    '<tr onclick="interactionsShowRaw(' + idx + ',\'' + esc(session_id) + '\')" ' +
    'class="interactions-cb-row" data-idx="' + idx + '" ' +
    'style="cursor:pointer;border-bottom:1px solid #252525">' +
    '<td style="padding:4px 8px;font-size:10px;color:var(--txt2);white-space:nowrap">' +
    _interactionsRelTime(cb.received_at) + '</td>' +
    '<td style="padding:4px 8px;font-size:10px;font-weight:600;' +
    'color:' + _interactionsCbTypeColor(cb.type) + ';white-space:nowrap">' +
    esc(cb.type) + '</td>' +
    '<td style="padding:4px 8px;font-size:10px;color:var(--txt);' +
    'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace">' +
    esc((cb.raw || '').slice(0, 80)) + '</td>' +
    '</tr>'
  ).join('');

  listEl.innerHTML =
    '<table style="width:100%;border-collapse:collapse;table-layout:fixed">' +
    '<thead style="position:sticky;top:0;z-index:2;background:var(--bg2)">' +
    '<tr>' +
    '<th style="width:110px;padding:4px 8px;text-align:left;color:var(--txt2);font-weight:400;' +
    'border-bottom:1px solid var(--bdr);font-size:10px;text-transform:uppercase;letter-spacing:.4px">Time</th>' +
    '<th style="width:60px;padding:4px 8px;text-align:left;color:var(--txt2);font-weight:400;' +
    'border-bottom:1px solid var(--bdr);font-size:10px;text-transform:uppercase;letter-spacing:.4px">Type</th>' +
    '<th style="padding:4px 8px;text-align:left;color:var(--txt2);font-weight:400;' +
    'border-bottom:1px solid var(--bdr);font-size:10px;text-transform:uppercase;letter-spacing:.4px">Preview</th>' +
    '</tr></thead>' +
    '<tbody>' + rows + '</tbody></table>';

  // Re-open the raw callback the operator was viewing so a 3s auto-refresh
  // does not snatch it away mid-read. Clear only if it no longer exists.
  if (_interactionsSelectedCbIdx != null && callbacks[_interactionsSelectedCbIdx]) {
    interactionsShowRaw(_interactionsSelectedCbIdx, session_id);
  } else {
    if (rawPanel) rawPanel.style.display = 'none';
    _interactionsSelectedCbIdx = null;
  }
}

function interactionsShowRaw(idx, session_id) {
  const rawPanel = document.getElementById('interactions-raw-panel');
  const rawPre   = document.getElementById('interactions-raw-pre');
  document.querySelectorAll('.interactions-cb-row').forEach((r, i) => {
    r.style.background = i === idx ? 'var(--sel)' : '';
  });
  const session = _interactionsSessions[session_id];
  if (!session) return;
  const cb = (session.callbacks || [])[idx];
  if (!cb) return;
  _interactionsSelectedCbIdx = idx;
  if (rawPanel) rawPanel.style.display = '';
  if (rawPre)   rawPre.textContent = _interactionsFormatRaw(cb.raw);
}

function interactionsCopyUrl(url) {
  navigator.clipboard.writeText(url).then(() => showToast('URL copied'));
}

// Stop polling but KEEP the session and everything it already captured, so
// the operator can still review the received interactions.
async function interactionsStop(session_id) {
  try {
    const r = await fetch('/api/interactions/' + session_id + '/stop', { method: 'POST' });
    if (!r.ok) { showToast('Failed to stop session', true); return; }
    if (_interactionsSessions[session_id]) _interactionsSessions[session_id].active = false;
    await interactionsLoadSessions();
    if (_interactionsSelectedId === session_id) _interactionsRenderCallbacks(session_id);
    showToast('Session stopped — callbacks kept');
  } catch(e) {
    showToast('Failed to stop session', true);
  }
}

// Remove the session entirely, discarding its callbacks.
async function interactionsDelete(session_id) {
  try {
    await fetch('/api/interactions/' + session_id, { method: 'DELETE' });
    if (_interactionsSelectedId === session_id) {
      _interactionsSelectedId = null;
      _interactionsSelectedCbIdx = null;
      const listEl = document.getElementById('interactions-cb-list');
      if (listEl) listEl.innerHTML = '<div class="empty">Select a session to see its callbacks.</div>';
      const titleEl = document.getElementById('interactions-cb-title');
      if (titleEl) titleEl.textContent = 'Callbacks';
      const rawPanel = document.getElementById('interactions-raw-panel');
      if (rawPanel) rawPanel.style.display = 'none';
    }
    await interactionsLoadSessions();
  } catch(e) {
    showToast('Failed to remove session', true);
  }
}

function _interactionsOnWsEvent(msg) {
  const session_id = msg.session_id;
  const cb = msg.callback;
  const oob_url = msg.oob_url || '';

  // Ensure session exists in local cache (may have been created externally)
  if (!_interactionsSessions[session_id]) {
    _interactionsSessions[session_id] = { session_id, oob_url, callbacks: [], active: true };
  }
  if (!_interactionsSessions[session_id].callbacks) {
    _interactionsSessions[session_id].callbacks = [];
  }
  _interactionsSessions[session_id].callbacks.push(cb);

  // Auto-select this session if none is selected
  if (!_interactionsSelectedId) {
    _interactionsSelectedId = session_id;
  }

  if (_interactionsSelectedId === session_id) {
    _interactionsRenderCallbacks(session_id);
  }

  interactionsLoadSessions();

  const isActive = document.getElementById('panel-extras').classList.contains('on')
    && document.getElementById('st-extras-interactions').classList.contains('on');
  if (!isActive) {
    _interactionsBadgeSet();
    const mtab = document.getElementById('mt-extras');
    if (mtab) {
      mtab.style.color = 'var(--red)';
      setTimeout(() => { mtab.style.color = ''; }, 3000);
    }
  }

  showToast('Interaction received on ' + oob_url);
}

setInterval(() => {
  if (document.getElementById('panel-extras').classList.contains('on')
      && document.getElementById('st-extras-interactions').classList.contains('on')) {
    interactionsLoadSessions();
    if (_interactionsSelectedId) {
      fetch('/api/interactions/' + _interactionsSelectedId)
        .then(r => r.json())
        .then(s => {
          if (s && s.session_id) {
            _interactionsSessions[s.session_id] = s;
            _interactionsRenderCallbacks(s.session_id);
          }
        })
        .catch(() => {});
    }
  }
}, 3000);

