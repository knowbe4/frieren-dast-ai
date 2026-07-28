// ── browse ─────────────────────────────────────────────────────────────
let activeBrowseSessionId = null;

async function startBrowse() {
  const url = document.getElementById('browse-url').value.trim();
  document.getElementById('browse-start-btn').disabled = true;
  document.getElementById('browse-status').textContent = 'Opening browser...';

  const r = await fetch('/api/browse/start', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: url || null }),
  });
  const data = await r.json();
  if (data.session_id) {
    activeBrowseSessionId = data.session_id;
    document.getElementById('browse-stop-btn').disabled  = false;
    document.getElementById('browse-status').innerHTML = 'Browser open — log in to the target, then use <b>Save Current Session</b> below.';
    document.getElementById('browse-session-id').textContent = data.session_id;
    document.getElementById('browse-session-info').style.display = 'block';
    updateBrowseCount();
  } else {
    document.getElementById('browse-start-btn').disabled = false;
    document.getElementById('browse-status').textContent = 'Failed to open browser.';
  }
}

async function stopBrowse() {
  if (!await confirmDlg('Close the browser session? The captured requests will remain in history.')) return;
  await fetch('/api/browse/stop', { method: 'POST' });
  document.getElementById('browse-start-btn').disabled = false;
  document.getElementById('browse-stop-btn').disabled  = true;
  document.getElementById('browse-status').textContent = 'Browser closed.';
}

function updateBrowseCount() {
  if (!activeBrowseSessionId) return;
  const count = Object.values(entries).filter(e => e.browse_session_id === activeBrowseSessionId).length;
  document.getElementById('browse-req-count').textContent = count + ' requests recorded';
  if (document.getElementById('browse-session-info').style.display !== 'none') {
    setTimeout(updateBrowseCount, 1000);
  }
}

function filterBrowseSession() {
  if (!activeBrowseSessionId) return;
  switchMain('proxy');
  document.getElementById('filter').value = '';
  document.getElementById('chk-conn').checked        = true;
  document.getElementById('chk-vuln').checked        = false;
  document.getElementById('chk-src-proxy').checked   = false;
  document.getElementById('chk-src-browse').checked  = true;
  document.getElementById('chk-src-crawler').checked = false;
  document.getElementById('chk-src-agent').checked = false;
  document.getElementById('chk-src-scan').checked = false;
  document.querySelectorAll('#tbody tr').forEach(tr => {
    const id = tr.id.replace('row-', '');
    const e  = entries[id];
    tr.style.display = (e && e.browse_session_id === activeBrowseSessionId) ? '' : 'none';
  });
}

async function scanBrowseSession() {
  if (!activeBrowseSessionId) return;
  const ids = Object.values(entries)
    .filter(e => e.browse_session_id === activeBrowseSessionId && !e.queued_for_scan)
    .map(e => e.id);
  if (!ids.length) { alert('No unscanned requests in this session.'); return; }
  await fetch('/api/scan', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ids }),
  });
  switchMain('proxy');
  filterBrowseSession();
}

// ── named sessions (multi-user IDOR testing) ───────────────────────────
// ── Multi-user testing ─────────────────────────────────────────────────────
function switchMuTab(tab) {
  document.getElementById('mu-panel-browser').style.display = tab === 'browser' ? '' : 'none';
  document.getElementById('mu-panel-creds').style.display   = tab === 'creds'   ? '' : 'none';
  document.getElementById('mu-tab-browser').style.background = tab === 'browser' ? 'var(--acc)' : 'var(--bg2)';
  document.getElementById('mu-tab-browser').style.color     = tab === 'browser' ? '#fff' : 'var(--txt2)';
  document.getElementById('mu-tab-creds').style.background  = tab === 'creds'   ? 'var(--acc)' : 'var(--bg2)';
  document.getElementById('mu-tab-creds').style.color       = tab === 'creds'   ? '#fff' : 'var(--txt2)';
}

async function openNamedBrowser() {
  const name = document.getElementById('nb-name').value.trim();
  const role = document.getElementById('nb-role').value.trim() || 'user';
  const url  = document.getElementById('nb-url').value.trim();
  if (!name) { showToast('Enter a session name.'); return; }
  const r = await fetch('/api/sessions/browser', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name, role, url: url || null }),
  });
  const d = await r.json();
  if (!r.ok) { showToast('Error: ' + (d.error || r.status)); return; }
  showToast(`Browser "${name}" opened — log in, then click Save`);
  document.getElementById('nb-name').value = '';
  document.getElementById('nb-role').value = '';
  document.getElementById('nb-url').value  = '';
  loadNamedBrowsers();
}

async function saveNamedBrowser(name) {
  const r = await fetch(`/api/sessions/browser/${encodeURIComponent(name)}/save`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({}),
  });
  const d = await r.json();
  if (!r.ok) { showToast('Error: ' + (d.error || r.status)); return; }
  showToast(`Session "${name}" saved — ${d.cookie_count} cookie(s)`);
  loadNamedSessions();
  loadNamedBrowsers();
}

async function stopNamedBrowser(name) {
  await fetch(`/api/sessions/browser/${encodeURIComponent(name)}/stop`, { method: 'POST' });
  loadNamedBrowsers();
}

async function loadNamedBrowsers() {
  const el = document.getElementById('named-browsers-list');
  if (!el) return;
  try {
    const r = await fetch('/api/sessions/browser');
    const browsers = await r.json();
    if (!browsers.length) { el.innerHTML = ''; return; }
    el.innerHTML = '<div style="font-size:10px;color:var(--txt2);margin-bottom:4px">Open browser sessions:</div>' +
      browsers.map(b => `
        <div style="display:flex;align-items:center;gap:8px;padding:5px 8px;
                    background:var(--bg2);border:1px solid var(--bdr);border-radius:4px;margin-bottom:3px">
          <span style="width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0"></span>
          <span style="color:var(--acc2);font-family:monospace;font-weight:600">${esc(b.name)}</span>
          <span style="color:var(--txt2);font-size:10px;margin-left:auto">
            Log in, then:
          </span>
          <button class="tbtn pri" style="font-size:10px;padding:2px 8px"
                  onclick="saveNamedBrowser('${esc(b.name)}')">Save Session</button>
          <button class="tbtn del" style="font-size:10px;padding:2px 8px"
                  onclick="stopNamedBrowser('${esc(b.name)}')">Close</button>
        </div>`).join('');
  } catch (_) {}
}

async function loginWithCredentials() {
  const name     = document.getElementById('cred-name').value.trim();
  const role     = document.getElementById('cred-role').value.trim() || 'user';
  const loginUrl = document.getElementById('cred-url').value.trim();
  const username = document.getElementById('cred-username').value.trim();
  const password = document.getElementById('cred-password').value;
  if (!name || !loginUrl || !username || !password) {
    showToast('Fill in name, login URL, username and password.'); return;
  }
  const btn = document.getElementById('cred-login-btn');
  const status = document.getElementById('cred-status');
  btn.disabled = true;
  status.textContent = 'Logging in…';
  status.style.color = 'var(--txt2)';
  const body = {
    name, role, login_url: loginUrl, username, password,
    username_selector: document.getElementById('cred-sel-user').value.trim(),
    password_selector: document.getElementById('cred-sel-pass').value.trim(),
    submit_selector:   document.getElementById('cred-sel-submit').value.trim(),
  };
  try {
    const r = await fetch('/api/sessions/credentials', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (!r.ok) {
      status.textContent = 'Failed: ' + (d.error || r.status);
      status.style.color = 'var(--red)';
    } else {
      status.textContent = `Saved — ${d.cookie_count} cookie(s)`;
      status.style.color = 'var(--green)';
      document.getElementById('cred-name').value = '';
      document.getElementById('cred-url').value  = '';
      document.getElementById('cred-username').value = '';
      document.getElementById('cred-password').value = '';
      loadNamedSessions();
    }
  } catch (e) {
    status.textContent = 'Error: ' + e.message;
    status.style.color = 'var(--red)';
  }
  btn.disabled = false;
}

async function saveNamedSession() {
  const name = document.getElementById('session-name-input').value.trim();
  const role = document.getElementById('session-role-input').value.trim() || 'user';
  if (!name) { showToast('Enter a session name.'); return; }
  const r = await fetch('/api/sessions/save', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name, role }),
  });
  const d = await r.json();
  if (!r.ok) { showToast('Error: ' + (d.error || r.status)); return; }
  showToast(`Session "${name}" saved — ${d.cookie_count} cookie(s), ${d.auth_header_count} auth header(s).`);
  document.getElementById('session-name-input').value = '';
  document.getElementById('session-role-input').value = '';
  loadNamedSessions();
}

async function loadNamedSessions() {
  const el = document.getElementById('named-sessions-list');
  if (!el) return;
  try {
    const r = await fetch('/api/named-sessions');
    const sessions = await r.json();
    if (!sessions.length) {
      el.innerHTML = '<div style="color:var(--txt2);padding:4px 0">No sessions saved yet.</div>';
      return;
    }
    const ready = sessions.length >= 2;
    const statusBanner = ready
      ? `<div style="display:flex;align-items:center;gap:7px;padding:6px 10px;margin-bottom:8px;background:#1a2e1a;border:1px solid var(--green);border-radius:4px;font-size:11px">
           <span style="width:8px;height:8px;border-radius:50%;background:var(--green);flex-shrink:0"></span>
           <span style="color:var(--green)">IDOR scanner active — ${sessions.length} sessions loaded. All scanned requests will be tested across sessions.</span>
         </div>`
      : `<div style="display:flex;align-items:center;gap:7px;padding:6px 10px;margin-bottom:8px;background:var(--bg2);border:1px solid var(--bdr);border-radius:4px;font-size:11px">
           <span style="width:8px;height:8px;border-radius:50%;background:var(--yellow);flex-shrink:0"></span>
           <span style="color:var(--yellow)">Add 1 more session to enable IDOR scanning (need at least 2)</span>
         </div>`;
    el.innerHTML = statusBanner + sessions.map(s => `
      <div style="display:flex;align-items:center;gap:8px;padding:6px 8px;border-bottom:1px solid var(--bdr);background:var(--bg2);border-radius:3px;margin-bottom:3px">
        <span style="color:var(--acc2);font-weight:600;min-width:80px;font-family:monospace">${esc(s.name)}</span>
        <span style="background:var(--bg3);color:var(--txt2);padding:1px 6px;border-radius:10px;font-size:10px">${esc(s.role)}</span>
        <span style="color:var(--txt2);font-size:10px">${s.cookie_count} cookie${s.cookie_count !== 1 ? 's' : ''}</span>
        <button class="tbtn del" style="margin-left:auto;font-size:10px;padding:1px 7px"
                onclick="deleteNamedSession('${esc(s.name)}')">Remove</button>
      </div>`).join('');
  } catch (_) {
    el.textContent = 'Could not load sessions.';
  }
}

async function deleteNamedSession(name) {
  if (!await confirmDlg(`Remove saved session "${name}"?`)) return;
  const r = await fetch(`/api/named-sessions/${encodeURIComponent(name)}`, { method: 'DELETE' });
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    showToast(d.error || 'Failed to remove session', 'error');
    return;
  }
  loadNamedSessions();
}

