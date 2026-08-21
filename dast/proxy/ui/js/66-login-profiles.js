// ── Login Profiles (Discovery > Logins) ──────────────────────────────────
// Encrypted per-site login profiles: list, create/edit, import an active
// session, and activate it into the live proxy store. Secrets never round-trip
// to the browser — the API returns only *_set booleans.

let _loginProfiles = [];
let _loginCurrentSlug = null;

function loadLoginProfiles() {
  fetch('/api/profiles').then(r => r.json()).then(data => {
    _loginProfiles = data.profiles || [];
    document.getElementById('logins-crypto-warn').style.display =
      data.crypto_available ? 'none' : 'inline';
    loginRenderList();
  }).catch(e => console.error('loadLoginProfiles', e));
}

function loginRenderList() {
  const el = document.getElementById('logins-list');
  if (!_loginProfiles.length) {
    el.innerHTML = '<div style="color:var(--txt2)">No profiles yet.</div>';
    return;
  }
  el.innerHTML = _loginProfiles.map(p => {
    const active = p.slug === _loginCurrentSlug ? 'background:var(--bg3)' : '';
    const badges = [
      p.credentials.length ? p.credentials.length + ' cred' : '',
      p.session_set ? 'session' : '',
      p.flow_set ? 'flow' : '',
    ].filter(Boolean).join(' · ');
    return `<div onclick="loginSelectProfile('${p.slug}')" style="padding:6px 8px;border:1px solid var(--bd);border-radius:4px;margin-bottom:4px;cursor:pointer;${active}">
      <div style="font-weight:600">${_esc(p.name)}</div>
      <div style="color:var(--txt2);font-size:10px">${_esc(p.host_pattern || '(no host pattern)')}</div>
      <div style="color:var(--txt2);font-size:10px">${badges}</div>
    </div>`;
  }).join('');
}

function loginNewProfile() {
  _loginCurrentSlug = null;
  document.getElementById('logins-editor').style.display = 'block';
  document.getElementById('logins-name').value = '';
  document.getElementById('logins-host').value = '';
  document.getElementById('logins-authurl').value = '';
  document.getElementById('logins-creds').innerHTML = '';
  document.getElementById('logins-session-status').textContent = '';
  document.getElementById('logins-editor-status').textContent = '';
  _loginSetRecording(false);
  _loginFlowStatus('');
  loginAddCred();
  loginRenderList();
}

function loginSelectProfile(slug) {
  const p = _loginProfiles.find(x => x.slug === slug);
  if (!p) return;
  _loginCurrentSlug = slug;
  document.getElementById('logins-editor').style.display = 'block';
  document.getElementById('logins-name').value = p.name || '';
  document.getElementById('logins-host').value = p.host_pattern || '';
  document.getElementById('logins-authurl').value = p.auth_url || '';
  document.getElementById('logins-creds').innerHTML = '';
  (p.credentials.length ? p.credentials : [{label: 'default', username: '', secret_set: false}])
    .forEach(c => loginAddCred(c));
  document.getElementById('logins-session-status').textContent =
    p.session_set ? 'A session is saved.' : 'No session saved.';
  document.getElementById('logins-editor-status').textContent = '';
  _loginSetRecording(false);
  _loginFlowStatus(p.flow_set ? `Flow saved — ${p.flow_step_count} step(s).` : 'No flow recorded.');
  loginRenderList();
}

function loginAddCred(cred) {
  cred = cred || {label: 'default', username: '', secret_set: false};
  const wrap = document.getElementById('logins-creds');
  const row = document.createElement('div');
  row.className = 'logins-cred-row';
  row.style.cssText = 'display:flex;gap:4px;margin-bottom:4px';
  const ph = cred.secret_set ? '•••••• (unchanged)' : 'secret';
  row.innerHTML = `
    <input class="tinput logins-cred-label" style="width:90px" placeholder="label" value="${_esc(cred.label || '')}">
    <input class="tinput logins-cred-user" style="flex:1" placeholder="username" value="${_esc(cred.username || '')}">
    <input class="tinput logins-cred-secret" type="password" style="flex:1" placeholder="${ph}" data-set="${cred.secret_set ? 1 : 0}">
    <button class="tbtn" onclick="this.parentElement.remove()">×</button>`;
  wrap.appendChild(row);
}

function _loginCollectCreds() {
  return Array.from(document.querySelectorAll('#logins-creds .logins-cred-row')).map(row => {
    const secretInput = row.querySelector('.logins-cred-secret');
    const cred = {
      label: row.querySelector('.logins-cred-label').value.trim() || 'default',
      username: row.querySelector('.logins-cred-user').value.trim(),
    };
    // Only send secret if the user typed a new one; omit to preserve the stored value.
    if (secretInput.value) cred.secret = secretInput.value;
    else if (secretInput.dataset.set !== '1') cred.secret = '';
    return cred;
  });
}

function loginSaveProfile() {
  const body = {
    slug: _loginCurrentSlug || undefined,
    name: document.getElementById('logins-name').value.trim(),
    host_pattern: document.getElementById('logins-host').value.trim(),
    auth_url: document.getElementById('logins-authurl').value.trim(),
    credentials: _loginCollectCreds(),
  };
  if (!body.name) { _loginStatus('Name is required.', true); return; }
  fetch('/api/profiles', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
  }).then(r => r.json()).then(p => {
    if (p.error) { _loginStatus(p.error, true); return; }
    _loginCurrentSlug = p.slug;
    _loginStatus('Saved.');
    loadLoginProfiles();
  }).catch(e => _loginStatus('Save failed: ' + e, true));
}

function loginImportSession() {
  if (!_loginCurrentSlug) { _loginStatus('Save the profile first, then import a session.', true); return; }
  const body = {
    target_url: document.getElementById('logins-authurl').value.trim(),
    cookie_header: document.getElementById('logins-cookie').value.trim(),
    auth_token: document.getElementById('logins-token').value.trim(),
    storage_state_json: document.getElementById('logins-storagestate').value.trim(),
  };
  fetch(`/api/profiles/${_loginCurrentSlug}/session-import`, {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
  }).then(r => r.json()).then(p => {
    const st = document.getElementById('logins-session-status');
    if (p.error) { st.textContent = p.error; st.style.color = 'var(--bad)'; return; }
    st.textContent = 'Session imported.'; st.style.color = 'var(--txt2)';
    document.getElementById('logins-cookie').value = '';
    document.getElementById('logins-token').value = '';
    document.getElementById('logins-storagestate').value = '';
    loadLoginProfiles();
  }).catch(e => _loginStatus('Import failed: ' + e, true));
}

function loginActivateProfile() {
  if (!_loginCurrentSlug) return;
  fetch(`/api/profiles/${_loginCurrentSlug}/activate`, {method: 'POST'})
    .then(r => r.json()).then(res => {
      if (res.error) { _loginStatus(res.error, true); return; }
      _loginStatus(`Activated — ${res.cookies_imported} cookies loaded into the proxy.`);
    }).catch(e => _loginStatus('Activate failed: ' + e, true));
}

function loginDeleteProfile() {
  if (!_loginCurrentSlug) return;
  if (!confirm('Delete this login profile?')) return;
  fetch(`/api/profiles/${_loginCurrentSlug}`, {method: 'DELETE'})
    .then(r => r.json()).then(() => {
      _loginCurrentSlug = null;
      document.getElementById('logins-editor').style.display = 'none';
      loadLoginProfiles();
    }).catch(e => _loginStatus('Delete failed: ' + e, true));
}

// ── Login-flow recording & replay (Phase 2) ──────────────────────────────

function _loginFlowStatus(msg, isError) {
  const el = document.getElementById('logins-flow-status');
  if (!el) return;
  el.textContent = msg;
  el.style.color = isError ? 'var(--bad)' : 'var(--txt2)';
}

function _loginSetRecording(on) {
  document.getElementById('logins-flow-record-btn').style.display = on ? 'none' : '';
  document.getElementById('logins-flow-stop-btn').style.display = on ? '' : 'none';
  document.getElementById('logins-flow-cancel-btn').style.display = on ? '' : 'none';
}

function loginStartRecord() {
  const url = document.getElementById('logins-authurl').value.trim();
  fetch('/api/login-flow/record/start', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({url}),
  }).then(r => r.json()).then(res => {
    if (res.error) { _loginFlowStatus(res.error, true); return; }
    _loginSetRecording(true);
    _loginFlowStatus('Recording — log in through the browser window, then Stop & save.');
  }).catch(e => _loginFlowStatus('Record failed: ' + e, true));
}

function loginStopRecord() {
  if (!_loginCurrentSlug) { _loginFlowStatus('Save the profile first.', true); return; }
  fetch('/api/login-flow/record/stop', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({slug: _loginCurrentSlug, save_session: true}),
  }).then(r => r.json()).then(res => {
    _loginSetRecording(false);
    if (res.error) { _loginFlowStatus(res.error, true); return; }
    _loginFlowStatus(`Flow saved — ${res.flow_step_count || 0} step(s).`);
    loadLoginProfiles();
  }).catch(e => _loginFlowStatus('Stop failed: ' + e, true));
}

function loginCancelRecord() {
  fetch('/api/login-flow/record/cancel', {method: 'POST'})
    .then(() => { _loginSetRecording(false); _loginFlowStatus('Recording cancelled.'); })
    .catch(e => _loginFlowStatus('Cancel failed: ' + e, true));
}

function loginReplayFlow() {
  if (!_loginCurrentSlug) { _loginFlowStatus('Save the profile first.', true); return; }
  _loginFlowStatus('Replaying flow…');
  fetch('/api/login-flow/replay', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({slug: _loginCurrentSlug}),
  }).then(r => r.json()).then(res => {
    if (res.error) { _loginFlowStatus(res.error, true); return; }
    if (res.success) {
      _loginFlowStatus(`Replay succeeded — ${res.cookies_imported} cookie(s) loaded.`);
    } else {
      _loginFlowStatus('Replay did not authenticate' + (res.error ? ': ' + res.error : ''), true);
    }
  }).catch(e => _loginFlowStatus('Replay failed: ' + e, true));
}

function loginResumeFlow() {
  fetch('/api/login-flow/resume', {method: 'POST'})
    .then(() => { document.getElementById('logins-flow-needhuman').style.display = 'none'; })
    .catch(e => _loginFlowStatus('Resume failed: ' + e, true));
}

// Live login-flow events (recording/replay/needs-human).
function _loginConnectWs() {
  try {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws/login`);
    ws.onmessage = (ev) => {
      let msg; try { msg = JSON.parse(ev.data); } catch (e) { return; }
      const banner = document.getElementById('logins-flow-needhuman');
      if (msg.type === 'needs_human') {
        if (banner) banner.style.display = 'block';
        _loginFlowStatus('Paused: ' + (msg.reason || 'action needed'), true);
      } else if (msg.type === 'resumed' || msg.type === 'replay_done') {
        if (banner) banner.style.display = 'none';
      }
    };
    ws.onclose = () => setTimeout(_loginConnectWs, 3000);
  } catch (e) { /* best-effort */ }
}
_loginConnectWs();

function _loginStatus(msg, isError) {
  const el = document.getElementById('logins-editor-status');
  el.textContent = msg;
  el.style.color = isError ? 'var(--bad)' : 'var(--txt2)';
}

function _esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
}
