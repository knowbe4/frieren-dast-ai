// -- Interactions (interactsh / OAST out-of-band callbacks) --------------------
// Dashboard driver for the OAST interactions backend (dast/proxy/api/interactions_routes.py).
// Restored after it was deleted as collateral with the H1-Validator removal (8d288a4);
// the backend and the Extras > Interactions sub-tab were kept, leaving the tab broken.
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

