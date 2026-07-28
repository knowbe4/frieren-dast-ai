// ── system logs ────────────────────────────────────────────────────────
let _logTimer = null;

function toggleLogAuto(cb) {
  if (cb.checked) {
    _logTimer = setInterval(loadLogs, 3000);
  } else {
    clearInterval(_logTimer);
    _logTimer = null;
  }
}

async function clearLogs() {
  if (!await confirmDlg('Clear all log events? This cannot be undone.')) return;
  await fetch('/api/logs/clear', { method: 'POST' });
  loadLogs();
}

const _LOG_LEVEL_COLOR = { finding: '#ff6b6b', warn: '#e5c07b', error: '#e06c75', info: 'var(--txt2)', system: '#61afef' };
const _LOG_SOURCE_COLOR = { plugin: 'var(--orange)', agent: '#c792ea', browser: '#61afef', crawler: '#98c379', system: 'var(--txt2)' };

async function loadLogs() {
  const el = document.getElementById('log-body');
  if (!el) return;
  const levelFilter  = document.getElementById('log-filter-level')?.value  || '';
  const sourceFilter = document.getElementById('log-filter-source')?.value || '';
  const textFilter   = (document.getElementById('log-filter-text')?.value  || '').toLowerCase();
  try {
    const r = await fetch('/api/logs');
    const data = await r.json();
    let events = data.events || [];
    if (levelFilter === 'no-warn') events = events.filter(e => e.level !== 'warn' && e.level !== 'warning');
    else if (levelFilter) events = events.filter(e => e.level === levelFilter);
    if (sourceFilter) events = events.filter(e => e.source === sourceFilter);
    if (textFilter)   events = events.filter(e =>
      (e.message||'').toLowerCase().includes(textFilter) ||
      (e.plugin||'').toLowerCase().includes(textFilter)  ||
      (e.url||'').toLowerCase().includes(textFilter)     ||
      (e.finding||'').toLowerCase().includes(textFilter)
    );
    if (!events.length) {
      el.innerHTML = '<div style="color:var(--txt2);padding:14px 12px">No log events match the current filter.</div>';
      return;
    }
    el.innerHTML = events.map(ev => {
      const d   = new Date(ev.ts * 1000);
      const ts  = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const levelColor  = _LOG_LEVEL_COLOR[ev.level]  || 'var(--txt2)';
      const sourceColor = _LOG_SOURCE_COLOR[ev.source] || 'var(--txt2)';
      const isFinding = ev.level === 'finding';

      // Truncate URL for display
      let urlDisplay = '';
      if (ev.url) {
        try {
          const u = new URL(ev.url);
          urlDisplay = `<span title="${esc(ev.url)}" style="color:var(--txt2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block">${esc(u.host)}<span style="color:var(--txt)">${esc(u.pathname)}</span></span>`;
        } catch { urlDisplay = `<span style="color:var(--txt2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block">${esc(ev.url)}</span>`; }
      }

      return `<div style="display:grid;grid-template-columns:80px 64px 70px 130px 1fr 200px;
                          border-bottom:1px solid var(--bdr);
                          ${isFinding ? 'background:rgba(255,107,107,.05)' : ''}">
        <div style="padding:4px 8px;color:var(--txt2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(ts)}</div>
        <div style="padding:4px 8px"><span style="color:${sourceColor};font-size:10px;font-weight:600">${esc(ev.source||'')}</span></div>
        <div style="padding:4px 8px"><span style="color:${levelColor};font-size:10px;font-weight:600;text-transform:uppercase">${esc(ev.level||'')}</span></div>
        <div style="padding:4px 8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--blue)">${esc(ev.plugin||'')}</div>
        <div style="padding:4px 8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:${isFinding ? '#ff6b6b' : 'var(--txt)'}">
          ${esc(ev.message||'')}
        </div>
        <div style="padding:4px 8px;overflow:hidden;font-size:10px">${urlDisplay}</div>
      </div>`;
    }).join('');
  } catch (e) {
    el.innerHTML = '<div style="color:var(--txt2);padding:14px 12px">Failed to load logs.</div>';
  }
}

// ── scan queue ─────────────────────────────────────────────────────────
let _scanTimer = null;

function toggleScanAuto(cb) {
  if (cb.checked) {
    _scanTimer = setInterval(loadScanQueue, 2000);
  } else {
    clearInterval(_scanTimer);
    _scanTimer = null;
  }
}

// start auto-refresh immediately when JS loads (tab may not be active yet)
document.addEventListener('DOMContentLoaded', () => {
  const cb = document.getElementById('scan-autoreload');
  if (cb && cb.checked) _scanTimer = setInterval(loadScanQueue, 2000);
});

const _SCAN_STATUS_COLOR = {
  vulnerable: 'var(--red)',
  safe:       'var(--green)',
  error:      'var(--yellow)',
  cancelled:  'var(--txt3)',
  skipped:    'var(--txt3)',
};

const _SCAN_STATUS_LABEL = {
  vulnerable: 'VULN',
  safe:       'SAFE',
  error:      'ERR',
  cancelled:  'CANCEL',
  skipped:    'SKIP',
};

function _methodColor(m) {
  const map = {GET:'var(--green)',POST:'var(--blue)',PUT:'var(--yellow)',
               PATCH:'var(--yellow)',DELETE:'var(--red)'};
  return map[m] || 'var(--txt2)';
}

function _scanCard(item, showCancel, showStop) {
  const url = item.url || '';
  let host = '', path = url;
  try { const u = new URL(url); host = u.host; path = u.pathname + u.search; } catch {}
  const age = item.queued_at
    ? Math.round((Date.now()/1000) - item.queued_at) + 's ago'
    : '';
  const elapsed = showStop && item.started_at
    ? Math.round((Date.now()/1000) - item.started_at) + 's'
    : '';
  const isWaiting = item.status === 'waiting';
  const opLabel = item.operation
    ? `<span style="display:inline-block;margin-top:2px;background:var(--bg3);border:1px solid #4a3a6a;
                    border-radius:3px;padding:0 5px;color:#c792ea;font-size:10px;
                    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:180px"
             title="${esc(item.operation)}">${esc(item.operation)}</span>` : '';
  const statusBadge = isWaiting
    ? `<span style="color:var(--txt3);font-size:10px">waiting...</span>` : '';
  return `<div style="padding:6px 12px;border-bottom:1px solid var(--bdr3,#252525);
                      display:flex;align-items:flex-start;gap:8px;font-size:11px;
                      ${isWaiting ? 'opacity:0.6' : ''}">
    <span style="color:${_methodColor(item.method)};font-weight:700;width:44px;flex-shrink:0;
                 font-size:10px;padding-top:1px">${esc(item.method||'')}</span>
    <div style="flex:1;min-width:0;overflow:hidden">
      <div style="color:var(--txt2);font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(host)}</div>
      <div style="color:var(--txt);white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(url)}">${esc(path)}</div>
      ${opLabel}
    </div>
    <div style="flex-shrink:0;text-align:right;min-width:60px">
      ${statusBadge}
      <div style="color:var(--txt3);font-size:10px">${esc(elapsed || age)}</div>
      ${showStop && !isWaiting ? `<button onclick="stopRunningItem('${esc(item.id)}')"
        style="margin-top:2px;background:none;border:1px solid var(--red);color:var(--red);
               padding:1px 6px;border-radius:3px;cursor:pointer;font-size:10px">Stop</button>` : ''}
      ${showCancel ? `<button onclick="cancelScanItem('${esc(item.id)}')"
        style="margin-top:2px;background:none;border:1px solid var(--bdr);color:var(--txt2);
               padding:1px 6px;border-radius:3px;cursor:pointer;font-size:10px">Cancel</button>` : ''}
    </div>
  </div>`;
}

function _completedCard(item) {
  const url = item.url || '';
  let host = '', path = url;
  try { const u = new URL(url); host = u.host; path = u.pathname + u.search; } catch {}
  const status = item.status || '';
  const color  = _SCAN_STATUS_COLOR[status] || 'var(--txt2)';
  const label  = _SCAN_STATUS_LABEL[status] || status.toUpperCase();
  const dur = (item.started_at && item.finished_at)
    ? ((item.finished_at - item.started_at).toFixed(1) + 's') : '';
  const findings = item.findings_count > 0
    ? `<span style="color:var(--red);font-weight:700;font-size:10px">+${item.findings_count} vuln</span>` : '';
  // Show skip/cancel reason as a dim subtitle
  const reason = (status === 'skipped' || status === 'cancelled') && item.reason
    ? `<div style="color:var(--txt3,#555);font-size:9px;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(item.reason)}">${esc(item.reason)}</div>`
    : '';
  return `<div style="padding:5px 12px;border-bottom:1px solid var(--bdr3,#252525);
                      display:flex;align-items:flex-start;gap:8px;font-size:11px
                      ${status==='vulnerable'?';background:rgba(255,107,107,.04)':''}">
    <span style="color:${color};font-weight:700;font-size:9px;width:44px;flex-shrink:0;
                 padding-top:2px;text-transform:uppercase">${esc(label)}</span>
    <div style="flex:1;min-width:0;overflow:hidden">
      <div style="color:var(--txt2);font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(host)}</div>
      <div style="color:var(--txt);white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(url)}">${esc(path)}</div>
      ${reason}
    </div>
    <div style="flex-shrink:0;text-align:right;min-width:50px">
      ${findings}
      <div style="color:var(--txt3);font-size:10px">${esc(dur)}</div>
    </div>
  </div>`;
}

async function loadScanQueue() {
  try {
    const r = await fetch('/api/scan-queue');
    if (!r.ok) return;
    const d = await r.json();

    // Summary bar
    const summary = document.getElementById('scan-queue-summary');
    if (summary) {
      summary.textContent =
        `${d.pending_count} pending · ${d.running_count} running · ${d.completed_count} completed`;
    }

    // Pause button label
    const btn = document.getElementById('scan-pause-btn');
    if (btn) {
      btn.textContent = d.paused ? 'Resume' : 'Pause';
      btn.style.background = d.paused ? 'var(--yellow)' : '';
      btn.style.color      = d.paused ? '#000' : '';
    }

    // Counts
    const pc = document.getElementById('scan-pending-count');
    const rc = document.getElementById('scan-running-count');
    const cc = document.getElementById('scan-completed-count');
    if (pc) pc.textContent = d.pending_count;
    if (rc) rc.textContent = d.running_count;
    if (cc) cc.textContent = d.completed_count;

    // Pending list — split into queued (status=pending) and waiting-for-slot (status=waiting)
    const pendingEl = document.getElementById('scan-pending-list');
    if (pendingEl) {
      const queued  = d.pending.filter(i => i.status !== 'waiting');
      const waiting = d.pending.filter(i => i.status === 'waiting');
      const allPending = [...queued, ...waiting];
      pendingEl.innerHTML = allPending.length
        ? allPending.map(i => _scanCard(i, i.status !== 'waiting')).join('')
        : '<div style="color:var(--txt2);padding:12px 14px;font-size:11px">Queue is empty.</div>';
    }

    // Running list
    const runningEl = document.getElementById('scan-running-list');
    if (runningEl) {
      runningEl.innerHTML = d.running.length
        ? d.running.map(i => _scanCard(i, false, true)).join('')
        : '<div style="color:var(--txt2);padding:12px 14px;font-size:11px">No active scans.</div>';
    }

    // Completed list
    const completedEl = document.getElementById('scan-completed-list');
    if (completedEl) {
      completedEl.innerHTML = d.completed.length
        ? d.completed.map(i => _completedCard(i)).join('')
        : '<div style="color:var(--txt2);padding:12px 14px;font-size:11px">No completed scans yet.</div>';
    }

  } catch(e) { console.error('loadScanQueue:', e); }
}

async function toggleScanPause() {
  const btn = document.getElementById('scan-pause-btn');
  const paused = btn && btn.textContent.trim() === 'Pause';
  await fetch(paused ? '/api/scan-queue/pause' : '/api/scan-queue/resume', { method: 'POST' });
  await loadScanQueue();
}

async function cancelScanItem(id) {
  await fetch('/api/scan-queue/cancel', {
    method: 'POST',
    headers: {'content-type':'application/json'},
    body: JSON.stringify({id}),
  });
  await loadScanQueue();
}

async function stopRunningItem(id) {
  await fetch('/api/scan-queue/stop', {
    method: 'POST',
    headers: {'content-type':'application/json'},
    body: JSON.stringify({id}),
  });
  await loadScanQueue();
}

async function cancelAllPending() {
  if (!await confirmDlg('Cancel all pending scan jobs? They will need to be re-queued to run.')) return;
  await fetch('/api/scan-queue/cancel-all', { method: 'POST' });
  await loadScanQueue();
}

async function clearCompleted() {
  if (!await confirmDlg('Remove all completed scan entries from the queue?')) return;
  await fetch('/api/scan-queue/clear-completed', { method: 'POST' });
  await loadScanQueue();
}

// ── plugins ────────────────────────────────────────────────────────────
async function loadPlugins() {
  const r = await fetch('/api/plugins');
  const plugins = await r.json();
  _gqlTabVisibility(plugins);
  const el = document.getElementById('plugin-list');
  if (!plugins.length) {
    el.innerHTML = '<div class="empty" style="padding:20px 0">No plugins loaded.</div>';
    return;
  }
  el.innerHTML = plugins.map(p => `
    <div style="border:1px solid var(--bdr);border-radius:4px;padding:12px 14px;
                margin-bottom:10px;background:var(--bg2);display:flex;align-items:flex-start;gap:14px">
      <div style="flex:1">
        <div style="font-size:12px;font-weight:600;color:var(--txt);margin-bottom:3px">
          ${esc(p.name)}
          <span style="font-size:10px;color:var(--txt2);font-weight:400;margin-left:6px">v${esc(p.version)}</span>
          ${p.author ? `<span style="font-size:10px;color:var(--txt2);margin-left:4px">by ${esc(p.author)}</span>` : ''}
        </div>
        <div style="font-size:11px;color:var(--txt2)">${esc(p.description)}</div>
      </div>
      <label style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--txt);
                    cursor:pointer;white-space:nowrap;flex-shrink:0">
        <input type="checkbox" ${p.enabled ? 'checked' : ''}
               style="accent-color:var(--acc)"
               onchange="togglePlugin('${esc(p.name)}', this.checked)">
        ${p.enabled ? 'Enabled' : 'Disabled'}
      </label>
    </div>`).join('');
}

async function togglePlugin(name, enabled) {
  await fetch('/api/plugins/' + encodeURIComponent(name), {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ enabled }),
  });
  loadPlugins();
}

// ── crawl ──────────────────────────────────────────────────────────────
let crawlWs = null;
let activeCrawlSessionId = null;

async function updateCrawlCookieStatus() {
  const dot   = document.getElementById('crawl-cookie-dot');
  const label = document.getElementById('crawl-cookie-label');
  if (!dot || !label) return;
  try {
    const r = await fetch('/api/crawl/cookie-status');
    if (!r.ok) throw new Error('status ' + r.status);
    const d = await r.json();
    const count = d.cookie_count || 0;
    if (count > 0) {
      dot.style.background = '#4caf50';
      label.style.color = 'var(--txt)';
      label.textContent = `${count} session cookie${count !== 1 ? 's' : ''} ready — crawler will use your authenticated session`;
    } else {
      dot.style.background = '#ff9800';
      label.style.color = 'var(--txt2)';
      label.textContent = 'No session cookies yet — use Browse to log in first, then start the crawl';
    }
  } catch (_) {
    dot.style.background = '#666';
    label.style.color = 'var(--txt3)';
    label.textContent = 'Could not fetch cookie status';
  }
}

function appendCrawlLog(msg) {
  const el = document.getElementById('crawl-log');
  el.textContent += msg + '\n';
  el.scrollTop = el.scrollHeight;
}

function updateCrawlStats() {
  const statsEl = document.getElementById('crawl-live-stats');
  const scanBtn = document.getElementById('crawl-scan-btn');
  if (!statsEl) return;
  const crawlerEntries = Object.values(entries).filter(e => e.source === 'crawler');
  if (!crawlerEntries.length) { statsEl.textContent = ''; return; }
  const unscanned = crawlerEntries.filter(e => !e.queued_for_scan && !e.scan_result).length;
  statsEl.textContent = `${crawlerEntries.length} requests captured, ${unscanned} unscanned`;
  if (scanBtn) scanBtn.style.display = unscanned > 0 ? '' : 'none';
}

async function startCrawl() {
  const url = document.getElementById('crawl-url').value.trim();
  if (!url) { appendCrawlLog('Error: enter a target URL'); return; }
  const headless   = document.getElementById('crawl-headless').checked;
  const maxClicks  = parseInt(document.getElementById('crawl-max-clicks').value) || 200;

  document.getElementById('crawl-start-btn').disabled = true;
  document.getElementById('crawl-stop-btn').disabled  = false;
  document.getElementById('crawl-log').textContent = '';
  updateCrawlCookieStatus();

  // Open a WebSocket for log streaming
  if (crawlWs) crawlWs.close();
  crawlWs = new WebSocket(`ws://${location.host}/ws/crawl`);
  crawlWs.onmessage = e => { appendCrawlLog(e.data); updateCrawlStats(); };
  crawlWs.onclose   = () => {
    document.getElementById('crawl-start-btn').disabled = false;
    document.getElementById('crawl-stop-btn').disabled  = true;
    updateCrawlStats();
  };

  await fetch('/api/crawl', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url, headless, max_clicks: maxClicks }),
  });
}

async function stopCrawl() {
  if (!await confirmDlg('Stop the crawler? Progress will be lost.')) return;
  await fetch('/api/crawl/stop', { method: 'POST' });
  document.getElementById('crawl-stop-btn').disabled  = true;
  document.getElementById('crawl-start-btn').disabled = false;
  if (crawlWs) { crawlWs.close(); crawlWs = null; }
}

// ── content discovery (forced browsing) ─────────────────────────────────
// Reuses the /ws/crawl log stream: the backend discovery worker sends its
// progress lines through broadcast_crawl_log, the same channel the crawler uses.
let discWs = null;

function appendDiscLog(msg) {
  const el = document.getElementById('disc-log');
  if (!el) return;
  el.textContent += msg + '\n';
  el.scrollTop = el.scrollHeight;
  // A hit line looks like: "HIT [kind] 200 /path (1234 bytes)" — render it as a row.
  const m = msg.match(/^HIT \[(\w+)\]\s+(\d+)\s+(\S+)\s+\((\d+) bytes\)/);
  if (m) _discAddHit(m[1], m[2], m[3], m[4]);
}

function _discAddHit(kind, status, path, size) {
  const tbody = document.getElementById('disc-results');
  if (!tbody) return;
  const tr = document.createElement('tr');
  tr.style.cssText = 'border-bottom:1px solid var(--bdr)';
  const statusColor = status.startsWith('2') ? 'var(--green)'
                    : status.startsWith('3') ? 'var(--yellow)'
                    : status.startsWith('4') ? 'var(--orange)' : 'var(--txt2)';
  tr.innerHTML =
    `<td style="padding:4px 8px;color:var(--txt2)">${esc(kind)}</td>` +
    `<td style="padding:4px 8px;color:${statusColor}">${esc(status)}</td>` +
    `<td style="padding:4px 8px;color:var(--txt)">${esc(path)}</td>` +
    `<td style="padding:4px 8px;color:var(--txt2)">${esc(size)}</td>`;
  tbody.appendChild(tr);
}

async function startDiscovery() {
  const url = document.getElementById('disc-url').value.trim();
  if (!url) { appendDiscLog('Error: enter a target URL'); return; }
  const dirs    = document.getElementById('disc-dirs').checked;
  const files   = document.getElementById('disc-files').checked;
  const graphql = document.getElementById('disc-graphql').checked;
  if (!dirs && !files && !graphql) { appendDiscLog('Error: select at least one wordlist'); return; }

  document.getElementById('disc-start-btn').disabled = true;
  document.getElementById('disc-stop-btn').disabled  = false;
  document.getElementById('disc-log').textContent = '';
  document.getElementById('disc-results').innerHTML = '';

  if (discWs) discWs.close();
  discWs = new WebSocket(`ws://${location.host}/ws/crawl`);
  discWs.onmessage = e => appendDiscLog(e.data);
  discWs.onclose   = () => {
    document.getElementById('disc-start-btn').disabled = false;
    document.getElementById('disc-stop-btn').disabled  = true;
  };

  const r = await fetch('/api/discovery', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url, dirs, files, graphql }),
  });
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    appendDiscLog('Error: ' + (d.error || ('HTTP ' + r.status)));
    document.getElementById('disc-start-btn').disabled = false;
    document.getElementById('disc-stop-btn').disabled  = true;
    if (discWs) { discWs.close(); discWs = null; }
  }
}

async function stopDiscovery() {
  await fetch('/api/discovery/stop', { method: 'POST' });
  document.getElementById('disc-stop-btn').disabled  = true;
  document.getElementById('disc-start-btn').disabled = false;
  if (discWs) { discWs.close(); discWs = null; }
}

// NOTE: hidden-parameter mining is no longer a manual UI action. It now runs
// automatically as part of a scan — deterministically on the AI-off scan path
// (ProxyRunner._mine_params_for_entry) and, with AI on, when the LLM planner
// judges an endpoint likely to accept undocumented params
// (Coordinator._run_param_mining_pass). Discovered names surface as
// "param-discovery" recon suggestions in the AI tab.

async function scanCrawled() {
  const ids = Object.values(entries)
    .filter(e => e.source === 'crawler' && !e.queued_for_scan)
    .map(e => e.id);
  if (!ids.length) { showToast('No unscanned crawler requests.'); return; }
  await fetch('/api/scan', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ids }),
  });
  showToast(`Queued ${ids.length} crawler requests for scanning.`);
  updateCrawlStats();
}

function viewCrawled() {
  switchMain('proxy');
  document.getElementById('chk-src-proxy').checked   = false;
  document.getElementById('chk-src-browse').checked  = false;
  document.getElementById('chk-src-crawler').checked = true;
  document.getElementById('chk-src-agent').checked = false;
  document.getElementById('chk-src-scan').checked = false;
  applyFilter();
}

function crawlHost(host) {
  // Derive URL from first request seen for that host
  const firstEntry = Object.values(entries).find(e => e.host === host);
  const scheme = firstEntry ? (firstEntry.url.startsWith('https') ? 'https' : 'http') : 'https';
  const url = `${scheme}://${host}/`;
  // Pre-fill crawl sub-tab and switch to it
  switchMain('browse');
  switchBrowseSub('crawl');
  document.getElementById('crawl-url').value = url;
}

async function scanHost(host) {
  const ids = Object.values(entries)
    .filter(e => e.host === host && !e.queued_for_scan)
    .map(e => e.id);
  if (!ids.length) { showToast('No unscanned requests for this host.'); return; }
  await fetch('/api/scan', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ids }),
  });
  selectHost(host);
  switchMain('proxy');
  showToast(`Queued ${ids.length} requests for scanning.`);
}

function crawlFromBrowse() {
  if (!activeBrowseSessionId) return;
  // Collect unique base URLs from this browse session
  const seeds = [...new Set(
    Object.values(entries)
      .filter(e => e.browse_session_id === activeBrowseSessionId)
      .map(e => { try { const u = new URL(e.url); return u.origin + u.pathname; } catch { return null; } })
      .filter(Boolean)
  )];
  if (!seeds.length) { showToast('No URLs in browse session.'); return; }
  // Use first URL as main target, rest as seeds
  switchMain('browse');
  switchBrowseSub('crawl');
  document.getElementById('crawl-url').value = seeds[0];
}

