// ── target issues ──────────────────────────────────────────────────────
const _SEV_ORDER = ['critical','high','medium','low','info'];
const _SEV_COLOR = {critical:'var(--red)',high:'#e8834a',medium:'var(--yellow)',low:'var(--green)',info:'var(--txt2)'};
const _SEV_LABEL = { critical:'Critical', high:'High', medium:'Medium', low:'Low', info:'Info' };
const _SEV_CLASS = { critical:'C', high:'H', medium:'M', low:'L', info:'I' };

const _ISSUES_PER_PAGE = 10;
let _issuesPage = 0;
let _issuesAll = [];      // confirmed findings
let _issuesFP = [];       // dismissed / AI-rejected false positives
let _issuesActiveTab = 'all';  // 'all' | 'fp'

function switchIssuesTab(tab) {
  _issuesActiveTab = tab;
  const btnAll = document.getElementById('issues-tab-all');
  const btnFp  = document.getElementById('issues-tab-fp');
  if (btnAll) {
    btnAll.style.background = tab === 'all' ? 'var(--acc)' : '';
    btnAll.style.color      = tab === 'all' ? '#000' : '';
    btnAll.style.borderColor= tab === 'all' ? 'var(--acc)' : '';
  }
  if (btnFp) {
    btnFp.style.background = tab === 'fp' ? '#7a2020' : '';
    btnFp.style.color      = tab === 'fp' ? '#ff6b6b' : '';
    btnFp.style.borderColor= tab === 'fp' ? '#7a2020' : '';
  }
  _renderIssuesPage();
}

function _buildIssuesList() {
  _issuesAll = [];
  _issuesFP  = [];
  for (const host of Object.keys(hosts)) {
    const seen = new Set();
    for (const id of (hosts[host].ids || [])) {
      const e = entries[id];
      if (!e?.findings?.length) continue;
      if (e.source === 'out-of-scope') continue;
      e.findings.forEach((f, fidx) => {
        if (!f.title) return;
        // An imported finding is only a real issue once the active replay CONFIRMS
        // it. Anything still queued for replay, or replayed without confirmation,
        // must not be surfaced as a finding — it is a hypothesis, not a vuln.
        if (f.import_status && f.import_status !== 'confirmed' && !f.confirmed) return;
        const key = (f.title || '') + '|' + (e.path || '') + '|' + (f.parameter || '');
        if (seen.has(key)) return;
        seen.add(key);
        const item = { host, f: { ...f, _entryId: id, _path: e.path, _fidx: fidx }, _fidx: fidx };
        if (f.dismissed) {
          _issuesFP.push(item);
        } else {
          _issuesAll.push(item);
        }
      });
    }
  }
  const sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorter = (a, b) => (sevRank[a.f.severity?.toLowerCase()] ?? 5) - (sevRank[b.f.severity?.toLowerCase()] ?? 5);
  _issuesAll.sort(sorter);
  _issuesFP.sort(sorter);
  // Update FP badge count
  const badge = document.getElementById('issues-fp-count');
  if (badge) badge.textContent = _issuesFP.length ? `(${_issuesFP.length})` : '';
}

function issuesPage(delta) {
  const total = Math.ceil(_issuesAll.length / _ISSUES_PER_PAGE);
  _issuesPage = Math.max(0, Math.min(_issuesPage + delta, total - 1));
  _renderIssuesPage();
}

const _issueSevCollapsed = {};

function _renderIssuesPage() {
  const wrap = document.getElementById('issues-wrap');
  const pager = document.getElementById('issues-pager');
  const lbl = document.getElementById('issues-page-lbl');
  const list = _issuesActiveTab === 'fp' ? _issuesFP : _issuesAll;
  const total = list.length;

  if (!total) {
    wrap.innerHTML = _issuesActiveTab === 'fp'
      ? '<div class="empty">No false positives yet.\nDismissed findings appear here.</div>'
      : '<div class="empty">No findings yet.\nScan requests to discover vulnerabilities.</div>';
    if (pager) pager.style.display = 'none';
    return;
  }
  if (pager) pager.style.display = 'none';

  // Group by severity
  const groups = {};
  list.forEach(({ host, f }, idx) => {
    const sev = (f.severity || 'info').toLowerCase();
    if (!groups[sev]) groups[sev] = [];
    groups[sev].push({ host, f, idx });
  });

  let html = '';
  for (const sev of _SEV_ORDER) {
    const items = groups[sev];
    if (!items || !items.length) continue;
    const collapsed = _issueSevCollapsed[sev];
    const color = _SEV_COLOR[sev] || 'var(--txt2)';
    html += `<div style="margin-bottom:6px">
      <div onclick="toggleIssueGroup('${sev}')"
           style="display:flex;align-items:center;gap:8px;padding:5px 8px;
                  background:var(--bg2);border:1px solid var(--bdr);border-radius:4px;
                  cursor:pointer;user-select:none;margin-bottom:4px">
        <span style="color:${color};font-weight:600;font-size:11px">${_SEV_LABEL[sev] || sev}</span>
        <span style="background:${color}25;color:${color};border:1px solid ${color}50;
                     border-radius:10px;padding:0 6px;font-size:10px;font-weight:600">${items.length}</span>
        <span style="margin-left:auto;color:var(--txt2);font-size:11px">${collapsed ? '▸' : '▾'}</span>
      </div>
      <div id="issue-group-${sev}" style="display:${collapsed ? 'none' : 'block'}">
        ${items.map(({ host, f, idx }) => _buildIssueCard(host, f, idx)).join('')}
      </div>
    </div>`;
  }
  wrap.innerHTML = html;
}

function toggleIssueGroup(sev) {
  _issueSevCollapsed[sev] = !_issueSevCollapsed[sev];
  const el = document.getElementById('issue-group-' + sev);
  if (el) el.style.display = _issueSevCollapsed[sev] ? 'none' : 'block';
  // Update arrow
  _renderIssuesPage();
}

function _hlHttp(text, terms, color, bg) {
  // Escape the raw text for HTML, then wrap each matching term in a highlight span.
  // terms is an array of strings — blanks and very-short ones are skipped.
  let escaped = esc(text);
  const seen = new Set();
  for (const term of terms) {
    if (!term || term.length < 4) continue;
    // Deduplicate terms that share a prefix (e.g. evidence already contains payload)
    if ([...seen].some(s => s.includes(term) || term.includes(s))) continue;
    seen.add(term);
    // Escape the term for use inside a regex (match literal string in escaped HTML)
    const escapedTerm = esc(term).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (!escapedTerm) continue;
    escaped = escaped.replace(
      new RegExp(escapedTerm, 'g'),
      `<span style="background:${bg};color:${color};border-radius:2px;padding:0 1px">$&</span>`
    );
  }
  return escaped;
}

function _buildIssueCard(host, f, globalIdx) {
  const sev = (f.severity || 'info').toLowerCase();
  const sc = _SEV_CLASS[sev] || 'I';
  const uid = esc(f._entryId) + '-' + globalIdx;
  const entryId = esc(f._entryId);
  const evidence = esc(f.evidence || '');
  const cwe = f.cwe ? `<div class="iissue-cwe">${esc(f.cwe)}</div>` : '';
  const payload = f.payload ? `<div class="iissue-cwe">Payload: <code>${esc(f.payload)}</code></div>` : '';
  // validated_by is now a list; normalise legacy strings for backwards compat
  const _vbyRaw = f.validated_by;
  const _vbyList = Array.isArray(_vbyRaw) ? _vbyRaw : (_vbyRaw ? [_vbyRaw] : ['passive']);
  const _VBY_LABEL = {
    ai:'AI validated',passive:'Passive',imported:'Imported',
    browser:'Browser confirmed',time_based:'Time-based',oob_callback:'OOB callback',
    error_pattern:'Error pattern',file_match:'File match',secret_pattern:'Secret pattern',
    response_diff:'Response diff',pattern:'Pattern match',
    // legacy single-string values
    'passive+ai':'Passive+AI',
  };
  const _VBY_CLASS = {
    ai:'vbdg-ai',passive:'vbdg-passive',imported:'vbdg-imported',
    browser:'vbdg-browser',time_based:'vbdg-time_based',oob_callback:'vbdg-oob_callback',
    error_pattern:'vbdg-error_pattern',file_match:'vbdg-file_match',secret_pattern:'vbdg-secret_pattern',
    response_diff:'vbdg-response_diff',pattern:'vbdg-pattern',
    'passive+ai':'vbdg-pai',
  };
  const vBadge = _vbyList.map(v => {
    if (v === 'ai' && f.dismissed) {
      return `<span class="vbdg vbdg-dismissed" title="AI reviewed and rejected this finding">AI rejected</span>`;
    }
    const lbl = _VBY_LABEL[v] || v;
    const cls = _VBY_CLASS[v] || 'vbdg-pattern';
    const tip = (v === 'ai' && f.validated_at)
      ? 'AI validated ' + f.validated_at.replace('T', ' ').slice(0, 16)
      : 'Detection method: ' + lbl;
    return `<span class="vbdg ${cls}" title="${tip}">${lbl}</span>`;
  }).join('');
  const importStatus = f.import_status;
  const _importTip = esc(f.reasoning || '');
  const importBadge = importStatus
    ? (importStatus === 'confirmed'
        ? `<span style="margin-left:6px;font-size:9px;padding:1px 5px;border-radius:3px;background:#1a3a1a;color:#4caf50;border:1px solid #4caf50;cursor:help"
                 title="${_importTip}">Replay confirmed</span>`
        : importStatus === 'unconfirmed'
          ? `<span style="margin-left:6px;font-size:9px;padding:1px 5px;border-radius:3px;background:#3a2a0a;color:#ff9800;border:1px solid #ff9800;cursor:help"
                   title="${_importTip}">Replay unconfirmed</span>`
          : importStatus === 'error'
            ? `<span style="margin-left:6px;font-size:9px;padding:1px 5px;border-radius:3px;background:#2a1a1a;color:#ef5350;border:1px solid #ef5350;cursor:help"
                     title="${_importTip}">Scan error</span>`
          : importStatus === 'unreachable'
            ? `<span style="margin-left:6px;font-size:9px;padding:1px 5px;border-radius:3px;background:#2a1a1a;color:#ef5350;border:1px solid #ef5350;cursor:help"
                     title="${_importTip}">Unreachable</span>`
          : importStatus === 'queued'
            ? `<span style="margin-left:6px;font-size:9px;padding:1px 5px;border-radius:3px;background:#1a1a1a;color:var(--txt2);border:1px solid var(--bdr)"
                     title="${_importTip}">Pending scan</span>`
            : `<span style="margin-left:6px;font-size:9px;padding:1px 5px;border-radius:3px;background:#1a1a2a;color:var(--txt2);border:1px solid var(--bdr)"
                     title="${_importTip}">Not replayed</span>`)
    : '';
  const snippetHtml = f.snippet
    ? `<div style="margin-top:6px;font-size:10px;color:var(--txt2)">Line ${f.line_no ?? '?'}:</div>
       <pre class="iissue-snippet">${esc(f.snippet)}</pre>` : '';
  const reasoningHtml = f.reasoning
    ? (f.dismissed
        ? `<div style="margin-top:8px;padding:6px 10px;background:#2a1a1a;border-left:3px solid #ef5350;border-radius:2px">
             <div style="font-size:9px;font-weight:600;color:#ef5350;text-transform:uppercase;letter-spacing:.5px;margin-bottom:3px">AI rejection reason</div>
             <div style="font-size:10.5px;color:var(--txt);line-height:1.5">${esc(f.reasoning)}</div>
           </div>`
        : `<div style="margin-top:6px;padding:5px 8px;background:#1a1a2a;border-left:3px solid var(--acc);border-radius:2px">
             <div style="font-size:9px;font-weight:600;color:var(--acc);text-transform:uppercase;letter-spacing:.5px;margin-bottom:3px">AI validator reasoning</div>
             <div style="font-size:10.5px;color:var(--txt);line-height:1.5">${esc(f.reasoning)}</div>
           </div>`)
    : '';
  const paramHtml = f.parameter && f.parameter !== 'response_body'
    ? `<div style="margin-top:4px;font-size:10px"><span style="color:var(--txt2)">Parameter:</span> <code style="color:var(--orange)">${esc(f.parameter)}</code></div>` : '';
  const _ibrReason = f.browser_confirm_reason || '';
  const _ibrTooltipMap = {
    'csp_or_sink': 'JS did not execute (CSP, different sink, or alert suppressed)',
    'timeout':     'Browser timed out loading the page',
    'confirmed':   'JS executed in browser',
  };
  const _ibrTooltip = _ibrTooltipMap[_ibrReason] || (_ibrReason.startsWith('error:') ? _ibrReason.slice(6) : '');
  const browserBadge = f.browser_confirmed === true
    ? `<span style="margin-left:6px;font-size:9px;padding:1px 5px;border-radius:3px;background:#1a3a1a;color:#4caf50;border:1px solid #4caf50"
             title="JS executed in browser">Browser confirmed</span>`
    : f.browser_confirmed === false
      ? `<span style="margin-left:6px;font-size:9px;padding:1px 5px;border-radius:3px;background:#3a2a0a;color:#ff9800;border:1px solid #ff9800;cursor:help"
               title="${esc(_ibrTooltip)}">${
                 _ibrReason === 'timeout' ? 'Browser timeout' :
                 _ibrReason === 'csp_or_sink' ? 'JS not executed' :
                 _ibrReason.startsWith('error:') ? 'Browser error' :
                 'Browser not confirmed'
               }</span>`
      : '';
  const _httpPair = (reqText, respText, reqLabel, respLabel, hlTerms) => `
    ${reqText ? `<div style="margin-top:6px">
      <div style="font-size:9px;color:var(--txt2);margin-bottom:2px;text-transform:uppercase;letter-spacing:.4px">${reqLabel}</div>
      <pre style="margin:0;padding:8px;background:#0a0a1a;border:1px solid var(--bdr);border-radius:3px;font-size:10px;overflow:auto;white-space:pre-wrap;word-break:break-all;color:#7eb8f7;max-height:260px">${_hlHttp(reqText, [f.payload], '#ffe066', '#2a2000')}</pre>
    </div>` : ''}
    ${respText ? `<div style="margin-top:6px">
      <div style="font-size:9px;color:var(--txt2);margin-bottom:2px;text-transform:uppercase;letter-spacing:.4px">${respLabel}</div>
      <pre style="margin:0;padding:8px;background:#0a1a0a;border:1px solid var(--bdr);border-radius:3px;font-size:10px;overflow:auto;white-space:pre-wrap;word-break:break-all;color:#7ef7a0;max-height:260px">${_hlHttp(respText, hlTerms, '#ffe066', '#2a2000')}</pre>
    </div>` : ''}`;
  const hasProbe = f.probe_request || f.probe_response;
  const httpDetails = (f.raw_request || f.raw_response) ? `
    <details style="margin-top:8px">
      <summary style="cursor:pointer;font-size:10px;color:var(--txt2);user-select:none">HTTP Request / Response${hasProbe ? ' · <span style="color:#4caf50">+ Exploit Proof</span>' : ''}</summary>
      ${hasProbe ? `<div style="margin-top:8px;padding:6px 8px;background:#0a1a0a;border-left:2px solid var(--txt3);border-radius:2px;font-size:9px;color:var(--txt3);margin-bottom:4px">
        Baseline — clean request with original parameter value (no payload)
      </div>` : ''}
      ${_httpPair(f.raw_request, f.raw_response, 'Request', 'Response', [f.evidence, f.payload])}
      ${hasProbe ? `<div style="margin-top:12px;padding:6px 8px;background:#0a200a;border-left:2px solid #4caf50;border-radius:2px;font-size:9px;color:#4caf50;margin-bottom:4px">
        Exploit Proof — probe with payload injected; confirms the vulnerability is exploitable
      </div>
      ${_httpPair(f.probe_request, f.probe_response, 'Probe Request', 'Probe Response', [f.evidence, f.payload])}` : ''}
    </details>` : '';
  const hostBadge = `<span style="font-size:9px;color:var(--txt2);margin-left:6px">${esc(host)}</span>`;
  const hasAiValidation = _vbyList.includes('ai');
  const fidx = f._fidx ?? globalIdx;
  const validateBtn = !hasAiValidation
    ? `<button class="tbtn" id="vbtn-${uid}" style="font-size:9px;padding:1px 7px;flex-shrink:0;color:var(--acc);border-color:var(--acc)"
        title="Ask the Red-Team Validator (LLM) to confirm or reject this finding"
        onclick="event.stopPropagation();validateFindingWithAI('${entryId}',${fidx},'${uid}')">Validate with AI</button>`
    : '';
  const dismissBtn = f.dismissed
    ? `<button class="tbtn" style="font-size:9px;padding:1px 7px;margin-left:auto;flex-shrink:0;color:#4caf50;border-color:#2a5a2a"
        title="Restore to active findings"
        onclick="event.stopPropagation();restoreFinding('${entryId}',${fidx})">Restore</button>`
    : `<button class="tbtn" style="font-size:9px;padding:1px 7px;margin-left:auto;flex-shrink:0;color:var(--txt2)"
        title="Mark as false positive — moves to False Positives tab"
        onclick="event.stopPropagation();dismissFinding('${entryId}',${globalIdx})">Dismiss FP</button>`;
  return `<div class="iissue" id="iissue-${uid}" data-entry-id="${entryId}" onclick="toggleIssue('${uid}','${entryId}')">
    <div class="iissue-row">
      <span class="iissue-sev s${sc}">${_SEV_LABEL[sev]}</span>
      <div class="iissue-info">
        <div class="iissue-title">${esc(f.title || 'Finding')}${vBadge}${browserBadge}${importBadge}</div>
        <div class="iissue-meta">${esc(f.attack_type || 'passive')} · ${esc(f._path)}${hostBadge}</div>
      </div>
      ${validateBtn}
      ${dismissBtn}
      <span class="iissue-arrow" style="margin-left:6px">▶</span>
    </div>
    <div class="iissue-detail" onclick="event.stopPropagation()">
      <div class="iissue-evidence">${evidence}</div>
      ${paramHtml}${snippetHtml}${reasoningHtml}${cwe}${payload}${httpDetails}
      <span class="iissue-goto" onclick="goToEntry('${entryId}')">Go to request →</span>
      <span class="iissue-goto" style="margin-left:12px" onclick="repLoadEntry('${entryId}')">Send to Repeater →</span>
    </div>
  </div>`;
}

async function dismissFinding(entryId, globalIdx) {
  // Look in both lists — the user may dismiss from either tab
  const item = (_issuesActiveTab === 'fp' ? _issuesFP : _issuesAll)[globalIdx]
    || _issuesAll.find(i => i.f._entryId === entryId && i._fidx === globalIdx)
    || _issuesFP.find(i => i.f._entryId === entryId && i._fidx === globalIdx);
  if (!item) return;
  const entry = entries[entryId];
  if (!entry || !entry.findings) return;
  const findingIdx = item._fidx;
  if (findingIdx == null || findingIdx < 0 || findingIdx >= entry.findings.length) return;
  // Mark dismissed in-place so it moves to the FP tab instead of disappearing
  const r = await fetch(`/api/findings/${encodeURIComponent(entryId)}/${findingIdx}/dismiss`, { method: 'POST' });
  if (!r.ok) { showToast('Could not dismiss finding', true); return; }
  entry.findings[findingIdx].dismissed = true;
  _buildIssuesList();
  _renderIssuesPage();
  showToast('Moved to False Positives');
}

async function restoreFinding(entryId, findingIdx) {
  const r = await fetch(`/api/findings/${encodeURIComponent(entryId)}/${findingIdx}/restore`, { method: 'POST' });
  if (!r.ok) { showToast('Could not restore finding', true); return; }
  const entry = entries[entryId];
  if (entry?.findings?.[findingIdx]) entry.findings[findingIdx].dismissed = false;
  _buildIssuesList();
  _renderIssuesPage();
  showToast('Finding restored');
}

async function validateFindingWithAI(entryId, fidx, uid) {
  const btn = document.getElementById('vbtn-' + uid);
  if (btn) { btn.disabled = true; btn.textContent = 'Validating...'; }
  try {
    const r = await fetch('/api/findings/validate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ entry_id: entryId, finding_index: fidx }),
    });
    const d = await r.json();
    if (!r.ok) { showToast(d.error || 'Validation failed', 'error'); return; }
    if (d.confirmed) {
      showToast('AI confirmed — real finding');
    } else {
      // AI rejected → auto-dismiss to False Positives tab
      const entry = entries[entryId];
      if (entry?.findings?.[fidx]) {
        await fetch(`/api/findings/${encodeURIComponent(entryId)}/${fidx}/dismiss`, { method: 'POST' });
        entry.findings[fidx].dismissed = true;
        showToast('AI rejected — moved to False Positives');
      } else {
        showToast('AI did not confirm — possible false positive');
      }
    }
    _buildIssuesList();
    _renderIssuesPage();
  } catch (e) {
    showToast('Validation error', 'error');
  } finally {
    if (btn) { btn.disabled = false; }
  }
}

function renderAllIssues() {
  _issuesPage = 0;
  _buildIssuesList();
  _renderIssuesPage();
}

function toggleIssue(uid, entryId) {
  const el = document.getElementById('iissue-' + uid);
  if (!el) return;
  el.classList.toggle('open');
}

function goToEntry(id) {
  switchProxySub('history');
  switchMain('proxy');
  selectRow(id);
  setDTab('findings');
  setTimeout(() => document.getElementById('row-' + id)?.scrollIntoView({ block: 'nearest' }), 50);
}

// ── import findings modal ──────────────────────────────────────────────
async function openImportFindingsModal() {
  document.getElementById('import-findings-modal').style.display = 'flex';
  document.getElementById('import-status').textContent = '';
  const btn = document.getElementById('import-submit-btn');
  btn.disabled = false;
  btn.textContent = 'Import & Scan';
  // Restore the submit handler in case a prior run repointed it to close.
  btn.onclick = submitImportFindings;
  await _loadImportHosts();
}

async function _loadImportHosts() {
  const wrap = document.getElementById('import-hosts-list');
  try {
    const resp = await fetch('/api/hosts');
    const hosts = await resp.json();
    if (!hosts.length) {
      wrap.innerHTML = '<span style="font-size:10px;color:var(--txt3);font-style:italic">No hosts in proxy yet — browse the target first</span>';
      return;
    }
    wrap.innerHTML = hosts.map(h =>
      `<label style="display:flex;align-items:center;gap:5px;font-size:11px;cursor:pointer;
               background:var(--bg3);border:1px solid var(--bdr);border-radius:3px;padding:3px 8px;
               white-space:nowrap">
        <input type="checkbox" class="import-host-chk" value="${esc(h.base_url)}" checked>
        <span style="color:var(--txt)">${esc(h.base_url)}</span>
        <span style="color:var(--txt3);font-size:9px">${h.count} req</span>
       </label>`
    ).join('');
  } catch(e) {
    wrap.innerHTML = '<span style="font-size:10px;color:var(--red)">Failed to load hosts</span>';
  }
}

function closeImportFindingsModal() {
  _stopImportPoll();
  document.getElementById('import-findings-modal').style.display = 'none';
  document.getElementById('import-manual-host-list').innerHTML = '';
  document.getElementById('import-manual-host').value = '';
  document.getElementById('import-content').value = '';
  document.getElementById('import-status').textContent = '';
}

function importFileSelected(input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    document.getElementById('import-content').value = e.target.result;
  };
  reader.readAsText(file);
}

async function testSuggestion(host, method, path, attackType, parameter) {
  const btn = event.target;
  btn.textContent = '...';
  btn.disabled = true;
  try {
    const r = await fetch('/api/ai/suggestions/test', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({host, method, path, attack_type: attackType, parameter}),
    });
    const d = await r.json();
    if (d.ok) {
      btn.textContent = 'queued';
      btn.style.background = 'var(--orange)';
    } else {
      btn.textContent = 'no entry';
      btn.style.background = 'var(--txt3)';
      btn.title = d.message || 'No matching proxy entry — browse to this endpoint first';
      btn.disabled = false;
    }
  } catch(e) {
    btn.textContent = 'error';
    btn.disabled = false;
  }
}

function importAddManualHost() {
  const input = document.getElementById('import-manual-host');
  const val = input.value.trim().replace(/\/$/, '');
  if (!val) return;
  // Prepend https:// if no scheme given
  const host = val.startsWith('http') ? val : 'https://' + val;
  const listEl = document.getElementById('import-manual-host-list');
  // Avoid duplicates
  if ([...listEl.querySelectorAll('.import-manual-host-tag')].some(el => el.dataset.host === host)) {
    input.value = '';
    return;
  }
  const tag = document.createElement('span');
  tag.className = 'import-manual-host-tag';
  tag.dataset.host = host;
  tag.style.cssText = 'display:flex;align-items:center;gap:4px;background:var(--bg3);border:1px solid var(--acc2);border-radius:3px;padding:2px 7px;font-size:11px;color:var(--acc2)';
  tag.innerHTML = `<span style="font-family:monospace">${esc(host)}</span><span style="cursor:pointer;color:var(--txt3);margin-left:2px" onclick="this.parentElement.remove()">✕</span>`;
  listEl.appendChild(tag);
  input.value = '';
}

let _importPollTimer = null;

function _stopImportPoll() {
  if (_importPollTimer) { clearTimeout(_importPollTimer); _importPollTimer = null; }
}

async function submitImportFindings() {
  const content = document.getElementById('import-content').value.trim();
  const selectedHosts = [...document.querySelectorAll('.import-host-chk:checked')].map(c => c.value);
  const manualHosts  = [...document.querySelectorAll('.import-manual-host-tag')].map(el => el.dataset.host);
  const allHosts = [...selectedHosts, ...manualHosts];
  const statusEl = document.getElementById('import-status');
  const btn = document.getElementById('import-submit-btn');

  if (!content) {
    statusEl.textContent = 'Paste or upload a report first.';
    statusEl.style.color = 'var(--red)';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Parsing...';
  statusEl.style.color = 'var(--txt2)';
  statusEl.textContent = 'Sending to AI for parsing and endpoint inference — this can take a minute for long reports...';

  try {
    const resp = await fetch('/api/findings/import', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        content,
        target_hosts: allHosts,
        base_url: manualHosts.length === 1 ? manualHosts[0] : '',
      }),
    });
    const data = await resp.json();

    if (!resp.ok || data.error) {
      statusEl.textContent = 'Error: ' + (data.error || resp.statusText);
      statusEl.style.color = 'var(--red)';
      btn.disabled = false;
      btn.textContent = 'Import & Scan';
      return;
    }

    _pollImportJob(data.job_id, statusEl, btn);
  } catch (e) {
    statusEl.textContent = 'Request failed: ' + e.message;
    statusEl.style.color = 'var(--red)';
    btn.disabled = false;
    btn.textContent = 'Import & Scan';
  }
}

async function _pollImportJob(jobId, statusEl, btn) {
  _stopImportPoll();

  const poll = async () => {
    let resp, data;
    try {
      resp = await fetch(`/api/findings/import/${jobId}`);
      data = await resp.json();
    } catch (e) {
      statusEl.textContent = 'Lost connection while checking import status: ' + e.message;
      statusEl.style.color = 'var(--red)';
      btn.disabled = false;
      btn.textContent = 'Import & Scan';
      return;
    }

    if (!resp.ok || data.error) {
      statusEl.textContent = 'Error: ' + (data.error || resp.statusText);
      statusEl.style.color = 'var(--red)';
      btn.disabled = false;
      btn.textContent = 'Import & Scan';
      return;
    }

    if (data.status === 'parsing' || data.status === 'storing') {
      const label = data.status === 'parsing' ? 'AI is parsing the report' : 'Storing findings';
      const p = data.progress;
      statusEl.textContent = p ? `${label}... (${p.done}/${p.total})` : `${label}...`;
      btn.textContent = data.status === 'parsing' ? 'Parsing...' : 'Storing...';
      _importPollTimer = setTimeout(poll, 1500);
      return;
    }

    // status === 'done' — the full result payload is returned directly
    if (data.parsed === 0) {
      statusEl.textContent = data.message || 'No findings found in the provided content.';
      statusEl.style.color = 'var(--yellow)';
      btn.disabled = false;
      btn.textContent = 'Import & Scan';
      return;
    }

    const scanned = data.scan_queued ?? 0;
    const pending = data.scan_pending ?? 0;
    let msg = `Parsed ${data.parsed} finding${data.parsed !== 1 ? 's' : ''}.`;
    if (scanned > 0) msg += ` ${scanned} queued for scan.`;
    if (pending > 0) msg += ` ${pending} parked — will test automatically as matching URLs appear in proxy.`;
    if (scanned === 0 && pending === 0 && data.parsed > 0) msg += ' No matching host in proxy yet — browse the target and they will be tested automatically.';
    statusEl.textContent = msg;
    statusEl.style.color = '#4caf50';

    if (document.getElementById('st-issues').classList.contains('on')) renderAllIssues();

    // Parsing is done and the scan is now queued on the server — it runs in the
    // background whether or not this modal stays open. Auto-close and surface the
    // summary as a toast so the operator keeps working while the scan proceeds.
    // (The button previously read "Done" but still bound submitImportFindings,
    // so a click re-imported — repoint it to close instead.)
    const scanning = scanned > 0 || pending > 0;
    btn.textContent = 'Close';
    btn.disabled = false;
    btn.onclick = closeImportFindingsModal;
    showToast(scanning ? msg + ' Scanning in the background.' : msg);
    setTimeout(closeImportFindingsModal, 1200);
  };

  poll();
}

