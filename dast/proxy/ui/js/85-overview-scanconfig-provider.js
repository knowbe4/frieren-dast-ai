// ── overview dashboard ─────────────────────────────────────────────────

async function loadOverview() {
  try {
    const [statusR, agentsR, ovR] = await Promise.all([
      fetch('/api/status'),
      fetch('/api/ai/agents'),
      fetch('/api/overview'),
    ]);
    const s     = await statusR.json();
    const aData = await agentsR.json();
    const ov    = await ovR.json();
    const st    = aData.stats || {};
    const critHigh = (ov.sev_counts?.critical || 0) + (ov.sev_counts?.high || 0);

    // Stat cards
    const cards = [
      {label:'Requests',          value: ov.total_requests ?? 0,  color:'var(--txt)'},
      {label:'Hosts',             value: ov.unique_hosts   ?? 0,  color:'var(--blue)'},
      {label:'Endpoints scanned', value: ov.ai_scanned     ?? 0,  color:'var(--orange)'},
      {label:'Total findings',    value: ov.total_findings ?? 0,  color:'var(--yellow)'},
      {label:'Critical / High',   value: critHigh,                color:'var(--red)'},
      {label:'Passive findings',  value: ov.passive_findings ?? 0, color:'var(--green)'},
    ];
    document.getElementById('ov-stat-cards').innerHTML = cards.map(c => `
      <div style="background:var(--bg2);border:1px solid var(--bdr);border-radius:5px;padding:14px 16px">
        <div style="font-size:10px;color:var(--txt2);margin-bottom:4px;text-transform:uppercase;letter-spacing:.4px">${esc(c.label)}</div>
        <div style="font-size:28px;font-weight:700;color:${c.color};line-height:1">${c.value}</div>
      </div>`).join('');

    // Findings by severity bars
    const sevCounts = ov.sev_counts || {};
    const maxSev = Math.max(1, ...Object.values(sevCounts));
    document.getElementById('ov-findings-sev').innerHTML = _SEV_ORDER.map(sev => {
      const n = sevCounts[sev] || 0;
      const pct = Math.round(n / maxSev * 100);
      return `<div style="display:flex;align-items:center;gap:8px">
        <div style="width:70px;font-size:11px;color:${_SEV_COLOR[sev]};text-transform:capitalize">${sev}</div>
        <div style="flex:1;height:8px;background:var(--bg3);border-radius:4px;overflow:hidden">
          <div style="width:${pct}%;height:100%;background:${_SEV_COLOR[sev]};border-radius:4px;transition:width .3s"></div>
        </div>
        <div style="width:28px;text-align:right;font-size:11px;color:var(--txt2)">${n}</div>
      </div>`;
    }).join('');

    // Agents pills
    if (aData.agents) {
      const agentColors = {
        xss:'var(--orange)',sqli:'var(--red)',ssrf:'var(--blue)',lfi:'var(--orange)',
        auth_bypass:'var(--red)',discovery:'var(--green)',sensitive_data:'var(--blue)',llm_injection:'#b48ead',
      };
      document.getElementById('ov-agents').innerHTML = aData.agents.map(a => `
        <span style="background:var(--bg3);border:1px solid var(--bdr);border-radius:12px;
                     padding:3px 10px;font-size:11px;color:${agentColors[a.attack_type]||'var(--txt)'}">
          ${esc(a.name)}
        </span>`).join('');
    }

    // Recent findings from server
    const recent = ov.recent_findings || [];
    if (!recent.length) {
      document.getElementById('ov-recent-findings').innerHTML =
        '<div style="color:var(--txt2);font-size:11px">No findings yet.</div>';
    } else {
      const _vLabel = {
        ai:'AI validated','passive+ai':'Passive+AI',pattern:'Pattern match',passive:'Passive',imported:'Imported',
        browser:'Browser confirmed',time_based:'Time-based',oob_callback:'OOB callback',
        error_pattern:'Error pattern',file_match:'File match',secret_pattern:'Secret pattern',response_diff:'Response diff',
      };
      const _vColor = {
        ai:'#4fc3f7','passive+ai':'#81d4fa',pattern:'#9e9e9e',passive:'#9e9e9e',imported:'#ce93d8',
        browser:'#4caf50',time_based:'#ffc107',oob_callback:'#ff9800',
        error_pattern:'#ef5350',file_match:'#81c784',secret_pattern:'#ba68c8',response_diff:'#4dd0e1',
      };
      document.getElementById('ov-recent-findings').innerHTML =
        `<table style="width:100%;border-collapse:collapse;font-size:11px">
          <thead><tr style="color:var(--txt2);border-bottom:1px solid var(--bdr)">
            <th style="padding:3px 8px;text-align:left;font-weight:500;width:70px">Severity</th>
            <th style="padding:3px 8px;text-align:left;font-weight:500">Title</th>
            <th style="padding:3px 8px;text-align:left;font-weight:500">Validated by</th>
            <th style="padding:3px 8px;text-align:left;font-weight:500">Host</th>
          </tr></thead>
          <tbody>${recent.map(f => {
            const _vbyRaw2 = f.validated_by;
            const _vbyList2 = Array.isArray(_vbyRaw2) ? _vbyRaw2 : (_vbyRaw2 ? [_vbyRaw2] : ['passive']);
            const vBadge = _vbyList2.map(v => {
              if (v === 'ai' && f.dismissed) {
                return `<span style="font-size:9px;padding:1px 5px;border-radius:3px;background:#ef535022;color:#ef5350;border:1px solid #ef535055;margin-right:3px">AI rejected</span>`;
              }
              const lbl = _vLabel[v] || v;
              const col = _vColor[v] || '#6b7280';
              // Enrich the AI badge with WHEN it was validated so a historical
              // AI verdict reads distinctly from current AI availability.
              let _tip = lbl;
              if (v === 'ai' && f.validated_at) {
                _tip = `AI validated ${f.validated_at.replace('T', ' ').slice(0, 16)}`;
              }
              return `<span title="${esc(_tip)}" style="font-size:9px;padding:1px 5px;border-radius:3px;background:${col}22;color:${col};border:1px solid ${col}55;margin-right:3px">${esc(lbl)}</span>`;
            }).join('');
            return `
            <tr style="border-bottom:1px solid var(--bdr3,#252525);cursor:pointer"
                onclick="goToEntry('${esc(f.entry_id||'')}')">
              <td style="padding:4px 8px;color:${_SEV_COLOR[f.severity]||'var(--txt2)'}">
                ${esc(f.severity||'?')}
              </td>
              <td style="padding:4px 8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:260px"
                  title="${esc(f.title||'')}">
                ${esc((f.title||'').slice(0,60))}
              </td>
              <td style="padding:4px 8px">${vBadge}</td>
              <td style="padding:4px 8px;color:var(--txt2);font-family:monospace;font-size:10px">
                ${esc(f.host||'')}
              </td>
            </tr>`;
          }).join('')}
          </tbody>
        </table>`;
    }

    // Engine status
    const aiOk = s.ai_enabled;
    document.getElementById('ov-engine').innerHTML = `
      <div style="display:flex;flex-direction:column;gap:8px;font-size:11px">
        <div style="display:flex;justify-content:space-between">
          <span style="color:var(--txt2)">AI status</span>
          <span style="color:${aiOk?'var(--green)':'var(--red)'}">${aiOk?'connected':'offline'}</span>
        </div>
        <div style="display:flex;justify-content:space-between">
          <span style="color:var(--txt2)">Endpoints scanned</span>
          <span style="color:var(--txt)">${ov.ai_scanned??0}</span>
        </div>
        <div style="display:flex;justify-content:space-between">
          <span style="color:var(--txt2)">AI-confirmed findings</span>
          <span style="color:var(--red)">${ov.ai_confirmed??0}</span>
        </div>
        <div style="display:flex;justify-content:space-between">
          <span style="color:var(--txt2)">Ruled safe by AI</span>
          <span style="color:var(--green)">${ov.ai_rejected??0}</span>
        </div>
        <hr style="border:none;border-top:1px solid var(--bdr);margin:4px 0">
        <div style="display:flex;justify-content:space-between">
          <span style="color:var(--txt2)">Passive findings</span>
          <span style="color:var(--orange)">${ov.passive_findings??0}</span>
        </div>
        ${(ov.pending_imports??0) > 0 ? `
        <div style="display:flex;justify-content:space-between">
          <span style="color:var(--txt2)" title="Imported findings waiting for a matching proxy URL">Pending imports</span>
          <span style="color:var(--yellow)">${ov.pending_imports}</span>
        </div>` : ''}
      </div>`;

  } catch(e) {
    console.error('loadOverview:', e);
  }
}

// ── scan config (engine settings) ─────────────────────────────────────
// Fill the primary/fast/validation model dropdowns from the backend's named
// presets (dast.config.settings.model_presets) — never hardcode a model
// ARN/name in the UI.
function populateModelPresets(presets) {
  const opts = presets.map(p => `<option value="${p.id}">${p.label}</option>`).join('');
  const setSelect = (elId, prefix) => {
    const el = document.getElementById(elId);
    if (!el) return;
    const prev = el.value;                       // preserve selection across repopulation
    el.innerHTML = (prefix || '') + opts;
    // Restore the prior value if it still exists among the new options.
    if (prev && [...el.options].some(o => o.value === prev)) el.value = prev;
  };
  setSelect('sc-model-id', '');
  setSelect('sc-fast-model-id', '<option value="">(use primary model)</option>');
  setSelect('sc-validation-model-id', '<option value="">(use primary model)</option>');
  // The free-text primary field (Anthropic/OpenAI/gateway) offers the same list
  // as autocomplete suggestions via a <datalist>, while staying free-text.
  const dl = document.getElementById('sc-model-list');
  if (dl) dl.innerHTML = opts;
}

// Fetch the model catalogue for the ACTIVE provider and repopulate the dropdowns.
// The backend returns provider-appropriate models (Anthropic/OpenAI/gateway live
// APIs; Bedrock static presets), so the Fast/Validation dropdowns no longer show
// Claude tiers when, e.g., OpenAI is selected. Falls back silently to whatever
// presets loadScanConfig already placed if the endpoint is unreachable.
async function loadProviderModels() {
  try {
    const r = await fetch('/api/ai/models');
    if (!r.ok) return;
    const data = await r.json();
    if (Array.isArray(data.models) && data.models.length) {
      populateModelPresets(data.models);
      // Re-apply saved tiered selections now that provider-specific options exist.
      const cfg = await fetch('/api/scan-config').then(x => x.json()).catch(() => ({}));
      const fast = document.getElementById('sc-fast-model-id');
      const val  = document.getElementById('sc-validation-model-id');
      if (fast && cfg.fast_model_id && [...fast.options].some(o => o.value === cfg.fast_model_id)) fast.value = cfg.fast_model_id;
      if (val && cfg.validation_model_id && [...val.options].some(o => o.value === cfg.validation_model_id)) val.value = cfg.validation_model_id;
    }
  } catch (e) { console.error('loadProviderModels:', e); }
}

async function loadScanConfig() {
  try {
    const r = await fetch('/api/scan-config');
    if (!r.ok) return;
    const c = await r.json();
    const s = v => document.getElementById(v);
    if (s('sc-workers'))           s('sc-workers').value           = c.workers            ?? 2;
    if (s('sc-probe-concurrency')) s('sc-probe-concurrency').value = c.probe_concurrency  ?? 3;
    if (s('sc-passive-enabled'))   s('sc-passive-enabled').checked = c.passive_enabled    ?? true;
    if (s('sc-passive-ai'))        s('sc-passive-ai').checked      = c.passive_ai         ?? true;
    if (s('sc-passive-aggressive')) s('sc-passive-aggressive').checked = c.passive_aggressive_rules ?? false;
    if (s('sc-active-enabled'))    s('sc-active-enabled').checked  = c.active_enabled     ?? true;
    if (s('sc-llm-planner'))       s('sc-llm-planner').checked     = c.llm_planner        ?? true;
    if (s('sc-llm-validator'))     s('sc-llm-validator').checked   = c.llm_validator      ?? true;
    if (s('sc-discovery-llm-classify')) s('sc-discovery-llm-classify').checked = c.discovery_llm_classify ?? false;
    if (s('sc-probe-diff'))        s('sc-probe-diff').checked      = c.probe_diff          ?? false;
    // Populate the model presets from the backend (dast.config.settings) —
    // the UI never hardcodes a model ARN/name.
    populateModelPresets(c.model_presets ?? []);
    if (s('sc-model-id') && c.model_id) s('sc-model-id').value = c.model_id;
    if (s('sc-model-freeform') && c.model_id) s('sc-model-freeform').value = c.model_id;
    if (s('sc-fast-model-id'))       s('sc-fast-model-id').value       = c.fast_model_id       ?? '';
    if (s('sc-validation-model-id')) s('sc-validation-model-id').value = c.validation_model_id ?? '';
    // Provider fields (API keys are never returned — only *_set booleans).
    if (s('sc-ai-provider'))    s('sc-ai-provider').value    = c.ai_provider ?? 'bedrock';
    if (s('sc-anthropic-url'))  s('sc-anthropic-url').value  = c.anthropic_base_url ?? '';
    if (s('sc-openai-url'))     s('sc-openai-url').value     = c.openai_base_url ?? '';
    if (s('sc-gateway-url'))    s('sc-gateway-url').value    = c.gateway_base_url ?? '';
    if (s('sc-anthropic-key-set')) s('sc-anthropic-key-set').style.display = c.anthropic_api_key_set ? 'block' : 'none';
    if (s('sc-openai-key-set'))    s('sc-openai-key-set').style.display    = c.openai_api_key_set ? 'block' : 'none';
    if (typeof onProviderChange === 'function') onProviderChange();
    // Replace the static Claude presets with the active provider's real catalogue.
    loadProviderModels();
    if (s('sc-confidence')) {
      const v = c.confidence_threshold ?? 0.5;
      s('sc-confidence').value = v;
      const lbl = document.getElementById('sc-confidence-val');
      if (lbl) lbl.textContent = parseFloat(v).toFixed(2);
    }
    if (s('sc-budget')) s('sc-budget').value = c.scan_budget_seconds ?? 120;
  } catch(e) {}
}

async function saveScanConfig() {
  const g = id => document.getElementById(id);
  const v = (id, fallback) => { const el = g(id); return el ? el.value : fallback; };
  const chk = (id, fallback) => { const el = g(id); return el ? el.checked : fallback; };
  const modelId = currentModelId();
  const body = {
    workers:              parseInt(v('sc-workers', 2))           || 2,
    probe_concurrency:    parseInt(v('sc-probe-concurrency', 3)) || 3,
    passive_enabled:      chk('sc-passive-enabled', true),
    passive_ai:           chk('sc-passive-ai', true),
    passive_aggressive_rules: chk('sc-passive-aggressive', false),
    active_enabled:       chk('sc-active-enabled', true),
    llm_planner:          chk('sc-llm-planner', true),
    llm_validator:        chk('sc-llm-validator', true),
    discovery_llm_classify: chk('sc-discovery-llm-classify', false),
    probe_diff:            chk('sc-probe-diff', false),
    confidence_threshold:  parseFloat(v('sc-confidence', 0.5)),
    fast_model_id:         v('sc-fast-model-id', ''),
    validation_model_id:   v('sc-validation-model-id', ''),
    scan_budget_seconds:   parseInt(v('sc-budget', 300)) || 300,
    ...(modelId ? { model_id: modelId } : {}),
  };
  try {
    const r = await fetch('/api/scan-config', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify(body),
    });
    const msg = document.getElementById('scan-config-msg');
    if (msg) {
      msg.textContent = r.ok ? 'Applied.' : 'Failed.';
      msg.style.color = r.ok ? 'var(--green)' : 'var(--red)';
      msg.style.display = 'inline';
      setTimeout(() => { msg.style.display = 'none'; }, 2500);
    }
    // Refresh the badge so an updated model/tier shows without a manual reload.
    if (r.ok && typeof loadAiStatus === 'function') loadAiStatus();
  } catch(e) {
    console.error('saveScanConfig:', e);
  }
}

// The active model id comes from the ARN preset dropdown for Bedrock, or the
// free-form model-name field for Anthropic/OpenAI.
function currentModelId() {
  const g = id => document.getElementById(id);
  const provider = g('sc-ai-provider') ? g('sc-ai-provider').value : 'bedrock';
  if (provider === 'bedrock') return g('sc-model-id') ? g('sc-model-id').value : '';
  return g('sc-model-freeform') ? g('sc-model-freeform').value.trim() : '';
}

async function saveAiModel() {
  const modelId = currentModelId();
  if (!modelId) return;
  const r = await fetch('/api/scan-config', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({ model_id: modelId }),
  });
  const msg = document.getElementById('ai-model-msg');
  if (r.ok) {
    msg.textContent = 'Applied.';
    msg.style.color = 'var(--green)';
  } else {
    msg.textContent = 'Failed.';
    msg.style.color = 'var(--red)';
  }
  msg.style.display = 'inline';
  setTimeout(() => { msg.style.display = 'none'; }, 2500);
  // Refresh the badge so the new model label shows without a manual reload.
  if (r.ok && typeof loadAiStatus === 'function') loadAiStatus();
}

// ── AI provider selection ─────────────────────────────────────────────
// Toggle credential rows + the model input style to match the chosen provider.
// Bedrock uses the ARN preset dropdown; Anthropic/OpenAI use a free-form model
// name field (an ARN is meaningless there).
function onProviderChange() {
  const g = id => document.getElementById(id);
  const provider = g('sc-ai-provider') ? g('sc-ai-provider').value : 'bedrock';
  if (g('provider-anthropic')) g('provider-anthropic').style.display = provider === 'anthropic' ? 'block' : 'none';
  if (g('provider-openai'))    g('provider-openai').style.display    = provider === 'openai'    ? 'block' : 'none';
  if (g('provider-gateway'))   g('provider-gateway').style.display   = provider === 'gateway'   ? 'block' : 'none';
  const isBedrock = provider === 'bedrock';
  if (g('sc-model-id'))       g('sc-model-id').style.display       = isBedrock ? '' : 'none';
  if (g('sc-model-freeform')) g('sc-model-freeform').style.display = isBedrock ? 'none' : '';
  // NOTE: do NOT refresh the model catalogue here — on a mere dropdown change the
  // backend is still on the OLD provider (and may lack the new key), so listing
  // would show stale models. The catalogue refreshes after "Apply Provider".
}

async function saveProvider() {
  const g = id => document.getElementById(id);
  const provider = g('sc-ai-provider').value;
  const body = {
    ai_provider: provider,
    anthropic_base_url: g('sc-anthropic-url') ? g('sc-anthropic-url').value.trim() : '',
    openai_base_url:    g('sc-openai-url')    ? g('sc-openai-url').value.trim()    : '',
    gateway_base_url:   g('sc-gateway-url')   ? g('sc-gateway-url').value.trim()   : '',
  };
  // Only send a key when the user typed one — an empty field keeps the existing
  // key server-side (the field is absent from the body, not blank).
  const antKey = g('sc-anthropic-key') ? g('sc-anthropic-key').value : '';
  const oaiKey = g('sc-openai-key')    ? g('sc-openai-key').value    : '';
  if (antKey) body.anthropic_api_key = antKey;
  if (oaiKey) body.openai_api_key = oaiKey;
  const msg = g('ai-provider-msg');
  try {
    const r = await fetch('/api/scan-config', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify(body),
    });
    if (msg) {
      msg.textContent = r.ok ? 'Applied.' : 'Failed.';
      msg.style.color = r.ok ? 'var(--green)' : 'var(--red)';
      msg.style.display = 'inline';
      setTimeout(() => { msg.style.display = 'none'; }, 2500);
    }
    if (r.ok) {
      // Clear the password fields and refresh the "configured" hints.
      if (g('sc-anthropic-key')) g('sc-anthropic-key').value = '';
      if (g('sc-openai-key'))    g('sc-openai-key').value = '';
      loadScanConfig();
      // Re-poll the connection badge right away: the backend cleared its AI-status
      // cache on the provider switch, so a fresh poll flips the badge to the new
      // provider immediately instead of waiting for the next interval. This is the
      // "auto-refresh on save" — no manual F5 needed (important in the desktop app).
      if (typeof loadAiStatus === 'function') loadAiStatus();
      if (typeof loadMcpStatus === 'function') loadMcpStatus();
      // loadScanConfig() above already calls loadProviderModels(), so the now-active
      // provider's catalogue (not the previous provider's) fills the dropdowns.
    }
  } catch(e) {
    console.error('saveProvider:', e);
  }
}

window.onerror = function(msg, src, line, col, err) {
  fetch('/api/client-error', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message: String(msg), source: src, line, col, stack: err?.stack || ''}),
  }).catch(() => {});
};
window.addEventListener('unhandledrejection', function(ev) {
  fetch('/api/client-error', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message: String(ev.reason), source: 'promise', line: 0, col: 0, stack: ev.reason?.stack || ''}),
  }).catch(() => {});
});

connect();
loadOverview();
setInterval(loadOverview, 10000);

