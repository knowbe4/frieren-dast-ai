// ── Extras sub-tabs (H1 Validator / Code / FedRAMP / Interactions / Decoder / JWT) ──
function switchExtrasSub(sub) {
  ['h1', 'code', 'fedramp', 'interactions', 'decoder', 'jwt'].forEach(s => {
    document.getElementById('extras-sub-' + s).style.display = s === sub ? 'flex' : 'none';
    document.getElementById('st-extras-' + s).classList.toggle('on', s === sub);
  });
  if (sub === 'h1')           h1LoadJobs();
  if (sub === 'code')         { codeRenderJobList(); if (_codeCurrentId) codeLoadResults(_codeCurrentId); }
  if (sub === 'fedramp')      fedrampLoad();
  if (sub === 'interactions') { interactionsLoadSessions(); _interactionsBadgeClear(); }
  if (sub === 'decoder')      decoderInit();
  if (sub === 'jwt')          jwtToggleSecret();
}

// ── Browse sub-tabs (Manual / Crawl) ─────────────────────────────────────
function switchBrowseSub(sub) {
  const panes = { manual: 'browse-sub-manual', crawl: 'browse-sub-crawl', discovery: 'browse-sub-discovery', logins: 'browse-sub-logins' };
  const tabs  = { manual: 'st-browse-manual', crawl: 'st-browse-crawl', discovery: 'st-browse-discovery', logins: 'st-browse-logins' };
  for (const [key, paneId] of Object.entries(panes)) {
    document.getElementById(paneId).style.display = (key === sub) ? 'block' : 'none';
    document.getElementById(tabs[key]).classList.toggle('on', key === sub);
  }
  if (sub === 'manual')      { loadNamedSessions(); loadNamedBrowsers(); }
  else if (sub === 'crawl')  updateCrawlCookieStatus();
  else if (sub === 'logins') loadLoginProfiles();
}

// ── AI panel (settings) ────────────────────────────────────────────────
async function loadAiPanel() {
  try {
    const [agentsR, graphR, ctxR, tmR] = await Promise.all([
      fetch('/api/ai/agents'),
      fetch('/api/service-graph'),
      fetch('/api/ai/app-context'),
      fetch('/api/ai/threat-models'),
    ]);
    const agentsData = await agentsR.json();
    const graphData = await graphR.json();
    const ctxData   = ctxR.ok ? await ctxR.json() : {};
    const tmData    = tmR.ok  ? await tmR.json()  : {};

    // App context
    const ctxEl = document.getElementById('ai-app-context');
    if (ctxEl) {
      const hosts = Object.keys(ctxData);
      if (!hosts.length) {
        ctxEl.innerHTML = '<div style="color:var(--txt2);font-size:11px">No app context yet — requires 15+ requests through proxy.</div>';
      } else {
        const _prioColor = {high:'var(--red)',medium:'var(--orange)',low:'var(--txt2)'};
        ctxEl.innerHTML = hosts.map(host => {
          const p = ctxData[host];
          const hyps = (p.vuln_hypotheses || []);
          const ts = p.last_analysed_at ? new Date(p.last_analysed_at * 1000).toLocaleTimeString() : '—';
          return `<div style="background:var(--bg2);border:1px solid var(--bdr);border-radius:4px;
                              padding:12px 14px;margin-bottom:12px;font-size:11px">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap">
              <span style="font-weight:700;color:var(--blue)">${esc(host)}</span>
              ${p.app_type ? `<span style="color:var(--txt2)">${esc(p.app_type)}</span>` : ''}
              ${p.auth_model ? `<span style="background:var(--bg3);border:1px solid var(--bdr);border-radius:3px;padding:1px 7px;color:var(--green)">${esc(p.auth_model)}</span>` : ''}
              <span style="color:var(--txt3);font-size:10px;margin-left:auto">analysed ${esc(ts)} · ${p.analysis_count||0}x · ${p.entry_count_at_analysis||0} reqs</span>
            </div>
            ${p.resource_types?.length ? `<div style="margin-bottom:6px"><span style="color:var(--txt2)">Resources: </span>${p.resource_types.map(r=>`<span style="background:var(--bg3);border-radius:3px;padding:1px 6px;margin-right:4px">${esc(r)}</span>`).join('')}</div>` : ''}
            ${p.privilege_levels?.length ? `<div style="margin-bottom:6px"><span style="color:var(--txt2)">Roles: </span>${p.privilege_levels.map(r=>`<span style="background:var(--bg3);border-radius:3px;padding:1px 6px;margin-right:4px">${esc(r)}</span>`).join('')}</div>` : ''}
            ${p.interesting_flows?.length ? `<div style="margin-bottom:8px;color:var(--txt2)">Flows: ${p.interesting_flows.slice(0,4).map(f=>`<em>${esc(f)}</em>`).join(' · ')}</div>` : ''}
            ${hyps.length ? `
              <div style="font-weight:600;margin-bottom:4px;color:var(--txt2)">Vulnerability hypotheses (${hyps.length})</div>
              ${hyps.map(h => {
                const statusBadge = `<button onclick='exploreHypothesis(${JSON.stringify(host)},${JSON.stringify(h.attack_type)},${JSON.stringify(h.endpoint)},${JSON.stringify(h.parameter||'')},${JSON.stringify(h.rationale||'')})'
                                style="font-size:9px;padding:1px 6px;background:var(--blue);color:#fff;border:none;border-radius:3px;cursor:pointer">Explore in Copilot</button>`;
                return `
                <div style="display:flex;align-items:baseline;gap:8px;padding:3px 0;border-top:1px solid var(--bdr3,#252525)">
                  <span style="color:${_prioColor[h.priority]||'var(--txt2)'};font-size:10px;text-transform:uppercase;width:44px;flex-shrink:0">${esc(h.priority)}</span>
                  <span style="color:var(--orange);width:90px;flex-shrink:0;font-family:monospace">${esc(h.attack_type)}</span>
                  <span style="color:var(--txt);font-family:monospace;white-space:nowrap">${esc(h.endpoint)}</span>
                  ${h.parameter !== '*' ? `<span style="color:var(--blue)">[${esc(h.parameter)}]</span>` : ''}
                  <span style="color:var(--txt2);font-size:10px;flex:1">${esc(h.rationale)}</span>
                  ${statusBadge}
                </div>`;
              }).join('')}` : '<div style="color:var(--txt3);font-size:10px">No hypotheses yet.</div>'}
          </div>`;
        }).join('');
      }
    }

    // Threat models
    const tmEl = document.getElementById('ai-threat-models');
    if (tmEl) {
      const tmHosts = Object.keys(tmData);
      if (!tmHosts.length) {
        tmEl.innerHTML = '<div style="color:var(--txt2);font-size:11px">No threat model yet — requires 15+ requests through proxy.</div>';
      } else {
        tmEl.innerHTML = tmHosts.map(host => {
          const m = tmData[host];
          const ts = m.last_analysed_at ? new Date(m.last_analysed_at * 1000).toLocaleTimeString() : '—';
          const _section = (label, items, color) => items?.length
            ? `<div style="margin-bottom:6px">
                <span style="color:var(--txt2);font-weight:600">${label}: </span>
                <ul style="margin:4px 0 0 0;padding-left:18px">
                  ${items.map(i => `<li style="color:${color};padding:1px 0">${esc(i)}</li>`).join('')}
                </ul>
               </div>`
            : '';
          return `<div style="background:var(--bg2);border:1px solid var(--bdr);border-radius:4px;
                              padding:12px 14px;margin-bottom:12px;font-size:11px">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap">
              <span style="font-weight:700;color:var(--blue)">${esc(host)}</span>
              <span style="color:var(--txt3);font-size:10px;margin-left:auto">analysed ${esc(ts)} · ${m.analysis_count||0}x</span>
            </div>
            ${_section('Security invariants', m.security_invariants, 'var(--green)')}
            ${_section('Not vulnerabilities', m.not_vulnerabilities, 'var(--txt2)')}
            ${_section('High-risk surfaces', m.high_risk_surfaces, 'var(--orange)')}
            ${_section('Trust boundaries', m.trust_boundaries, 'var(--txt)')}
          </div>`;
        }).join('');
      }
    }

    // Service graph
    const graphEl = document.getElementById('ai-service-graph');
    if (graphEl && graphData.groups) {
      const multiGroups = graphData.groups.filter(g => g.hosts.length > 1);
      if (!multiGroups.length) {
        graphEl.innerHTML = `<div style="color:var(--txt2);font-size:11px">
          No multi-host groups detected yet. Browse the application to accumulate traffic.
        </div>`;
      } else {
        graphEl.innerHTML = multiGroups.map(g => `
          <div style="background:var(--bg2);border:1px solid var(--bdr);border-radius:4px;
                      padding:10px 14px;margin-bottom:10px;font-size:11px">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
              <span style="color:var(--txt2)">Group</span>
              <code style="color:var(--orange)">${esc(g.id)}</code>
              ${g.manually_managed ? '<span style="color:var(--blue);font-size:10px">[manual]</span>' : ''}
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px">
              ${g.hosts.map(h => `
                <span style="background:var(--bg3);border:1px solid var(--bdr);border-radius:3px;
                             padding:2px 8px;color:var(--txt)">
                  ${esc(h)}
                  <button onclick="splitHost('${esc(h)}')" style="background:none;border:none;
                    color:var(--txt3);cursor:pointer;font-size:10px;padding:0 0 0 4px"
                    title="Split out of group">✕</button>
                </span>`).join('')}
            </div>
            <div style="color:var(--txt3);font-size:10px">${esc(g.detection_signals.slice(-3).join(' · '))}</div>
          </div>`).join('') +
          `<div style="margin-top:8px;display:flex;gap:8px;align-items:center">
            <input id="merge-host-a" placeholder="host-a.example.com"
              style="flex:1;background:var(--bg2);border:1px solid var(--bdr);color:var(--txt);
                     padding:4px 8px;border-radius:3px;font-size:11px">
            <input id="merge-host-b" placeholder="host-b.example.com"
              style="flex:1;background:var(--bg2);border:1px solid var(--bdr);color:var(--txt);
                     padding:4px 8px;border-radius:3px;font-size:11px">
            <button class="tbtn" onclick="mergeHosts()">Merge</button>
          </div>`;
      }
    }

    // Payload sources
    const payloadEl = document.getElementById('ai-payload-sources');
    if (payloadEl && agentsData.payload_files) {
      payloadEl.innerHTML = `
        <table style="width:100%;border-collapse:collapse;font-size:11px">
          <thead>
            <tr style="color:var(--txt2);border-bottom:1px solid var(--bdr)">
              <th style="text-align:left;padding:4px 8px;font-weight:500">File</th>
              <th style="text-align:left;padding:4px 8px;font-weight:500">Categories</th>
              <th style="text-align:right;padding:4px 8px;font-weight:500">Total payloads</th>
            </tr>
          </thead>
          <tbody>
            ${agentsData.payload_files.map(f => `
              <tr style="border-bottom:1px solid var(--bdr3,var(--bdr))">
                <td style="padding:5px 8px;font-family:monospace;color:var(--orange)">${esc(f.file)}</td>
                <td style="padding:5px 8px;color:var(--txt2)">${esc(f.groups.join(', '))}</td>
                <td style="padding:5px 8px;text-align:right;color:var(--txt)">${f.count}</td>
              </tr>`).join('')}
          </tbody>
        </table>`;
    }

  } catch(e) {
    console.error('loadAiPanel:', e);
  }
}

async function mergeHosts() {
  const a = document.getElementById('merge-host-a')?.value.trim();
  const b = document.getElementById('merge-host-b')?.value.trim();
  if (!a || !b) { showToast('Enter both hosts'); return; }
  const r = await fetch('/api/service-graph/merge', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({host_a: a, host_b: b}),
  });
  if (r.ok) { showToast(`Merged ${a} and ${b}`); loadAiPanel(); }
  else showToast('Merge failed');
}

async function splitHost(host) {
  const r = await fetch('/api/service-graph/split', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({host}),
  });
  if (r.ok) { showToast(`Split ${host} into its own group`); loadAiPanel(); }
  else showToast('Split failed');
}

