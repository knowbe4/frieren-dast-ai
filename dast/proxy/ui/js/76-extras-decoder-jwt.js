// ── Decoder / Encoder — client-side transform toolbelt ──────────────────
// All transforms run in the browser; no request ever leaves the page.

// Ops are grouped by family so the encode/decode pair for each codec sits together
// in the picker instead of being scattered across one flat list.
const _DECODER_OPS = [
  { id: 'b64-enc',    group: 'Base64',    label: 'Encode',            fn: s => _b64encode(s) },
  { id: 'b64-dec',    group: 'Base64',    label: 'Decode',            fn: s => _b64decode(s) },
  { id: 'b64url-enc', group: 'Base64URL', label: 'Encode',            fn: s => _b64encode(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'') },
  { id: 'b64url-dec', group: 'Base64URL', label: 'Decode',            fn: s => _b64decode(_b64urlPad(s.replace(/-/g,'+').replace(/_/g,'/'))) },
  { id: 'url-enc',    group: 'URL',       label: 'Encode',            fn: s => encodeURIComponent(s) },
  { id: 'url-dec',    group: 'URL',       label: 'Decode',            fn: s => decodeURIComponent(s.replace(/\+/g,' ')) },
  { id: 'url-enc-all',group: 'URL',       label: 'Encode (all chars)',fn: s => Array.from(s).map(c => '%' + c.charCodeAt(0).toString(16).padStart(2,'0').toUpperCase()).join('') },
  { id: 'html-enc',   group: 'HTML',      label: 'Encode',            fn: s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;') },
  { id: 'html-dec',   group: 'HTML',      label: 'Decode',            fn: s => _htmlDecode(s) },
  { id: 'hex-enc',    group: 'Hex',       label: 'Encode',            fn: s => Array.from(new TextEncoder().encode(s)).map(b => b.toString(16).padStart(2,'0')).join('') },
  { id: 'hex-dec',    group: 'Hex',       label: 'Decode',            fn: s => _hexDecode(s) },
  { id: 'jwt-dec',    group: 'JWT',       label: 'Decode',            fn: s => _jwtDecodeText(s) },
];

let _decoderOp = 'b64-dec';

function _b64encode(s) {
  return btoa(unescape(encodeURIComponent(s)));
}
function _b64decode(s) {
  return decodeURIComponent(escape(atob(s.trim())));
}
function _b64urlPad(s) {
  const pad = s.length % 4;
  return pad ? s + '='.repeat(4 - pad) : s;
}
function _htmlDecode(s) {
  const el = document.createElement('textarea');
  el.innerHTML = s;
  return el.value;
}
function _hexDecode(s) {
  const clean = s.replace(/[^0-9a-fA-F]/g, '');
  const bytes = [];
  for (let i = 0; i + 1 < clean.length; i += 2) bytes.push(parseInt(clean.slice(i, i + 2), 16));
  return new TextDecoder().decode(new Uint8Array(bytes));
}
function _jwtDecodeText(s) {
  const parts = s.trim().split('.');
  if (parts.length < 2) throw new Error('not a JWT (need header.payload)');
  const hdr = JSON.parse(_b64decode(_b64urlPad(parts[0].replace(/-/g,'+').replace(/_/g,'/'))));
  const pl  = JSON.parse(_b64decode(_b64urlPad(parts[1].replace(/-/g,'+').replace(/_/g,'/'))));
  return 'HEADER:\n' + JSON.stringify(hdr, null, 2) + '\n\nPAYLOAD:\n' + JSON.stringify(pl, null, 2);
}

function decoderInit() {
  const ops = document.getElementById('dec-ops');
  if (ops && !ops.dataset.built) {
    const groups = [];
    _DECODER_OPS.forEach(op => {
      let g = groups.find(x => x.name === op.group);
      if (!g) { g = { name: op.group, ops: [] }; groups.push(g); }
      g.ops.push(op);
    });
    ops.innerHTML = groups.map(g =>
      `<div class="dec-group">` +
        `<div style="padding:9px 14px 3px;font-size:9px;font-weight:600;color:var(--txt2);` +
             `text-transform:uppercase;letter-spacing:.5px">${g.name}</div>` +
        g.ops.map(op =>
          `<div class="dec-op" id="dec-op-${op.id}" onclick="decoderPick('${op.id}')">${op.label}</div>`
        ).join('') +
      `</div>`
    ).join('');
    ops.dataset.built = '1';
  }
  decoderPick(_decoderOp);
}

function decoderPick(id) {
  _decoderOp = id;
  _DECODER_OPS.forEach(op => {
    const el = document.getElementById('dec-op-' + op.id);
    if (el) el.classList.toggle('on', op.id === id);
  });
  decoderRun();
}

// Map raw JS exceptions to short, human-readable reasons per transform kind.
function _decoderFriendlyError(op) {
  if (op.id.startsWith('b64')) return 'Not valid Base64 — check for stray characters or padding.';
  if (op.id.startsWith('url')) return 'Not valid URL-encoded text — check for a lone % or bad %XX sequence.';
  if (op.id.startsWith('hex')) return 'Not valid hex — expected pairs of 0-9 / a-f.';
  if (op.id === 'jwt-dec')     return 'Not a valid JWT — expected header.payload with Base64URL JSON.';
  return 'Input could not be transformed.';
}

function decoderRun() {
  const input   = document.getElementById('dec-input').value;
  const out      = document.getElementById('dec-output');
  const op        = _DECODER_OPS.find(o => o.id === _decoderOp);
  const inLen    = document.getElementById('dec-in-len');
  const outLen  = document.getElementById('dec-out-len');
  if (inLen) inLen.textContent = input ? input.length + ' chars' : '';
  if (!op) return;
  if (!input) { out.textContent = ''; out.style.color = 'var(--txt2)'; if (outLen) outLen.textContent = ''; return; }
  try {
    const result = op.fn(input);
    out.textContent = result;
    out.style.color = 'var(--orange)';
    if (outLen) outLen.textContent = result.length + ' chars';
  } catch (e) {
    out.textContent = _decoderFriendlyError(op);
    out.style.color = 'var(--txt2)';
    if (outLen) outLen.textContent = '';
  }
}

function decoderCopy() {
  const out = document.getElementById('dec-output').textContent;
  if (out) navigator.clipboard.writeText(out).then(() => showToast('Copied output'));
}

// Feed the current output back into the input to chain transforms
// (e.g. URL decode then Base64 decode).
function decoderUseOutputAsInput() {
  const out = document.getElementById('dec-output').textContent;
  const inp = document.getElementById('dec-input');
  if (!out || !inp) return;
  inp.value = out;
  decoderRun();
}

// ── JWT editor — decode, edit, re-sign, send to Repeater ─────────────────
let _jwtLastToken = '';

function jwtToggleSecret() {
  const mode = document.getElementById('jwt-mode').value;
  const row  = document.getElementById('jwt-secret-row');
  if (row) row.style.display = mode === 'none' ? 'none' : 'block';
}

function jwtDecode() {
  const raw = document.getElementById('jwt-input').value.trim();
  const msg = document.getElementById('jwt-decode-msg');
  if (!raw) { msg.textContent = ''; return; }
  try {
    const parts = raw.split('.');
    if (parts.length < 2) throw new Error('need at least header.payload');
    const hdr = JSON.parse(_b64decode(_b64urlPad(parts[0].replace(/-/g,'+').replace(/_/g,'/'))));
    const pl  = JSON.parse(_b64decode(_b64urlPad(parts[1].replace(/-/g,'+').replace(/_/g,'/'))));
    document.getElementById('jwt-header').value  = JSON.stringify(hdr, null, 2);
    document.getElementById('jwt-payload').value = JSON.stringify(pl, null, 2);
    const alg = (hdr.alg || '').toLowerCase();
    const sel = document.getElementById('jwt-mode');
    if (['hs256','hs384','hs512','none'].includes(alg)) { sel.value = alg; jwtToggleSecret(); }
    msg.style.color = 'var(--green)';
    msg.textContent = 'Decoded (alg=' + (hdr.alg || '?') + '). Edit header/payload below, then Build token.';
  } catch (e) {
    msg.style.color = 'var(--txt2)';
    msg.textContent = 'Not a valid JWT — expected header.payload with Base64URL-encoded JSON.';
  }
}

async function jwtBuild() {
  const msg = document.getElementById('jwt-build-msg');
  const out = document.getElementById('jwt-output');
  let header, payload;
  try {
    header  = JSON.parse(document.getElementById('jwt-header').value || '{}');
    payload = JSON.parse(document.getElementById('jwt-payload').value || '{}');
  } catch (e) {
    msg.style.color = 'var(--txt2)';
    msg.textContent = 'Header or payload is not valid JSON — fix the highlighted text and try again.';
    return;
  }
  const mode   = document.getElementById('jwt-mode').value;
  const secret = mode === 'none' ? null : document.getElementById('jwt-secret').value;
  msg.style.color = 'var(--txt2)';
  msg.textContent = 'Building...';
  try {
    const r = await fetch('/api/jwt/build', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ header, payload, mode, secret }),
    });
    const d = await r.json();
    if (!r.ok || d.error) throw new Error(d.error || ('HTTP ' + r.status));
    _jwtLastToken = d.token;
    out.textContent = d.token;
    msg.style.color = 'var(--green)';
    msg.textContent = 'Signed with ' + mode + '.';
  } catch (e) {
    out.textContent = '';
    msg.style.color = 'var(--txt2)';
    msg.textContent = 'Could not build the token — check the header, payload, and signing mode.';
  }
}

function jwtCopy() {
  if (_jwtLastToken) navigator.clipboard.writeText(_jwtLastToken).then(() => showToast('Copied token'));
}

function jwtToRepeater() {
  if (!_jwtLastToken) { showToast('Build a token first'); return; }
  repNewTab({
    method: 'GET',
    url: '',
    headers: 'Authorization: Bearer ' + _jwtLastToken,
    body: '',
    label: 'JWT probe',
  });
  switchMain('repeater');
}
