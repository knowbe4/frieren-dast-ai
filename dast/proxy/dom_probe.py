"""
DOM enumeration helpers for the SPA explorer.

These are the JavaScript snippets the explorer runs via ``page.evaluate`` to
discover client-side routes and forms, piercing OPEN shadow DOM (which a plain
``document.querySelectorAll`` and the custom collector in the old crawler do
not). Kept out of the explorer logic so the big JS strings stay in one place.
"""

from __future__ import annotations

# Selectors whose elements commonly reveal a hidden menu on hover/focus. The
# explorer hovers these before enumerating, so dropdown/flyout items that are
# display:none until hover become visible and clickable.
MENU_TRIGGER_SELECTORS = (
    "[aria-haspopup]",
    "[aria-expanded='false']",
    ".dropdown-toggle",
    "[role='menubar'] [role='button']",
    "[role='navigation'] [aria-expanded]",
    "[data-toggle='dropdown']",
)

# Recursively walk the document AND open shadow roots, collecting candidate
# client-side route targets. Returns absolute URLs (resolved against origin).
# Covers <a href>, Angular routerLink (attribute + ng-reflect mirror), data-href,
# and hash routes (#/...). Static assets and javascript:/mailto: are dropped.
COLLECT_ROUTES_JS = r"""
() => {
  const origin = window.location.origin;
  const out = new Set();
  const addRaw = (h) => {
    if (!h) return;
    const v = String(h).trim();
    if (!v || v.startsWith('javascript:') || v.startsWith('mailto:') || v.startsWith('tel:')) return;
    try {
      if (v.startsWith('#')) { out.add(origin + window.location.pathname + v); return; }
      const abs = new URL(v, window.location.href).href;
      out.add(abs);
    } catch (e) { /* ignore unparseable */ }
  };
  const scan = (root) => {
    let els;
    try { els = root.querySelectorAll('a[href],[routerLink],[ng-reflect-router-link],[data-href],[ng-href]'); }
    catch (e) { return; }
    els.forEach(el => {
      addRaw(el.getAttribute('href'));
      addRaw(el.getAttribute('routerLink'));
      addRaw(el.getAttribute('ng-reflect-router-link'));
      addRaw(el.getAttribute('data-href'));
      addRaw(el.getAttribute('ng-href'));
    });
    // descend open shadow roots
    try {
      root.querySelectorAll('*').forEach(node => { if (node.shadowRoot) scan(node.shadowRoot); });
    } catch (e) { /* ignore */ }
  };
  scan(document);
  return [...out];
}
"""

# Enumerate forms (document + open shadow roots) with their fields, so the
# explorer can decide what to fill. Capped to keep the payload small.
COLLECT_FORMS_JS = r"""
() => {
  const forms = [];
  const scan = (root) => {
    let fs;
    try { fs = root.querySelectorAll('form'); } catch (e) { return; }
    fs.forEach((f, i) => {
      if (forms.length >= 25) return;
      const fields = [];
      f.querySelectorAll('input,select,textarea').forEach(el => {
        if (fields.length >= 40) return;
        const style = window.getComputedStyle(el);
        fields.push({
          tag: el.tagName.toLowerCase(),
          type: (el.getAttribute('type') || '').toLowerCase(),
          name: el.getAttribute('name') || '',
          id: el.id || '',
          required: el.required || false,
          hidden: el.type === 'hidden' || style.display === 'none' || style.visibility === 'hidden',
        });
      });
      forms.push({
        index: forms.length,
        action: f.getAttribute('action') || '',
        method: (f.getAttribute('method') || 'get').toLowerCase(),
        fields,
      });
    });
    try {
      root.querySelectorAll('*').forEach(node => { if (node.shadowRoot) scan(node.shadowRoot); });
    } catch (e) { /* ignore */ }
  };
  scan(document);
  return forms;
}
"""
