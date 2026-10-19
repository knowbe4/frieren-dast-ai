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

# Tag every interactive-LOOKING element (piercing open shadow DOM) with a marker
# attribute so Playwright can query handles to them. SPAs build nav from <div>/
# <span> with click handlers, role=, tabindex, or cursor:pointer — not just <a>/
# <button>. Returns the count tagged. This is the "clickable detector": we treat
# an element as clickable if it has an onclick attr, an interactive ARIA role, a
# tabindex, or a computed `cursor: pointer`. (Listeners added via addEventListener
# with no onclick attr are approximated by role/cursor; full detection needs CDP.)
TAG_CLICKABLES_JS = r"""
() => {
  const INTERACTIVE_ROLES = new Set(["button","link","tab","menuitem","option","treeitem","checkbox","radio","switch","menuitemcheckbox","menuitemradio"]);
  let n = 0;
  const mark = (el) => { try { el.setAttribute("data-dast-clickable","1"); n++; } catch(e){} };
  const consider = (el) => {
    try {
      if (el.hasAttribute("data-dast-clickable")) return;
      const tag = el.tagName ? el.tagName.toLowerCase() : "";
      if (tag === "a" || tag === "button") { mark(el); return; }
      if (el.hasAttribute("onclick") || el.hasAttribute("routerLink") || el.hasAttribute("ng-reflect-router-link") || el.hasAttribute("data-href")) { mark(el); return; }
      const role = (el.getAttribute && el.getAttribute("role")) || "";
      if (INTERACTIVE_ROLES.has(role)) { mark(el); return; }
      const ti = el.getAttribute && el.getAttribute("tabindex");
      if (ti !== null && ti !== undefined && ti !== "-1") { mark(el); return; }
      const cs = window.getComputedStyle(el);
      if (cs && cs.cursor === "pointer") { mark(el); return; }
    } catch(e){}
  };
  const scan = (root) => {
    let els; try { els = root.querySelectorAll("*"); } catch(e){ return; }
    els.forEach(el => { consider(el); if (el.shadowRoot) scan(el.shadowRoot); });
  };
  scan(document);
  return n;
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
