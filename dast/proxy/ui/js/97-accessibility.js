// ── Accessibility / keyboard navigation ─────────────────────────────────────
// Centralised, non-invasive a11y layer: rather than editing every tab <div> and
// every dynamically rendered row, this module adds ARIA roles, roving tabindex,
// arrow-key tab navigation, keyboard activation for list rows, and Escape-to-
// close for modals — all via delegation and MutationObservers so it keeps
// working as the app re-renders content.

(function () {
  'use strict';

  // ── Tab layers: role=tablist/tab, roving tabindex, arrow-key navigation ────
  // Activation is manual (Arrow moves focus; Enter/Space activates) because
  // switching a tab triggers data loads — we don't want arrow-scrolling to fire
  // a fetch on every key press.
  function enhanceTablist(container, tabSelector) {
    const tabs = Array.prototype.slice.call(container.querySelectorAll(tabSelector));
    if (!tabs.length) return;
    container.setAttribute('role', 'tablist');

    function syncSelected() {
      tabs.forEach(function (t) {
        const on = t.classList.contains('on');
        t.setAttribute('aria-selected', on ? 'true' : 'false');
        t.setAttribute('tabindex', on ? '0' : '-1');
      });
    }

    tabs.forEach(function (tab, index) {
      tab.setAttribute('role', 'tab');
      tab.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
          e.preventDefault(); tabs[(index + 1) % tabs.length].focus();
        } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
          e.preventDefault(); tabs[(index - 1 + tabs.length) % tabs.length].focus();
        } else if (e.key === 'Home') {
          e.preventDefault(); tabs[0].focus();
        } else if (e.key === 'End') {
          e.preventDefault(); tabs[tabs.length - 1].focus();
        } else if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault(); tab.click();
        }
      });
    });

    // Keep ARIA state correct however `.on` gets toggled (click or programmatic).
    const observer = new MutationObserver(syncSelected);
    tabs.forEach(function (t) { observer.observe(t, { attributes: true, attributeFilter: ['class'] }); });
    syncSelected();
  }

  // ── Dynamic list rows: make them focusable + Enter/Space activatable ───────
  // Rows are re-rendered constantly, so we set tabindex on newly added nodes via
  // an observer and handle activation through delegation on the container.
  function makeRowsOperable(container, rowSelector, roleName) {
    if (!container) return;

    function tag(root) {
      const rows = root.matches && root.matches(rowSelector)
        ? [root]
        : Array.prototype.slice.call((root.querySelectorAll ? root.querySelectorAll(rowSelector) : []));
      rows.forEach(function (row) {
        if (!row.hasAttribute('tabindex')) row.setAttribute('tabindex', '0');
        if (roleName && !row.hasAttribute('role')) row.setAttribute('role', roleName);
      });
    }

    tag(container);
    const observer = new MutationObserver(function (mutations) {
      mutations.forEach(function (m) {
        Array.prototype.forEach.call(m.addedNodes, function (node) {
          if (node.nodeType === 1) tag(node);
        });
      });
    });
    observer.observe(container, { childList: true, subtree: true });

    container.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const row = e.target.closest(rowSelector);
      if (row && container.contains(row)) { e.preventDefault(); row.click(); }
    });
  }

  // ── Escape closes whichever modal/overlay is open ──────────────────────────
  // Each known overlay is closed through its own close function so any teardown
  // logic runs. confirmDlg handles its own Escape, so it is intentionally absent.
  const CLOSERS = [
    { id: 'sessions-overlay', fn: 'hideSessionsPanel' },
    { id: 'import-findings-modal', fn: 'closeImportFindingsModal' },
  ];
  function isVisible(el) {
    return el && getComputedStyle(el).display !== 'none';
  }
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    for (let i = 0; i < CLOSERS.length; i++) {
      const el = document.getElementById(CLOSERS[i].id);
      if (isVisible(el) && typeof window[CLOSERS[i].fn] === 'function') {
        e.preventDefault();
        window[CLOSERS[i].fn]();
        return;
      }
    }
  });

  document.addEventListener('DOMContentLoaded', function () {
    // Main tabs, then every sub-tab and detail-tab bar present in the markup.
    const mainbar = document.getElementById('tabbar');
    if (mainbar) enhanceTablist(mainbar, '.mtab');
    document.querySelectorAll('.subtab-bar').forEach(function (bar) { enhanceTablist(bar, '.stab'); });
    document.querySelectorAll('.dtab-bar').forEach(function (bar) { enhanceTablist(bar, '.dtab'); });

    // HTTP history rows and the shared host sidebar.
    makeRowsOperable(document.getElementById('tbody'), 'tr[id^="row-"]', 'button');
    document.querySelectorAll('.hosts-list').forEach(function (list) {
      makeRowsOperable(list, '.host-item', 'button');
    });
  });
})();
