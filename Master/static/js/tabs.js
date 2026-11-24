// Client-side dashboard tabs. Sections are never duplicated or re-fetched:
// every tab shows a subset of the same DOM (via data-tabs on .tab-section),
// so filters, tables and in-memory data are shared across all tabs.
var DASHBOARD_TABS = ['overview', 'risky', 'movement', 'avs', 'tables'];
var DEFAULT_DASHBOARD_TAB = 'overview';

function normalizeDashboardTab(value) {
  var key = String(value || '').replace(/^#/, '').replace(/^\/+/, '').replace(/^tab-/, '').trim().toLowerCase();
  return DASHBOARD_TABS.indexOf(key) >= 0 ? key : DEFAULT_DASHBOARD_TAB;
}

function currentDashboardTabFromLocation() {
  var path = window.location.pathname.replace(/^\/+/, '').replace(/\/+$/, '');
  if (path) return path;
  // Back-compat: support old #hash links by converting them to the new path-based URL.
  return window.location.hash;
}

function initDashboardTabs(options) {
  var opts = options || {};
  var nav = document.getElementById('dashboardTabs');
  var panel = document.getElementById('dashboardTabPanel');
  if (!nav || !panel) return null;
  var buttons = Array.prototype.slice.call(nav.querySelectorAll('[data-tab]'));
  var active = null;

  function activate(tab, settings) {
    var cfg = settings || {};
    var next = normalizeDashboardTab(tab);
    if (next === active) return;
    active = next;
    panel.setAttribute('data-active-tab', next);
    panel.setAttribute('aria-labelledby', 'tab-' + next);
    buttons.forEach(function (button) {
      var selected = button.getAttribute('data-tab') === next;
      button.classList.toggle('is-active', selected);
      button.setAttribute('aria-selected', String(selected));
      button.setAttribute('tabindex', selected ? '0' : '-1');
      if (selected && cfg.focus) button.focus();
    });
    if (cfg.updateHash !== false && window.history && window.history.replaceState) {
      var path = next === DEFAULT_DASHBOARD_TAB ? '/' : '/' + next;
      window.history.replaceState(null, '', path + window.location.search);
    }
    if (typeof opts.onChange === 'function' && !cfg.silent) opts.onChange(next);
  }

  nav.addEventListener('click', function (event) {
    var button = event.target.closest ? event.target.closest('[data-tab]') : null;
    if (button) activate(button.getAttribute('data-tab'));
  });

  nav.addEventListener('keydown', function (event) {
    var index = DASHBOARD_TABS.indexOf(active);
    var target = null;
    if (event.key === 'ArrowRight') target = DASHBOARD_TABS[(index + 1) % DASHBOARD_TABS.length];
    else if (event.key === 'ArrowLeft') target = DASHBOARD_TABS[(index - 1 + DASHBOARD_TABS.length) % DASHBOARD_TABS.length];
    else if (event.key === 'Home') target = DASHBOARD_TABS[0];
    else if (event.key === 'End') target = DASHBOARD_TABS[DASHBOARD_TABS.length - 1];
    if (!target) return;
    event.preventDefault();
    activate(target, { focus: true });
  });

  // Initial tab comes from the URL path so Refresh keeps the user on the same view.
  // Silent: the dashboard's first render() runs after this and draws visible charts.
  activate(currentDashboardTabFromLocation(), { updateHash: false, silent: true });

  return {
    activate: activate,
    getActive: function () { return active; },
  };
}
