// AVS (Application Vulnerability Score) dashboard rendering.
// Scores come from computeAvsMetrics in avs-core.js so the AVS section
// updates live as dashboard filters change, the same way every other
// section on this page recomputes from the currently filtered records.

// Which AVS KPI card is currently selected ('all', 'Low', 'Medium', 'High').
// Drives the active-card highlight and the AVS List table filter below, both
// through the shared createDataTable#setFilter hook - no separate filtering
// logic is implemented for the cards.
let avsActiveLevel = 'all';

function avsKpiCard(label, value, icon, tone, level) {
  const isActive = avsActiveLevel === level;
  return `<article class="kpi kpi-clickable ${tone}${isActive ? ' kpi-active' : ''}" data-avs-level="${level}" role="button" tabindex="0" aria-pressed="${isActive}"><div class="kpi-label"><span>${label}</span><span class="kpi-icon">${icon}</span></div><div class="kpi-value">${(value || 0).toLocaleString()}</div></article>`;
}

// Reused by both the card click handler and every renderAvs() refresh
// (including after an AVS List import) so the table filter always matches
// whichever card is currently highlighted.
function avsCardMatches(row) {
  return avsActiveLevel === 'all' || row.level === avsActiveLevel;
}

function avsSetActiveLevel(level) {
  avsActiveLevel = level;
  document.querySelectorAll('#avsKpis [data-avs-level]').forEach(card => {
    const isActive = card.dataset.avsLevel === level;
    card.classList.toggle('kpi-active', isActive);
    card.setAttribute('aria-pressed', String(isActive));
  });
  avsTable.setFilter(avsCardMatches);
}

function renderAvs(records) {
  const apps = computeAvsMetrics(records).sort((a, b) => b.score - a.score);
  const low = apps.filter(a => a.level === 'Low').length;
  const medium = apps.filter(a => a.level === 'Medium').length;
  const high = apps.filter(a => a.level === 'High').length;
  $('avsKpis').innerHTML = [
    ['Total Apps', apps.length, '▦', '', 'all'],
    ['Low AVS', low, '●', 'kpi-good', 'Low'],
    ['Medium AVS', medium, '●', 'kpi-warning', 'Medium'],
    ['High AVS', high, '▲', 'kpi-critical', 'High'],
  ].map(x => avsKpiCard(...x)).join('');

  const distribution = { Low: low, Medium: medium, High: high };
  const avsColors = { Low: '#2f9d6c', Medium: '#e8b23c', High: '#d43a2c' };
  donut($('avsDistributionChart'), distribution, avsColors);
  $('avsDonutTotal').textContent = apps.length.toLocaleString();
  $('avsDistributionLegend').innerHTML = Object.entries(distribution)
    .map(([key, value]) => `<span class="legend-item"><i class="legend-dot" style="background:${avsColors[key]}"></i>${key} ${value}</span>`)
    .join('');

  const topApps = apps.slice(0, 10).map(a => ({ name: a.name, total: Math.round(a.score * 100) / 100 }));
  horizontalBars($('avsTopAppsChart'), topApps, '#de8324');

  const byTeam = {};
  apps.forEach(a => { byTeam[a.team] = (byTeam[a.team] || 0) + a.score; });
  const teamEntries = Object.entries(byTeam).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, total]) => ({ name, total: Math.round(total * 100) / 100 }));
  horizontalBars($('avsTeamChart'), teamEntries, '#f2661e');

  avsTable.update(apps);
}

function renderAvsRow(a) {
  return `<tr><td><strong>${esc(a.name)}</strong></td><td>${esc(a.team)}</td><td>${a.score.toFixed(1)}</td><td>${badge(a.level, 'avs')}</td><td>${a.uniqueCount}</td><td>${esc(a.assetType)}</td><td>${esc(a.zone)}</td></tr>`;
}

const avsTable = createDataTable({
  tbodyId: 'avsTable', searchInputId: 'avsSearch', pageSizeSelectId: 'avsPageSize',
  previousButtonId: 'avsPreviousPage', nextButtonId: 'avsNextPage', pageInfoId: 'avsPageInfo', countId: 'avsCount',
  colSpan: 7, renderRow: renderAvsRow, emptyMessage: 'No application data in current scope',
  matches: (row, query) => `${row.name} ${row.team} ${row.assetType} ${row.zone} ${row.level}`.toLowerCase().includes(query),
});

// Delegated so the listener survives every innerHTML re-render of #avsKpis.
(function bindAvsKpiClicks() {
  const container = document.getElementById('avsKpis');
  if (!container) return;
  container.addEventListener('click', event => {
    const card = event.target.closest('[data-avs-level]');
    if (card) avsSetActiveLevel(card.dataset.avsLevel);
  });
  container.addEventListener('keydown', event => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const card = event.target.closest('[data-avs-level]');
    if (!card) return;
    event.preventDefault();
    avsSetActiveLevel(card.dataset.avsLevel);
  });
})();

function setAvsImportMessage(text, type = '') {
  const message = document.getElementById('avsImportMessage');
  if (!message) return;
  message.className = `avs-import-message ${type}`.trim();
  message.textContent = text;
}

async function exportAvsList() {
  const button = document.getElementById('exportAvsList');
  if (button) button.disabled = true;
  setAvsImportMessage('Exporting AVS List...');
  try {
    const response = await fetch('/api/avs/export');
    await downloadFromResponse(response, `avs_list_${new Date().toISOString().slice(0, 10)}.csv`);
    setAvsImportMessage('AVS List exported.', 'success');
  } catch (error) {
    setAvsImportMessage(error.message, 'error');
  } finally {
    if (button) button.disabled = false;
  }
}

(function bindAvsExportControl() {
  const button = document.getElementById('exportAvsList');
  if (!button) return;
  button.addEventListener('click', exportAvsList);
})();
