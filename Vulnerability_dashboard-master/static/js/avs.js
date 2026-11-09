// AVS (Application Vulnerability Score) dashboard rendering.
// Scores come from computeAvsMetrics in avs-core.js so the AVS section
// updates live as dashboard filters change, the same way every other
// section on this page recomputes from the currently filtered records.

// Which AVS KPI card is currently selected ('all', 'Low', 'Medium', 'High').
// Drives the active-card highlight and the AVS List table filter below, both
// through the shared createDataTable#setFilter hook - no separate filtering
// logic is implemented for the cards.
let avsActiveLevel = 'all';

// AVS List drill-down state: the selected application row and, within it, the
// selected pie category. Both null when nothing is selected.
let avsSelectedAppId = null;
let avsSelectedCategory = null;
let avsLastRecords = [];
// Last apps array from computeAvsMetrics (as used to render the AVS KPIs,
// table, and charts) so other consumers, such as the PDF report, can reuse
// it without recomputing AVS scores.
let avsLastApps = [];
let avsCurrentDrilldown = null;
let avsPieGeometry = null;
const AVS_CATEGORY_COLORS = { CoreOS: '#f2661e', Java: '#0f1b2d', Agents: '#5b6b8f', ThirdParty: '#2f9d6c', Others: '#e8b23c' };

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
  renderAvsWeeklyUpdate();
  avsLastRecords = records;
  avsLastApps = apps;
  avsRefreshDrilldown(apps);
}

function renderAvsWeeklyUpdate() {
  const grid = document.getElementById('avsUpdateGrid');
  const section = document.getElementById('avsWeeklyUpdate');
  const title = document.getElementById('avsWeeklyUpdateTitle');
  const table = document.getElementById('avsWeeklyUpdateTable');
  const notes = document.getElementById('avsWeeklyUpdateNotes');
  const update = typeof data === 'undefined' ? {} : data.avs_update || {};
  const rows = update.rows || [];
  if (!section || !table) return;

  section.hidden = !rows.length;
  if (grid) grid.hidden = !rows.length;
  if (!rows.length) return;
  if (title) title.textContent = `AVS update for  ${update.week || 'Current Week'}`;
  const improvedOrTreated = rows.filter(row => row.status === 'Improved/Treated');
  const scoredRows = rows
    .filter(row => row.status !== 'Improved/Treated')
    .sort((left, right) => Number(right.avs || 0) - Number(left.avs || 0)
      || String(left.app_name || '').localeCompare(String(right.app_name || '')));
  const renderScoredRow = row => {
    const statusClass = {
      New: 'avs-update-row-new',
      High: 'avs-update-row-high',
      Med: 'avs-update-row-med',
    }[row.status] || '';
    const avs = Number(row.avs || 0);
    const score = Number.isFinite(avs) ? avs.toFixed(1).replace(/\.0$/, '') : '0';
    const scoreClass = avs > 1000 ? 'avs-update-row-high' : avs >= 500 ? 'avs-update-row-med' : '';
    return `<tr class="${`${statusClass} ${scoreClass}`.trim()}"><td>${esc(row.app_name)}</td><td class="avs-update-score">${score}</td></tr>`;
  };
  const improvedRows = improvedOrTreated.length
    ? `<tr class="avs-update-treated-heading"><td colspan="2">Improved/Treated Apps</td></tr>${improvedOrTreated.map(row => `<tr class="avs-update-row-treated"><td colspan="2">${esc(row.app_name)}</td></tr>`).join('')}`
    : '';
  table.innerHTML = `${scoredRows.map(renderScoredRow).join('')}${improvedRows}`;
  if (notes) {
    const transitions = rows.map(avsUpdateTransitionNote).filter(Boolean);
    notes.hidden = !transitions.length;
    notes.innerHTML = transitions.map(note => `<li>${note}</li>`).join('');
  }
  renderAvsWeeklyMovement(rows);
}

function avsUpdateLevel(score) {
  const value = Number(score || 0);
  return value > 1000 ? 'High' : value >= 500 ? 'Med' : 'Low';
}

function avsUpdateTransitionNote(row) {
  const previousScore = Number(row.previous_avs || 0);
  const currentScore = Number(row.avs || 0);
  const previousLevel = avsUpdateLevel(previousScore);
  const currentLevel = avsUpdateLevel(currentScore);
  if (row.status === 'Improved/Treated') return `${esc(row.app_name)} moved from ${previousLevel} to Treated`;
  if (row.status === 'New') return `${esc(row.app_name)} moved from ${previousLevel} to New`;
  if (previousLevel !== currentLevel) return `${esc(row.app_name)} moved from ${previousLevel} to ${currentLevel}`;
  return '';
}

function renderAvsWeeklyMovement(rows) {
  const canvas = document.getElementById('avsWeeklyMovementChart');
  const legend = document.getElementById('avsWeeklyMovementLegend');
  if (legend) {
    legend.innerHTML = '<span class="legend-item"><i class="legend-dot" style="background:#789096"></i>Previous AVS</span><span class="legend-item"><i class="legend-dot" style="background:#f2661e"></i>Current AVS</span>';
  }
  if (!canvas) return;
  const entries = rows
    .map(row => ({
      name: row.app_name,
      previous: Number(row.previous_avs || 0),
      current: Number(row.avs || 0),
    }))
    .filter(row => Number.isFinite(row.previous) && Number.isFinite(row.current))
    .sort((left, right) => Math.abs(right.current - right.previous) - Math.abs(left.current - left.previous))
    .slice(0, 7);
  const { ctx, w, h } = setupCanvas(canvas);
  const left = 28;
  const right = 12;
  const top = 40;
  const bottom = 38;
  const chartWidth = Math.max(1, w - left - right);
  const chartHeight = Math.max(1, h - top - bottom);
  const groupWidth = chartWidth / Math.max(entries.length, 1);
  const barWidth = Math.max(6, Math.min(20, groupWidth * .28));
  const maximum = Math.max(...entries.flatMap(row => [row.previous, row.current]), 1);

  ctx.strokeStyle = '#dce4e5';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(left, top);
  ctx.lineTo(left, h - bottom);
  ctx.lineTo(w - right, h - bottom);
  ctx.stroke();

  ctx.font = '700 10px Manrope, Segoe UI, Arial';
  entries.forEach((entry, index) => {
    const center = left + index * groupWidth + groupWidth / 2;
    const bars = [
      { color: '#789096', value: entry.previous, x: center - barWidth - 2, labelOffset: 4 },
      { color: '#f2661e', value: entry.current, x: center + 2, labelOffset: 16 },
    ];
    bars.forEach(bar => {
      const barHeight = bar.value / maximum * chartHeight;
      const y = h - bottom - barHeight;
      ctx.fillStyle = bar.color;
      ctx.fillRect(bar.x, y, barWidth, barHeight);
      if (bar.value > 1) {
        ctx.fillStyle = '#52656b';
        ctx.textAlign = 'center';
        ctx.fillText(shortNumber(bar.value), bar.x + barWidth / 2, Math.max(top - bar.labelOffset + 2, y - bar.labelOffset));
      }
    });
    ctx.fillStyle = '#71808a';
    ctx.textAlign = 'center';
    ctx.fillText(ellipsize(ctx, entry.name, groupWidth - 8), center, h - 10);
  });
}

function renderAvsRow(a) {
  const selected = a.appId === avsSelectedAppId;
  return `<tr class="avs-row-clickable${selected ? ' avs-row-selected' : ''}" data-app-id="${esc(a.appId)}" tabindex="0" aria-selected="${selected}" title="View AVS drill-down"><td><strong>${esc(a.name)}</strong></td><td>${esc(a.team)}</td><td>${a.score.toFixed(1)}</td><td>${badge(a.level, 'avs')}</td><td>${a.uniqueCount}</td><td>${esc(a.fundamentalClassification)}</td><td>${esc(a.zone)}</td></tr>`;
}

const avsTable = createDataTable({
  tbodyId: 'avsTable', searchInputId: 'avsSearch', pageSizeSelectId: 'avsPageSize',
  previousButtonId: 'avsPreviousPage', nextButtonId: 'avsNextPage', pageInfoId: 'avsPageInfo', countId: 'avsCount',
  colSpan: 7, renderRow: renderAvsRow, emptyMessage: 'No application data in current scope',
  matches: (row, query) => `${row.name} ${row.team} ${row.fundamentalClassification} ${row.zone} ${row.level}`.toLowerCase().includes(query),
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

// ----------------------------- Drill-down ---------------------------------

function avsSeverityCell(v) {
  const tone = v.severity === 'Sev5' ? ' avs-sev-5' : v.severity === 'Sev4' ? ' avs-sev-4' : '';
  return `<span class="avs-sev-badge${tone}">${esc(v.severity)}</span>`;
}

function avsExploitCell(v) {
  return v.exploit ? '<span class="avs-sev-badge avs-sev-5">TRUE</span>' : 'FALSE';
}

function renderAvsDetailRow(v) {
  return `<tr><td><strong>${esc(v.name)}</strong></td><td>${esc(v.cve)}</td><td>${avsSeverityCell(v)}</td><td>${esc(v.firstDetected || '—')}</td><td>${v.age} days</td><td>${avsExploitCell(v)}</td><td class="avs-solution">${esc(v.solution || '—')}</td></tr>`;
}

const avsDetailTable = createDataTable({
  tbodyId: 'avsDetailTable', searchInputId: 'avsDetailSearch', pageSizeSelectId: 'avsDetailPageSize',
  previousButtonId: 'avsDetailPreviousPage', nextButtonId: 'avsDetailNextPage', pageInfoId: 'avsDetailPageInfo', countId: 'avsDetailCount',
  colSpan: 7, renderRow: renderAvsDetailRow, emptyMessage: 'No vulnerabilities in this category',
  matches: (row, query) => `${row.name} ${row.cve} ${row.severity} ${row.exploit ? 'exploit true' : 'false'} ${row.solution}`.toLowerCase().includes(query),
});

function avsMarkSelectedRow() {
  const table = document.getElementById('avsTable');
  if (!table || !table.querySelectorAll) return;
  table.querySelectorAll('tr[data-app-id]').forEach(row => {
    const selected = row.dataset.appId === avsSelectedAppId;
    row.classList.toggle('avs-row-selected', selected);
    row.setAttribute('aria-selected', String(selected));
  });
}

function avsHideDrilldown() {
  const section = document.getElementById('avsDrilldown');
  if (section) section.hidden = true;
  avsCurrentDrilldown = null;
  avsPieGeometry = null;
}

function avsRenderCategoryDetail() {
  const detail = document.getElementById('avsCategoryDetail');
  const drill = avsCurrentDrilldown;
  if (!detail || !drill) return;
  const category = drill.categories.find(c => c.name === avsSelectedCategory);
  if (!category || !category.count) {
    avsSelectedCategory = null;
    detail.hidden = true;
    return;
  }
  const rows = avsDrilldownCategoryRows(drill, category.name);
  const { sev4, sev5 } = avsSeverityCounts(rows);
  document.getElementById('avsCategoryDetailTitle').textContent = `${drill.name} · ${category.name}`;
  document.getElementById('avsCategoryDetailSummary').textContent =
    `${category.count.toLocaleString()} unique Sev4/5 vulnerabilities (${category.percent.toFixed(1)}%) · Unique Sev4 Count : ${sev4.toLocaleString()} · Unique Sev5 Count : ${sev5.toLocaleString()}`;
  detail.hidden = false;
  avsDetailTable.update(rows);
}

function avsRenderDrilldown() {
  const drill = avsCurrentDrilldown;
  if (!drill) return;
  document.getElementById('avsDrilldownTitle').textContent = drill.name;
  const kpis = [
    ['Total Unique Sev4/5 Vulnerabilities', drill.total.toLocaleString(), '▦', '', 'Unique (CVE/Vendor) Severity 4 & 5 vulnerabilities older than 45 days'],
    ['Average Age', `${drill.averageAge.toLocaleString()} Days`, '◷', 'kpi-warning', 'Average age of the included unique vulnerabilities'],
    ['Unique Sev4 Count', drill.sev4.toLocaleString(), '●', 'kpi-warning', 'Unique vulnerabilities whose highest source severity is 4'],
    ['Unique Sev5 Count', drill.sev5.toLocaleString(), '▲', 'kpi-critical', 'Unique vulnerabilities with source severity 5'],
  ];
  document.getElementById('avsDrilldownKpis').innerHTML = kpis
    .map(([label, value, icon, tone, hint]) => `<article class="kpi ${tone}" title="${esc(hint)}"><div class="kpi-label"><span>${label}</span><span class="kpi-icon">${icon}</span></div><div class="kpi-value">${value}</div></article>`)
    .join('');

  const entries = drill.categories.map(c => ({ label: c.name, value: c.count, text: `${Math.round(c.percent)}%` }));
  avsPieGeometry = pie(document.getElementById('avsCategoryChart'), entries, AVS_CATEGORY_COLORS, avsSelectedCategory);

  document.getElementById('avsCategoryLegend').innerHTML = drill.categories.map(c => {
    const active = c.name === avsSelectedCategory;
    return `<button type="button" class="legend-item legend-button${active ? ' legend-active' : ''}" data-avs-category="${esc(c.name)}" aria-pressed="${active}"${c.count ? '' : ' disabled'}><i class="legend-dot" style="background:${AVS_CATEGORY_COLORS[c.name]}"></i>${esc(c.name)} ${c.percent.toFixed(1)}%</button>`;
  }).join('');

  document.getElementById('avsCategoryTable').innerHTML = drill.categories.map(c => {
    const active = c.name === avsSelectedCategory;
    const attrs = c.count ? ` class="avs-row-clickable${active ? ' avs-row-selected' : ''}" data-avs-category="${esc(c.name)}" tabindex="0" aria-selected="${active}"` : ' class="avs-row-empty"';
    return `<tr${attrs}><td><i class="legend-dot" style="background:${AVS_CATEGORY_COLORS[c.name]}"></i> ${esc(c.name)}</td><td>${c.count.toLocaleString()}</td><td>${c.percent.toFixed(1)}%</td></tr>`;
  }).join('') + `<tr class="avs-total-row"><td>Total</td><td>${drill.total.toLocaleString()}</td><td>${drill.total ? '100.0%' : '0.0%'}</td></tr>`;

  avsRenderCategoryDetail();
}

// Recomputes the drill-down from the current (dashboard-filtered) records.
// Called on every renderAvs() so filters/resizes keep it in sync; hides the
// section if the selected application is no longer in scope.
function avsRefreshDrilldown(apps) {
  if (!avsSelectedAppId) { avsHideDrilldown(); return; }
  if (apps && !apps.some(a => a.appId === avsSelectedAppId)) {
    avsSelectedAppId = null;
    avsSelectedCategory = null;
    avsHideDrilldown();
    return;
  }
  avsCurrentDrilldown = computeAvsDrilldown(avsLastRecords, avsSelectedAppId);
  const section = document.getElementById('avsDrilldown');
  if (section) section.hidden = false;
  avsRenderDrilldown();
}

function avsSelectApp(appId) {
  const toggleOff = appId === avsSelectedAppId;
  avsSelectedAppId = toggleOff ? null : appId;
  avsSelectedCategory = null;
  avsMarkSelectedRow();
  const detail = document.getElementById('avsCategoryDetail');
  if (detail) detail.hidden = true;
  avsRefreshDrilldown(null);
  const section = document.getElementById('avsDrilldown');
  if (!toggleOff && section && section.scrollIntoView) section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function avsSelectCategory(category) {
  if (!avsCurrentDrilldown) return;
  avsSelectedCategory = category === avsSelectedCategory ? null : category;
  const detail = document.getElementById('avsCategoryDetail');
  if (!avsSelectedCategory && detail) detail.hidden = true;
  avsRenderDrilldown();
  if (avsSelectedCategory && detail && detail.scrollIntoView) detail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function avsCloseDrilldown() {
  avsSelectedAppId = null;
  avsSelectedCategory = null;
  avsMarkSelectedRow();
  avsHideDrilldown();
}

// Delegated activation helper: click + Enter/Space on elements matching `selector`.
function avsBindActivation(element, selector, handler) {
  if (!element || !element.addEventListener) return;
  element.addEventListener('click', event => {
    const target = event.target.closest(selector);
    if (target && !target.disabled) handler(target);
  });
  element.addEventListener('keydown', event => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const target = event.target.closest(selector);
    if (!target || target.tagName === 'BUTTON') return;
    event.preventDefault();
    handler(target);
  });
}

(function bindAvsDrilldown() {
  avsBindActivation(document.getElementById('avsTable'), 'tr[data-app-id]', row => avsSelectApp(row.dataset.appId));
  avsBindActivation(document.getElementById('avsCategoryLegend'), '[data-avs-category]', el => avsSelectCategory(el.dataset.avsCategory));
  avsBindActivation(document.getElementById('avsCategoryTable'), '[data-avs-category]', el => avsSelectCategory(el.dataset.avsCategory));
  const close = document.getElementById('avsDrilldownClose');
  if (close && close.addEventListener) close.addEventListener('click', avsCloseDrilldown);
  const canvas = document.getElementById('avsCategoryChart');
  if (!canvas || !canvas.addEventListener) return;
  const sliceFromEvent = event => {
    const rect = canvas.getBoundingClientRect();
    return pieSliceAt(avsPieGeometry, event.clientX - rect.left, event.clientY - rect.top);
  };
  canvas.addEventListener('click', event => {
    const slice = sliceFromEvent(event);
    if (slice) avsSelectCategory(slice);
  });
  canvas.addEventListener('mousemove', event => {
    canvas.style.cursor = sliceFromEvent(event) ? 'pointer' : 'default';
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
