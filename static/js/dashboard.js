const data = window.DASHBOARD_DATA || {};
let filteredRecords = data.records || [];
const $ = id => document.getElementById(id);
const esc = escapeHtml;

function matchingRecords() {
  const filters = getFilters();
  const query = ($('tableSearch')?.value || '').toLowerCase();
  return (data.records || []).filter(record => recordMatchesFilters(record, filters) && (!query || JSON.stringify(record).toLowerCase().includes(query)));
}

function csvCell(value) { return `"${String(value ?? '').replaceAll('"', '""')}"`; }

function buildFilteredCsv(records) {
  const columns = ['ServerName', 'Operating System', 'Environment', 'AppSpaceName', 'AppSpaceTeam', 'QID', 'Vulnerability Name', 'Severity', 'CVSS Base Score', 'AssetRiskScore', 'CVE', 'Vendor', 'DependantTeam', 'Group', 'Type Category', 'PCI Required', 'Status', 'First Detected', 'Last Detected', 'SLA Due Date', 'Vulnerability Age', 'Days Open', 'Days Remaining', 'Days Overdue', 'SLA Breach', 'Overdue', 'Aging Bucket'];
  return [columns.map(csvCell).join(','), ...records.map(record => columns.map(column => csvCell(record[column])).join(','))].join('\r\n');
}

function downloadBlob(content, mimeType, filename) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function downloadFromResponse(response, fallbackName) {
  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  const disposition = response.headers.get('Content-Disposition') || '';
  const match = disposition.match(/filename="?([^"]+)"?/);
  const filename = match ? match[1] : fallbackName;
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function exportFilteredReport() {
  const csv = buildFilteredCsv(matchingRecords());
  try {
    const response = await fetch('/api/export/filtered', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ csv }) });
    await downloadFromResponse(response, `vulnerability_report_filtered_${new Date().toISOString().slice(0, 10)}.csv`);
  } catch (error) {
    downloadBlob(csv, 'text/csv;charset=utf-8;', `vulnerability_report_filtered_${new Date().toISOString().slice(0, 10)}.csv`);
  }
}

async function exportRawReport() {
  const response = await fetch('/api/export/raw');
  await downloadFromResponse(response, `raw_input_report_${new Date().toISOString().slice(0, 10)}.csv`);
}

async function exportOutputFile() {
  const response = await fetch('/api/export/output');
  await downloadFromResponse(response, 'processed_vulnerabilities.csv');
}

function setImportMessage(text, type = '') {
  const message = $('importMessage');
  message.className = `import-message ${type}`.trim();
  message.textContent = text;
}

async function uploadSelectedReport(file) {
  const button = $('importReport');
  const formData = new FormData();
  formData.append('report', file);
  button.disabled = true;
  setImportMessage(`Importing ${file.name}...`);
  try {
    const response = await fetch('/api/import/upload', { method: 'POST', body: formData });
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.error || `Import failed: ${response.status}`);
    setImportMessage(`Imported ${result.record_count.toLocaleString()} findings from ${result.source}.`, 'success');
    setTimeout(() => window.location.reload(), 700);
  } catch (error) {
    setImportMessage(error.message, 'error');
  } finally {
    button.disabled = false;
    $('reportFileInput').value = '';
  }
}

async function showPortalPlaceholder() {
  setImportMessage('Portal Integration Coming Soon.', 'success');
  try { await fetch('/api/import/portal', { method: 'POST' }); } catch (error) { /* placeholder only */ }
}

async function openArchiveModal() {
  const response = await fetch('/api/archive');
  const { files = [] } = await response.json();
  $('archiveTable').querySelector('tbody').innerHTML = files.map(file => `<tr><td>${esc(file.name)}</td><td>${file.size_kb}</td><td>${esc(file.modified)}</td><td><button type="button" class="archive-download-btn" data-file="${esc(file.name)}">Download</button> <button type="button" class="archive-delete-btn" data-delete="${esc(file.name)}">Delete</button></td></tr>`).join('') || '<tr><td colspan="4">No archived reports yet</td></tr>';
  $('archiveModal').hidden = false;
}

async function deleteArchiveFile(filename) {
  if (!confirm(`Delete "${filename}" from the archive folder?`)) return;
  const response = await fetch(`/api/archive/${encodeURIComponent(filename)}`, { method: 'DELETE' });
  if (response.ok) openArchiveModal();
  else alert('Failed to delete the archived file.');
}

function kpi(label, value, icon, tone = '') {
  return `<article class="kpi ${tone}"><div class="kpi-label"><span>${label}</span><span class="kpi-icon">${icon}</span></div><div class="kpi-value">${(value || 0).toLocaleString()}</div></article>`;
}

function renderKpis(records) {
  const count = key => records.filter(key).length;
  const critical = count(r => r.Severity === 'Critical');
  const values = [
    ['Total Vulnerabilities', records.length, '◈'],
    ['Critical Vulnerabilities', critical, '◆', 'kpi-critical'],
    ['High Vulnerabilities', count(r => r.Severity === 'High'), '▲', 'kpi-warning'],
    ['Medium Vulnerabilities', count(r => r.Severity === 'Medium'), '●', 'kpi-warning'],
    ['Low Vulnerabilities', count(r => r.Severity === 'Low'), '●', 'kpi-good'],
    ['Overdue Vulnerabilities', count(r => r.Overdue), '!', 'kpi-critical'],
    ['Critical Overdue', count(r => r.Overdue && r.Severity === 'Critical'), '!', 'kpi-critical'],
    ['Open Vulnerabilities', count(r => r.Status === 'Open'), '○', 'kpi-warning'],
    ['Resolved Vulnerabilities', count(r => r.Status === 'Resolved'), '✓', 'kpi-good'],
    ['SLA Breached', count(r => r['SLA Breach']), '!', 'kpi-critical'],
    ['Assets Affected', new Set(records.map(r => r.ServerName)).size, '◇'],
    ['Unique Servers', new Set(records.map(r => r.ServerName)).size, '⌁'],
    ['Applications', new Set(records.map(r => r.AppSpaceName)).size, '▦'],
    ['PCI Required', count(r => r['PCI Required']), '▣'],
  ];
  $('kpis').innerHTML = values.map(x => kpi(...x)).join('');
}

function renderCharts(records) {
  const groups = ['Critical', 'High', 'Medium', 'Low'];
  const statuses = ['Open', 'In Progress', 'Resolved', 'Closed'];

  const severity = Object.fromEntries(groups.map(key => [key, records.filter(r => r.Severity === key).length]));
  donut($('severityChart'), severity);
  $('donutTotal').textContent = records.length.toLocaleString();
  $('severityLegend').innerHTML = Object.entries(severity).map(([key, value]) => `<span class="legend-item"><i class="legend-dot" style="background:${COLORS[key]}"></i>${key} ${value}</span>`).join('');

  const statusValues = Object.fromEntries(statuses.map(status => [status, Object.fromEntries(groups.map(s => [s, records.filter(r => r.Severity === s && r.Status === status).length]))]));
  groupedBars($('statusChart'), groups, statuses, statuses.map(s => COLORS[s]), Math.max(...Object.values(statusValues).flatMap(Object.values), 1), statusValues);

  const slaValues = { 'Within SLA': Object.fromEntries(groups.map(s => [s, records.filter(r => r.Severity === s && !r['SLA Breach']).length])), 'SLA Breached': Object.fromEntries(groups.map(s => [s, records.filter(r => r.Severity === s && r['SLA Breach']).length])) };
  groupedBars($('slaChart'), groups, Object.keys(slaValues), ['#2f9d6c', '#d43a2c'], Math.max(...Object.values(slaValues).flatMap(Object.values), 1), slaValues);

  const ages = ['0-7 Days', '8-30 Days', '31-60 Days', '61-90 Days', '91-180 Days', '181-365 Days', '365+ Days'];
  horizontalBars($('agingChart'), ages.map(name => ({ name, total: records.filter(r => r['Aging Bucket'] === name).length })), '#f2661e');

  const servers = {};
  records.forEach(r => { servers[r.ServerName] = (servers[r.ServerName] || 0) + 1; });
  horizontalBars($('serverChart'), Object.entries(servers).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, total]) => ({ name, total })), '#de8324');

  // Environment distribution: dynamic categories, so build a stable palette-based color map.
  const environments = [...new Set(records.map(r => r.Environment))].sort((a, b) => records.filter(r => r.Environment === b).length - records.filter(r => r.Environment === a).length);
  const envCounts = Object.fromEntries(environments.map(name => [name, records.filter(r => r.Environment === name).length]));
  const envColors = paletteColorMap(environments);
  donut($('envDistributionChart'), envCounts, envColors);
  $('envDonutTotal').textContent = records.length.toLocaleString();
  $('envDistributionLegend').innerHTML = Object.entries(envCounts).map(([key, value]) => `<span class="legend-item"><i class="legend-dot" style="background:${envColors[key]}"></i>${esc(key)} ${value}</span>`).join('') || '<span class="muted">No data</span>';

  // Remediation action distribution: reuses the Status field (Open / In Progress / Resolved / Closed),
  // which represents the remediation stage each finding is currently in.
  const remediationCounts = Object.fromEntries(statuses.map(status => [status, records.filter(r => r.Status === status).length]));
  donut($('remediationChart'), remediationCounts);
  $('remediationDonutTotal').textContent = records.length.toLocaleString();
  $('remediationLegend').innerHTML = Object.entries(remediationCounts).map(([key, value]) => `<span class="legend-item"><i class="legend-dot" style="background:${COLORS[key]}"></i>${key} ${value}</span>`).join('');
}

function heat(value) { return `heat-${Math.min(4, Math.ceil(value / 5) || 0)}`; }

function computeMatrixRows(records) {
  return [...new Set(records.map(r => r.AppSpaceName))].map(name => {
    const rs = records.filter(r => r.AppSpaceName === name);
    return {
      name,
      team: rs[0]?.AppSpaceTeam || 'Unknown',
      values: Object.fromEntries(['Critical', 'High', 'Medium', 'Low'].map(s => [s, rs.filter(r => r.Severity === s).length])),
      overdue: rs.filter(r => r.Overdue).length,
      breach: rs.filter(r => r['SLA Breach']).length,
    };
  }).sort((a, b) => Object.values(b.values).reduce((x, y) => x + y, 0) - Object.values(a.values).reduce((x, y) => x + y, 0));
}

function renderMatrixRow(row) {
  return `<tr><td><strong>${esc(row.name)}</strong></td><td>${esc(row.team)}</td>${['Critical', 'High', 'Medium', 'Low'].map(s => `<td class="${heat(row.values[s])}">${row.values[s]}</td>`).join('')}<td class="${row.overdue ? 'heat-3' : ''}">${row.overdue}</td><td class="${row.breach ? 'heat-3' : ''}">${row.breach}</td></tr>`;
}

function badge(value, type) { return `<span class="${type}-badge ${type}-${String(value).replaceAll(' ', '-')}">${esc(value || 'Unknown')}</span>`; }

function computeCriticalRows(records) {
  return records.filter(r => r.Severity === 'Critical').sort((a, b) => Number(b['SLA Breach']) - Number(a['SLA Breach']) || b['Days Open'] - a['Days Open']);
}

function renderCriticalRow(r) {
  return `<tr><td>${esc(r.ServerName)}</td><td>${esc(r['Vulnerability Name'])}</td><td>${esc(r.Environment)}</td><td>${esc(r.AppSpaceName)}</td><td>${r['Days Open']}d</td><td>${r['SLA Due Date'] || 'Unknown'}</td><td>${r['SLA Breach'] ? '<span class="sla-badge">Breached</span>' : badge(r.Status, 'status')}</td></tr>`;
}

function rankList(id, records, key) {
  const counts = {};
  records.forEach(r => { const value = r[key]; if (value && value !== 'N/A' && value !== 'Unknown') counts[value] = (counts[value] || 0) + 1; });
  $(id).innerHTML = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, count], i) => `<div class="rank-row"><span class="rank-number">${String(i + 1).padStart(2, '0')}</span><span class="rank-name" title="${esc(name)}">${esc(name)}</span><strong class="rank-count">${count}</strong></div>`).join('') || '<span class="muted">No data</span>';
}

function renderRegisterRow(r) {
  return `<tr><td>${esc(r.ServerName)}</td><td>${esc(r['Operating System'])}</td><td>${esc(r.Environment)}</td><td>${esc(r.AppSpaceName)}</td><td>${esc(r.DependantTeam || 'Other')}</td><td>${esc(r.Group || 'Suncorp Group')}</td><td>${esc(r.QID)}</td><td title="${esc(r['Vulnerability Name'])}">${esc(String(r['Vulnerability Name']).slice(0, 30))}</td><td>${badge(r.Severity, 'severity')}</td><td>${r['CVSS Base Score'] ?? '-'}</td><td>${r['First Detected'] || '-'}</td><td>${r['Days Open']}d</td><td>${r['SLA Breach'] ? '<span class="sla-badge">' + (r['Days Overdue'] || 0) + 'd late</span>' : `<span class="ok">${r['SLA Due Date'] || '-'}</span>`}</td><td>${badge(r.Status, 'status')}</td></tr>`;
}

function recordSearchText(record) { return JSON.stringify(record).toLowerCase(); }

const registerTable = createDataTable({
  tbodyId: 'recordsTable', searchInputId: 'tableSearch', pageSizeSelectId: 'recordsPageSize',
  previousButtonId: 'previousPage', nextButtonId: 'nextPage', pageInfoId: 'pageInfo', countId: 'tableCount',
  colSpan: 14, renderRow: renderRegisterRow, emptyMessage: 'No vulnerabilities match the current scope',
  matches: (row, query) => recordSearchText(row).includes(query),
});

const criticalTable = createDataTable({
  tbodyId: 'criticalTable', searchInputId: 'criticalSearch', pageSizeSelectId: 'criticalPageSize',
  previousButtonId: 'criticalPreviousPage', nextButtonId: 'criticalNextPage', pageInfoId: 'criticalPageInfo', countId: 'criticalCount',
  colSpan: 7, renderRow: renderCriticalRow, emptyMessage: 'No critical vulnerabilities in current scope',
  matches: (row, query) => recordSearchText(row).includes(query),
});

const matrixTable = createDataTable({
  tbodyId: 'matrixTable', searchInputId: 'matrixSearch', pageSizeSelectId: 'matrixPageSize',
  previousButtonId: 'matrixPreviousPage', nextButtonId: 'matrixNextPage', pageInfoId: 'matrixPageInfo', countId: 'matrixCount',
  colSpan: 8, renderRow: renderMatrixRow, emptyMessage: 'No AppSpace data',
  matches: (row, query) => `${row.name} ${row.team}`.toLowerCase().includes(query),
});

function render() {
  filteredRecords = matchingRecords();
  renderKpis(filteredRecords);
  renderCharts(filteredRecords);
  renderAvs(filteredRecords);
  matrixTable.update(computeMatrixRows(filteredRecords));
  criticalTable.update(computeCriticalRows(filteredRecords));
  rankList('cveList', filteredRecords, 'CVE');
  rankList('qidList', filteredRecords, 'QID');
  const pci = filteredRecords.filter(r => r['PCI Required']);
  $('pciMetric').innerHTML = `<div><div class="compliance-number">${pci.length}</div><div class="compliance-label">required findings <span class="footer-separator">•</span> ${pci.filter(r => r['SLA Breach']).length} breached</div></div>`;
  registerTable.update(filteredRecords);
}

buildFilters(data, () => { render(); });
$('resetFilters').addEventListener('click', () => { resetFilters(data); $('tableSearch').value = ''; render(); });
$('refreshDashboard').addEventListener('click', () => window.location.reload());
$('exportReport').addEventListener('click', event => { event.stopPropagation(); $('exportMenu').hidden = !$('exportMenu').hidden; });
$('importReport').addEventListener('click', event => { event.stopPropagation(); $('importMenu').hidden = !$('importMenu').hidden; });
$('importMenu').addEventListener('click', event => {
  const action = event.target.dataset.action;
  if (!action) return;
  $('importMenu').hidden = true;
  if (action === 'upload') $('reportFileInput').click();
  else if (action === 'portal') showPortalPlaceholder();
});
$('reportFileInput').addEventListener('change', event => { const [file] = event.target.files; if (file) uploadSelectedReport(file); });
$('exportMenu').addEventListener('click', event => {
  const action = event.target.dataset.action;
  if (!action) return;
  $('exportMenu').hidden = true;
  if (action === 'filtered') exportFilteredReport();
  else if (action === 'output') exportOutputFile();
  else if (action === 'raw') exportRawReport();
  else if (action === 'archive') openArchiveModal();
});
document.addEventListener('click', event => {
  if (!$('exportMenu').hidden && !event.target.closest('.export-dropdown')) $('exportMenu').hidden = true;
  if (!$('importMenu').hidden && !event.target.closest('.import-dropdown')) $('importMenu').hidden = true;
});
$('archiveModalClose').addEventListener('click', () => { $('archiveModal').hidden = true; });
$('archiveModal').addEventListener('click', async event => {
  if (event.target === $('archiveModal')) { $('archiveModal').hidden = true; return; }
  const file = event.target.dataset.file;
  if (file) { const response = await fetch(`/api/archive/download/${encodeURIComponent(file)}`); await downloadFromResponse(response, file); return; }
  const toDelete = event.target.dataset.delete;
  if (toDelete) await deleteArchiveFile(toDelete);
});
$('tableSearch').addEventListener('input', () => { render(); });

let resizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => { renderCharts(filteredRecords); renderAvs(filteredRecords); }, 120);
});

$('reportStatus').textContent = window.LOAD_ERROR ? 'Report unavailable' : `${data.meta?.record_count || 0} findings loaded`;
if (window.LOAD_ERROR) {
  $('statusChip').classList.add('status-chip-error');
  $('statusDot').classList.add('status-dot-error');
}
$('lastUpdated').textContent = data.meta?.today ? `Calculated ${data.meta.today}` : '';
render();

// The assistant reads the already-filtered record set on demand, so opening or
// querying it never adds work to the dashboard render path.
initAssistant({
  getContext: () => ({
    records: filteredRecords,
    allRecords: data.records || [],
    rawFilters: getFilters(),
    filters: activeFilterSummary(),
    search: $('tableSearch')?.value || '',
    meta: data.meta || {},
  }),
});
