const data = window.DASHBOARD_DATA || {};
let filteredRecords = data.records || [];
const $ = id => document.getElementById(id);
const esc = escapeHtml;

function matchingRecords() {
  const filters = getFilters();
  const query = ($('tableSearch')?.value || '').toLowerCase();
  return (data.records || []).filter(record => recordMatchesFilters(record, filters) && (!query || JSON.stringify(record).toLowerCase().includes(query)));
}

const EXPLOIT_COLORS = { Exploitable: '#c9363e', 'Not exploitable': '#9fb7b7' };

// Exploit flag of a record (boolean in the API, "TRUE"/"FALSE" in CSV data).
function isExploit(record) {
  const value = record.Exploit;
  return value === true || String(value).trim().toUpperCase() === 'TRUE';
}

function csvCell(value) { return `"${String(value ?? '').replaceAll('"', '""')}"`; }

function buildFilteredCsv(records) {
  const columns = ['ServerName', 'Operating System', 'Environment', 'AppSpaceName', 'AppSpaceTeam', 'QID', 'Vulnerability Name', 'Severity', 'CVSS Base Score', 'AssetRiskScore', 'CVE', 'Vendor', 'Unique Vuln Name', 'VULN COUNT', 'VulKey', 'NewResolvedStatus', 'ThreatIntel', 'Exploit', 'RemitTeam', 'Group', 'Type Category', 'PCI Required', 'Status', 'First Detected', 'Last Detected', 'SLA Due Date', 'Vulnerability Age', 'Days Open', 'Days Remaining', 'Days Overdue', 'SLABreach', 'Overdue', 'Aging Bucket', 'FundamentalClassification', 'Zone'];
  const cellValue = (record, column) => (column === 'Exploit' ? (isExploit(record) ? 'TRUE' : 'FALSE') : record[column]);
  return [columns.map(csvCell).join(','), ...records.map(record => columns.map(column => csvCell(cellValue(record, column))).join(','))].join('\r\n');
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

function kpi(label, value, icon, tone = '', hint = '') {
  const title = hint ? ` title="${esc(hint)}"` : '';
  return `<article class="kpi ${tone}"${title}><div class="kpi-label"><span>${label}</span><span class="kpi-icon">${icon}</span></div><div class="kpi-value">${(value || 0).toLocaleString()}</div></article>`;
}

function latestTrendEntry() {
  const history = data.trend_history || [];
  return history[history.length - 1] || {};
}

function scopeIsFiltered() {
  return Object.values(getFilters()).some(values => values.length) || Boolean(($('tableSearch')?.value || '').trim());
}

// Unfiltered: the latest weekly comparison in trend_history.json. Filtered: the
// same metric re-derived from the in-scope records' NewResolvedStatus.
function newVulnerabilityCount(records) {
  if (!scopeIsFiltered()) return Number(latestTrendEntry().new) || 0;
  return records.filter(r => r.NewResolvedStatus === 'New').length;
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
    ['New Vulnerabilities', newVulnerabilityCount(records), '✚', 'kpi-warning', 'New vulnerabilities identified in the latest weekly comparison.'],
    ['Last Week Resolved Vulnerabilities', latestTrendEntry().resolved || 0, '✓', 'kpi-good'],
    ['SLA Breached', count(r => r.SLABreach), '!', 'kpi-critical'],
    ['Assets Affected', new Set(records.map(r => r.ServerName)).size, '◇'],
    ['Unique Servers', new Set(records.map(r => r.ServerName)).size, '⌁'],
    ['Applications', new Set(records.map(r => r.AppSpaceName)).size, '▦'],
    ['PCI Required', count(r => r['PCI Required']), '▣'],
    ['Exploitable Vulnerabilities', count(isExploit), '⚠', 'kpi-critical'],
    ['Unique Vuln Instances', new Set(records.map(r => r['VULN COUNT']).filter(Boolean)).size, '#'],
  ];
  $('kpis').innerHTML = values.map(x => kpi(...x)).join('');
}

const MOVEMENT_SERIES = [
  { key: 'new', label: 'New', color: '#d43a2c' },
  { key: 'resolved', label: 'Resolved', color: '#2f9d6c' },
  { key: 'unchanged', label: 'Unchanged', color: '#de8324' },
];

function movementStatusSelection() {
  return getFilters().new_resolved_status || [];
}

function selectMovementStatus(status) {
  const select = document.querySelector('[data-filter="new_resolved_status"]');
  if (!select) return;
  select.value = select.value === status ? '' : status;
  updateFilterOptions(data);
  render();
}

function movementCard(item, value) {
  const tone = item.key === 'new' ? 'kpi-critical' : item.key === 'resolved' ? 'kpi-good' : 'kpi-warning';
  return `<button type="button" class="kpi kpi-clickable movement-kpi ${tone}" data-movement-status="${item.label}"><span class="kpi-label"><span>${item.label} Vulnerabilities</span><span class="kpi-icon">●</span></span><span class="kpi-value">${Number(value || 0).toLocaleString()}</span></button>`;
}

function renderWeeklyMovement() {
  const history = data.trend_history || [];
  const latest = history[history.length - 1] || { new: 0, resolved: 0, unchanged: 0 };
  const selected = movementStatusSelection();
  const visibleSeries = MOVEMENT_SERIES.filter(item => !selected.length || selected.includes(item.label));
  lineChart($('movementTrendChart'), history, visibleSeries, $('movementTrendTooltip'));
  $('movementTrendLegend').innerHTML = visibleSeries.map(item => `<span class="legend-item"><i class="legend-dot" style="background:${item.color}"></i>${item.label}</span>`).join('');
  $('movementKpis').innerHTML = MOVEMENT_SERIES.map(item => movementCard(item, latest[item.key])).join('');
  document.querySelectorAll('[data-movement-status]').forEach(button => {
    button.addEventListener('click', () => selectMovementStatus(button.dataset.movementStatus));
  });

  const pieValues = Object.fromEntries(MOVEMENT_SERIES.map(item => [item.label, (!selected.length || selected.includes(item.label)) ? Number(latest[item.key] || 0) : 0]));
  const total = Object.values(pieValues).reduce((sum, value) => sum + value, 0);
  const colors = Object.fromEntries(MOVEMENT_SERIES.map(item => [item.label, item.color]));
  const geometry = pie($('movementPieChart'), MOVEMENT_SERIES.map(item => ({
    label: item.label,
    value: pieValues[item.label],
    text: assistantPercent(pieValues[item.label], total),
  })), colors, null);
  $('movementPieLegend').innerHTML = MOVEMENT_SERIES.map(item => `<span class="legend-item"><i class="legend-dot" style="background:${item.color}"></i>${item.label} ${pieValues[item.label].toLocaleString()} (${assistantPercent(pieValues[item.label], total)})</span>`).join('');
  const pieCanvas = $('movementPieChart');
  const pieTooltip = $('movementPieTooltip');
  pieCanvas.onmousemove = event => {
    const rect = pieCanvas.getBoundingClientRect();
    const label = pieSliceAt(geometry, event.clientX - rect.left, event.clientY - rect.top);
    if (!label) { pieTooltip.hidden = true; return; }
    pieTooltip.innerHTML = `<strong>${esc(label)}</strong><span>Count: ${pieValues[label].toLocaleString()}</span><span>Percentage: ${assistantPercent(pieValues[label], total)}</span>`;
    pieTooltip.style.left = `${Math.min(rect.width - 145, Math.max(8, event.clientX - rect.left + 10))}px`;
    pieTooltip.style.top = `${Math.max(8, event.clientY - rect.top - 55)}px`;
    pieTooltip.hidden = false;
  };
  pieCanvas.onmouseleave = () => { pieTooltip.hidden = true; };
  movementTable.update(history.slice().reverse());
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

  const slaValues = { 'Within SLA': Object.fromEntries(groups.map(s => [s, records.filter(r => r.Severity === s && !r.SLABreach).length])), 'SLA Breached': Object.fromEntries(groups.map(s => [s, records.filter(r => r.Severity === s && r.SLABreach).length])) };
  groupedBars($('slaChart'), groups, Object.keys(slaValues), ['#2f9d6c', '#d43a2c'], Math.max(...Object.values(slaValues).flatMap(Object.values), 1), slaValues);

  const ages = ['0-7 Days', '8-30 Days', '31-60 Days', '61-90 Days', '91-180 Days', '181-365 Days', '365+ Days'];
  horizontalBars($('agingChart'), ages.map(name => ({ name, total: records.filter(r => r['Aging Bucket'] === name).length })), '#f2661e');

  const servers = {};
  records.forEach(r => { servers[r.ServerName] = (servers[r.ServerName] || 0) + 1; });
  const exploitCount = records.filter(isExploit).length;
  const exploit = { Exploitable: exploitCount, 'Not exploitable': records.length - exploitCount };
  donut($('exploitChart'), exploit, EXPLOIT_COLORS);
  $('exploitTotal').textContent = exploitCount.toLocaleString();
  $('exploitLegend').innerHTML = Object.entries(exploit).map(([key, value]) => `<span class="legend-item"><i class="legend-dot" style="background:${EXPLOIT_COLORS[key]}"></i>${key} ${value}</span>`).join('');

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
      breach: rs.filter(r => r.SLABreach).length,
    };
  }).sort((a, b) => Object.values(b.values).reduce((x, y) => x + y, 0) - Object.values(a.values).reduce((x, y) => x + y, 0));
}

function renderMatrixRow(row) {
  return `<tr><td><strong>${esc(row.name)}</strong></td><td>${esc(row.team)}</td>${['Critical', 'High', 'Medium', 'Low'].map(s => `<td class="${heat(row.values[s])}">${row.values[s]}</td>`).join('')}<td class="${row.overdue ? 'heat-3' : ''}">${row.overdue}</td><td class="${row.breach ? 'heat-3' : ''}">${row.breach}</td></tr>`;
}

function badge(value, type) { return `<span class="${type}-badge ${type}-${String(value).replaceAll(' ', '-')}">${esc(value || 'Unknown')}</span>`; }

function computeCriticalRows(records) {
  return records.filter(r => r.Severity === 'Critical').sort((a, b) => Number(b.SLABreach) - Number(a.SLABreach) || b['Days Open'] - a['Days Open']);
}

function isTrue(value) {
  if (value === true || value === 1) return true;
  if (value === false || value === 0 || value === null || value === undefined) return false;
  const s = String(value).trim().toUpperCase();
  return s === 'TRUE' || s === '1' || s === 'YES' || s === 'T' || s === 'Y';
}

function computeMostRiskyRows(records) {
  const unique = new Map();
  records.forEach(record => {
    if (!['4', '5'].includes(String(record['Severity Level'] || '')) ||
        !['Essential', 'Fundamental'].includes(record.FundamentalClassification) ||
        !isTrue(record.PatchAvailable) || !isTrue(record.SLABreach ?? record.SIABreach) ||
        record.Zone !== 'External' || !isTrue(record.Exploit) ||
        !record['VULN COUNT'] || unique.has(record['VULN COUNT'])) return;
    unique.set(record['VULN COUNT'], record);
  });
  return [...unique.values()].sort((a, b) => Number(b['Days Open'] || 0) - Number(a['Days Open'] || 0));
}

function renderMostRiskyRow(r) {
  return `<tr><td>${esc(r.AppSpaceId || 'N/A')}</td><td>${esc(r.AppSpaceName || 'N/A')}</td><td>${esc(r.ServerName || 'N/A')}</td><td>${esc(r['Vulnerability Name'] || 'N/A')}</td><td>${esc(r.CVE || 'N/A')}</td><td>${esc(r['First Detected'] || 'N/A')}</td><td>${r['Vulnerability Age'] || 0}d</td><td>${esc(r.RemitTeam || 'N/A')}</td><td>${esc(r.Solution || 'N/A')}</td></tr>`;
}

function renderMostRiskyCharts(records) {
  const total = records.length;
  const uniqueApps = new Set(records.map(r => r.AppSpaceName).filter(Boolean)).size;
  const averageAge = total ? Math.round(records.reduce((sum, r) => sum + Number(r['Vulnerability Age'] || r['Days Open'] || 0), 0) / total) : 0;
  $('mostRiskySummary').innerHTML = [
    ['Total Most Risky Vulnerabilities', total],
    ['Unique Applications', uniqueApps],
    ['Average Age', `${averageAge} days`],
  ].map(([label, value]) => `<div class="risky-summary-item"><span>${label}</span><strong>${Number.isFinite(value) ? value.toLocaleString() : value}</strong></div>`).join('');

  const categoryCounts = {};
  records.forEach(r => { const key = r['Type Category'] || r.Category || 'Unknown'; categoryCounts[key] = (categoryCounts[key] || 0) + 1; });
  const categoryColors = paletteColorMap(Object.keys(categoryCounts));
  donut($('mostRiskyCategoryChart'), categoryCounts, categoryColors);
  $('mostRiskyCategoryLegend').innerHTML = Object.entries(categoryCounts).map(([key, value]) => `<span class="legend-item"><i class="legend-dot" style="background:${categoryColors[key]}"></i>${esc(key)} ${value} (${assistantPercent(value, total)})</span>`).join('') || '<span class="muted">No data</span>';

  const appCounts = {};
  records.forEach(r => { appCounts[r.AppSpaceName] = (appCounts[r.AppSpaceName] || 0) + 1; });
  horizontalBars($('mostRiskyApplicationChart'), Object.entries(appCounts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, count]) => ({ name, total: count })), '#f2661e');
}

function renderMostRiskyDebug(recordsInScope) {
  const host = $('mostRiskyDebugPanel');
  if (!host) return;
  const all = recordsInScope || [];
  const total = all.length;

  // Individual rule counts
  const cSeverity = all.filter(r => ['4', '5'].includes(String(r['Severity Level'] || ''))).length;
  const cClassification = all.filter(r => ['Essential', 'Fundamental'].includes(r.FundamentalClassification)).length;
  const cPatch = all.filter(r => isTrue(r.PatchAvailable)).length;
  const cSla = all.filter(r => isTrue(r.SLABreach ?? r.SIABreach)).length;
  const cZone = all.filter(r => r.Zone === 'External').length;
  const cExploit = all.filter(r => isTrue(r.Exploit)).length;

  // Cumulative steps
  const s1 = all.filter(r => ['4', '5'].includes(String(r['Severity Level'] || '')));
  const s3 = s1.filter(r => ['Essential', 'Fundamental'].includes(r.FundamentalClassification));
  const s4 = s3.filter(r => isTrue(r.PatchAvailable));
  const s5 = s4.filter(r => isTrue(r.SLABreach ?? r.SIABreach));
  const s6 = s5.filter(r => r.Zone === 'External');
  const s7 = s6.filter(r => isTrue(r.Exploit));

  const uniqueMap = new Map();
  s7.forEach(r => { if (r['VULN COUNT'] && !uniqueMap.has(r['VULN COUNT'])) uniqueMap.set(r['VULN COUNT'], r); });
  const finalCount = uniqueMap.size;

  let reasonHtml = '';
  if (finalCount === 0) {
    let bottleneck = 'No records in active scope.';
    if (total > 0) {
      if (s1.length === 0) bottleneck = 'Eliminated at Step 1: No records have Severity 4 or 5.';
      else if (s3.length === 0) bottleneck = 'Eliminated at Step 2: No Severity 4/5 records match FundamentalClassification in ("Essential", "Fundamental").';
      else if (s4.length === 0) bottleneck = 'Eliminated at Step 3: No records have PatchAvailable = TRUE (or 1).';
      else if (s5.length === 0) bottleneck = 'Eliminated at Step 4: No records have SLABreach = TRUE.';
      else if (s6.length === 0) bottleneck = 'Eliminated at Step 5: No records have Zone = "External".';
      else if (s7.length === 0) bottleneck = 'Eliminated at Step 6: No records have Exploit = TRUE.';
      else bottleneck = 'Eliminated at Step 6: VULN COUNT deduplication or missing VULN COUNT keys.';
    }
    reasonHtml = `<div class="risky-debug-reason"><strong>Reason for 0 count:</strong> ${esc(bottleneck)}</div>`;
  }

  host.innerHTML = `
    <div class="risky-debug-head">
      <h4>Most Risky Vulnerabilities Logic Validation (Debug Mode)</h4>
      <span class="risky-debug-tag">${finalCount} Active Unique Findings</span>
    </div>
    <div class="risky-debug-grid">
      <div class="risky-debug-col">
        <h5>1. Individual Rule Breakdown (in scope)</h5>
        <ul class="risky-debug-list">
          <li><span>1. Total Records</span><strong>${total.toLocaleString()}</strong></li>
          <li><span>2. Severity 4 or 5</span><strong>${cSeverity.toLocaleString()}</strong></li>
          <li><span>3. FundamentalClassification = Essential/Fundamental</span><strong>${cClassification.toLocaleString()}</strong></li>
          <li><span>4. PatchAvailable = TRUE</span><strong>${cPatch.toLocaleString()}</strong></li>
          <li><span>5. SLABreach = TRUE</span><strong>${cSla.toLocaleString()}</strong></li>
          <li><span>6. Zone = External</span><strong>${cZone.toLocaleString()}</strong></li>
          <li><span>7. Exploit = TRUE</span><strong>${cExploit.toLocaleString()}</strong></li>
        </ul>
      </div>
      <div class="risky-debug-col">
        <h5>2. Cumulative Filtering Steps</h5>
        <ul class="risky-debug-list">
          <li><span>Step 1: Severity 4/5</span><strong>${s1.length.toLocaleString()}</strong></li>
          <li class="${s3.length === 0 ? 'debug-step-eliminated' : ''}"><span>Step 2: + FundamentalClassification</span><strong>${s3.length.toLocaleString()}</strong></li>
          <li class="${s4.length === 0 ? 'debug-step-eliminated' : ''}"><span>Step 3: + PatchAvailable</span><strong>${s4.length.toLocaleString()}</strong></li>
          <li class="${s5.length === 0 ? 'debug-step-eliminated' : ''}"><span>Step 4: + SLABreach</span><strong>${s5.length.toLocaleString()}</strong></li>
          <li class="${s6.length === 0 ? 'debug-step-eliminated' : ''}"><span>Step 5: + Zone (External)</span><strong>${s6.length.toLocaleString()}</strong></li>
          <li class="${s7.length === 0 ? 'debug-step-eliminated' : ''}"><span>Step 6: + Exploit (All criteria)</span><strong>${s7.length.toLocaleString()}</strong></li>
          <li class="debug-step-final"><span>Final: Unique VULN COUNT</span><strong>${finalCount.toLocaleString()}</strong></li>
        </ul>
      </div>
    </div>
    ${reasonHtml}
  `;
}

function renderCriticalRow(r) {
  return `<tr><td>${esc(r.ServerName)}</td><td>${esc(r['Vulnerability Name'])}</td><td>${esc(r.Environment)}</td><td>${esc(r.AppSpaceName)}</td><td>${r['Days Open']}d</td><td>${r['SLA Due Date'] || 'Unknown'}</td><td>${r.SLABreach ? '<span class="sla-badge">Breached</span>' : badge(r.Status, 'status')}</td></tr>`;
}

function rankList(id, records, key) {
  const counts = {};
  records.forEach(r => { const value = r[key]; if (value && value !== 'N/A' && value !== 'Unknown') counts[value] = (counts[value] || 0) + 1; });
  $(id).innerHTML = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, count], i) => `<div class="rank-row"><span class="rank-number">${String(i + 1).padStart(2, '0')}</span><span class="rank-name" title="${esc(name)}">${esc(name)}</span><strong class="rank-count">${count}</strong></div>`).join('') || '<span class="muted">No data</span>';
}

function renderRegisterRow(r) {
  return `<tr><td>${esc(r.ServerName)}</td><td>${esc(r['Operating System'])}</td><td>${esc(r.Environment)}</td><td>${esc(r.AppSpaceName)}</td><td>${esc(r.RemitTeam || 'Other')}</td><td>${esc(r.Group || 'Suncorp Group')}</td><td>${esc(r.QID)}</td><td>${esc(r['Unique Vuln Name'] || '-')}</td><td title="${esc(r['Vulnerability Name'])}">${esc(String(r['Vulnerability Name']).slice(0, 30))}</td><td>${badge(r.Severity, 'severity')}</td><td>${isExploit(r) ? '<span class="sla-badge">TRUE</span>' : 'FALSE'}</td><td>${r['CVSS Base Score'] ?? '-'}</td><td>${r['First Detected'] || '-'}</td><td>${r['Days Open']}d</td><td>${r.SLABreach ? '<span class="sla-badge">' + (r['Days Overdue'] || 0) + 'd late</span>' : `<span class="ok">${r['SLA Due Date'] || '-'}</span>`}</td><td>${badge(r.Status, 'status')}</td></tr>`;
}

function recordSearchText(record) { return JSON.stringify(record).toLowerCase(); }

const registerTable = createDataTable({
  tbodyId: 'recordsTable', searchInputId: 'tableSearch', pageSizeSelectId: 'recordsPageSize',
  previousButtonId: 'previousPage', nextButtonId: 'nextPage', pageInfoId: 'pageInfo', countId: 'tableCount',
  colSpan: 16, renderRow: renderRegisterRow, emptyMessage: 'No vulnerabilities match the current scope',
  matches: (row, query) => recordSearchText(row).includes(query),
});

const criticalTable = createDataTable({
  tbodyId: 'criticalTable', searchInputId: 'criticalSearch', pageSizeSelectId: 'criticalPageSize',
  previousButtonId: 'criticalPreviousPage', nextButtonId: 'criticalNextPage', pageInfoId: 'criticalPageInfo', countId: 'criticalCount',
  colSpan: 7, renderRow: renderCriticalRow, emptyMessage: 'No critical vulnerabilities in current scope',
  matches: (row, query) => recordSearchText(row).includes(query),
});

const mostRiskyTable = createDataTable({
  tbodyId: 'mostRiskyTable', searchInputId: 'mostRiskySearch', pageSizeSelectId: 'mostRiskyPageSize',
  previousButtonId: 'mostRiskyPreviousPage', nextButtonId: 'mostRiskyNextPage', pageInfoId: 'mostRiskyPageInfo', countId: 'mostRiskyCount',
  colSpan: 9, renderRow: renderMostRiskyRow, emptyMessage: 'No Most Risky Vulnerabilities match the current scope',
  matches: (row, query) => recordSearchText(row).includes(query),
});

const matrixTable = createDataTable({
  tbodyId: 'matrixTable', searchInputId: 'matrixSearch', pageSizeSelectId: 'matrixPageSize',
  previousButtonId: 'matrixPreviousPage', nextButtonId: 'matrixNextPage', pageInfoId: 'matrixPageInfo', countId: 'matrixCount',
  colSpan: 8, renderRow: renderMatrixRow, emptyMessage: 'No AppSpace data',
  matches: (row, query) => `${row.name} ${row.team}`.toLowerCase().includes(query),
});

const movementTable = createDataTable({
  tbodyId: 'movementTable', searchInputId: 'movementSearch',
  previousButtonId: 'movementPreviousPage', nextButtonId: 'movementNextPage',
  pageInfoId: 'movementPageInfo', countId: 'movementCount', defaultPageSize: 7,
  colSpan: 4,
  renderRow: row => `<tr><td><strong>${esc(row.week)}</strong></td><td>${Number(row.new || 0).toLocaleString()}</td><td>${Number(row.resolved || 0).toLocaleString()}</td><td>${Number(row.unchanged || 0).toLocaleString()}</td></tr>`,
  emptyMessage: 'No weekly movement history is available',
  matches: (row, query) => String(row.week || '').toLowerCase().includes(query),
});

function render() {
  filteredRecords = matchingRecords();
  renderKpis(filteredRecords);
  renderCharts(filteredRecords);
  renderAvs(filteredRecords);
  matrixTable.update(computeMatrixRows(filteredRecords));
  criticalTable.update(computeCriticalRows(filteredRecords));
  const mostRisky = computeMostRiskyRows(filteredRecords);
  mostRiskyTable.update(mostRisky);
  renderMostRiskyCharts(mostRisky);
  renderWeeklyMovement();
  renderMostRiskyDebug(filteredRecords);
  rankList('cveList', filteredRecords, 'CVE');
  rankList('qidList', filteredRecords, 'QID');
  const pci = filteredRecords.filter(r => r['PCI Required']);
  $('pciMetric').innerHTML = `<div><div class="compliance-number">${pci.length}</div><div class="compliance-label">required findings <span class="footer-separator">•</span> ${pci.filter(r => r.SLABreach).length} breached</div></div>`;
  registerTable.update(filteredRecords);
}

function exportMostRisky(records, format) {
  const columns = Object.keys(data.records?.[0] || {});
  const csv = [columns.map(csvCell).join(','), ...records.map(record => columns.map(column => csvCell(record[column])).join(','))].join('\r\n');
  const dateStamp = new Date().toISOString().slice(0, 10);
  if (format === 'excel') {
    const cell = value => String(value ?? '').replaceAll('\t', ' ').replaceAll('\r', ' ').replaceAll('\n', ' ');
    const tsv = [columns.join('\t'), ...records.map(record => columns.map(column => cell(record[column])).join('\t'))].join('\r\n');
    downloadBlob(`\ufeff${tsv}`, 'application/vnd.ms-excel;charset=utf-8;', `most_risky_vulnerabilities_${dateStamp}.xls`);
  } else {
    exportFilteredRecordsCsv(csv, `most_risky_vulnerabilities_${dateStamp}.csv`);
  }
}

async function exportFilteredRecordsCsv(csv, filename) {
  try {
    const response = await fetch('/api/export/filtered', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ csv, filename }) });
    await downloadFromResponse(response, filename);
  } catch (error) {
    downloadBlob(csv, 'text/csv;charset=utf-8;', filename);
  }
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
$('exportMostRiskyCsv').addEventListener('click', () => exportMostRisky(computeMostRiskyRows(filteredRecords), 'csv'));
$('exportMostRiskyExcel').addEventListener('click', () => exportMostRisky(computeMostRiskyRows(filteredRecords), 'excel'));
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
  resizeTimer = setTimeout(redrawCharts, 120);
});

// Canvases inside hidden tabs measure 0x0, so redraw charts from the
// already-filtered in-memory records whenever a tab becomes visible.
function redrawCharts() {
  renderCharts(filteredRecords);
  renderAvs(filteredRecords);
  renderMostRiskyCharts(computeMostRiskyRows(filteredRecords));
  renderWeeklyMovement();
}
initDashboardTabs({ onChange: () => requestAnimationFrame(redrawCharts) });

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
    trendHistory: data.trend_history || [],
  }),
});
