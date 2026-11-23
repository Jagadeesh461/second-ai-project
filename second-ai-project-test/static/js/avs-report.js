// AVS PDF report generation.
//
// This file contains no AVS scoring logic of its own. It only reads the
// data the dashboard already prepared:
//   - avsLastApps / avsLastRecords (set by renderAvs() in avs.js) for the
//     report summary and the per-application pages,
//   - computeAvsDrilldown() / avsExportRecordsForCategory() (avs-core.js)
//     for each application's page - the exact same functions that power the
//     on-page AVS drill-down, and
//   - the already-rendered chart <canvas> elements, captured as images, so
//     the PDF always matches what is on screen for the current filters.
//
// Each application page's "Export CSV" links reuse the dashboard's existing
// CSV export plumbing (buildFilteredCsv() + the /api/export/filtered
// endpoint, see dashboard.js), so no new export logic is introduced here -
// the PDF only persists one CSV per category/app and links to it.
//
// PDF assembly uses the vendored jsPDF UMD build (static/js/vendor).

const AVS_REPORT_MARGIN = { top: 16, bottom: 16, left: 14, right: 14 };
const AVS_REPORT_COLORS = { ink: '#182236', muted: '#667180', brand: '#f2661e', low: '#2f9d6c', medium: '#e8b23c', high: '#d43a2c' };

function avsReportFilename() {
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}`;
  return `AVS_Report_${stamp}.pdf`;
}

// "Group = Suncorp Bank" style lines for whichever dashboard filters are
// currently active (see filters.js#activeFilterSummary). No longer rendered
// on the report itself (replaced by the "AVS Report Summary" scope table
// below), but kept as a small reusable helper covered by its own tests.
function avsReportFormatFilterLine(item) {
  return `${item.label} = ${item.values.join(', ')}`;
}

function avsReportFilterLines() {
  const summary = (typeof activeFilterSummary === 'function') ? activeFilterSummary() : [];
  if (!summary.length) return ['No filters applied (showing all applications in current scope)'];
  return summary.map(avsReportFormatFilterLine);
}

function avsReportHexToRgb(hex) {
  const num = parseInt(String(hex).replace('#', ''), 16);
  return [(num >> 16) & 255, (num >> 8) & 255, num & 255];
}

// "Owner Name / Environment / Group / Type" scope line for the "AVS Report
// Summary" table - the currently selected dashboard filter values, each
// defaulting to "All" when nothing is selected. Type has no dedicated
// dashboard filter yet, so it always reports "All".
function avsReportScopeValues() {
  const filters = (typeof getFilters === 'function') ? getFilters() : {};
  const valueOrAll = key => {
    const values = filters[key];
    return (values && values.length) ? values.join(', ') : 'All';
  };
  return {
    owner: valueOrAll('app_space_owner'),
    environment: valueOrAll('environment'),
    group: valueOrAll('group'),
    type: 'All',
  };
}

// Draws one rounded KPI card with a brand-colored accent bar, mirroring the
// dashboard's .kpi cards (white body, colored top border, muted label).
function avsReportKpiCard(doc, x, y, w, h, label, value, accentHex) {
  const [ar, ag, ab] = avsReportHexToRgb(accentHex);
  doc.setDrawColor(228, 236, 236);
  doc.setFillColor(255, 255, 255);
  doc.roundedRect(x, y, w, h, 1.8, 1.8, 'FD');
  doc.setFillColor(ar, ag, ab);
  doc.rect(x, y, w, 1.6, 'F');
  const [mr, mg, mb] = avsReportHexToRgb(AVS_REPORT_COLORS.muted);
  doc.setTextColor(mr, mg, mb);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.2);
  doc.text(String(label).toUpperCase(), x + 4, y + 8, { maxWidth: w - 8 });
  const [ir, ig, ib] = avsReportHexToRgb(AVS_REPORT_COLORS.ink);
  doc.setTextColor(ir, ig, ib);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15.5);
  doc.text(String(value), x + 4, y + h - 6);
}

function avsReportSectionTitle(doc, x, y, text) {
  const [ir, ig, ib] = avsReportHexToRgb(AVS_REPORT_COLORS.ink);
  doc.setTextColor(ir, ig, ib);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11.5);
  doc.text(text, x, y);
  const [br, bg, bb] = avsReportHexToRgb(AVS_REPORT_COLORS.brand);
  doc.setDrawColor(br, bg, bb);
  doc.setLineWidth(0.6);
  doc.line(x, y + 1.8, x + 20, y + 1.8);
}

// Starts a new page if `needed` mm of vertical space is not available below
// `y`, so a section header is never stranded at the bottom of a page.
function avsReportEnsureSpace(doc, y, needed, margin) {
  const pageHeight = doc.internal.pageSize.getHeight();
  if (y + needed <= pageHeight - margin.bottom) return y;
  doc.addPage();
  return margin.top;
}

// Captures an already-rendered chart canvas as a PNG, scaled to fit within
// maxW x maxH while preserving its aspect ratio. Returns the drawn height
// (0 if the canvas is missing/empty), so callers can advance their cursor.
function avsReportAddCanvasImage(doc, canvas, x, y, maxW, maxH) {
  if (!canvas || !canvas.width || !canvas.height) return 0;
  const ratio = canvas.width / canvas.height;
  let w = maxW;
  let h = w / ratio;
  if (h > maxH) { h = maxH; w = h * ratio; }
  let dataUrl;
  try { dataUrl = canvas.toDataURL('image/png'); } catch (error) { return 0; }
  doc.addImage(dataUrl, 'PNG', x + (maxW - w) / 2, y, w, h);
  return h;
}

// Renders an off-screen donut of the Low/Medium/High application mix for the
// "AVS Distribution" section, independent of the on-page canvas so it can be
// sized specifically for the PDF (bigger ring, report-only color pass).
function avsReportDistributionDonutImage(values) {
  const canvas = document.createElement('canvas');
  canvas.width = 520;
  canvas.height = 520;
  canvas.style.position = 'fixed';
  canvas.style.left = '-9999px';
  canvas.style.top = '0';
  canvas.style.width = '260px';
  canvas.style.height = '260px';
  document.body.appendChild(canvas);
  try {
    const colors = { Low: AVS_REPORT_COLORS.low, Medium: AVS_REPORT_COLORS.medium, High: AVS_REPORT_COLORS.high };
    donut(canvas, values, colors);
    return canvas.toDataURL('image/png');
  } catch (error) {
    return null;
  } finally {
    canvas.remove();
  }
}

// Renders an off-screen copy of an application's category pie so each
// application's PDF page gets its own chart, independent of whichever
// application (if any) is currently expanded in the on-page drill-down.
// Uses the same pie() renderer and AVS_CATEGORY_COLORS as the dashboard.
function avsReportCategoryPieImage(drilldown) {
  const canvas = document.createElement('canvas');
  canvas.width = 480;
  canvas.height = 480;
  canvas.style.position = 'fixed';
  canvas.style.left = '-9999px';
  canvas.style.top = '0';
  canvas.style.width = '240px';
  canvas.style.height = '240px';
  document.body.appendChild(canvas);
  try {
    const entries = drilldown.categories.map(c => ({ label: c.name, value: c.count, text: `${Math.round(c.percent)}%` }));
    pie(canvas, entries, AVS_CATEGORY_COLORS, null);
    return canvas.toDataURL('image/png');
  } catch (error) {
    return null;
  } finally {
    canvas.remove();
  }
}

// Generic paginated table: draws a header row, wraps cell text to each
// column's width, and starts a new page (repeating the header) whenever the
// next row would not fit above the bottom margin. Returns the final y.
function avsReportDrawTable(doc, { startX, startY, columns, rows, margin, headerFill = AVS_REPORT_COLORS.brand }) {
  const pageHeight = doc.internal.pageSize.getHeight();
  const bottomLimit = pageHeight - margin.bottom;
  const tableWidth = columns.reduce((sum, col) => sum + col.width, 0);
  const [hr, hg, hb] = avsReportHexToRgb(headerFill);
  let y = startY;

  function drawHeaderRow() {
    doc.setFillColor(hr, hg, hb);
    doc.rect(startX, y, tableWidth, 7, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    let cx = startX;
    columns.forEach(col => {
      doc.text(col.label, cx + 2, y + 4.8, { maxWidth: col.width - 4 });
      cx += col.width;
    });
    y += 7;
  }

  drawHeaderRow();
  const [ir, ig, ib] = avsReportHexToRgb(AVS_REPORT_COLORS.ink);

  rows.forEach((row, index) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    const cellLines = columns.map(col => doc.splitTextToSize(String(row[col.key] ?? ''), col.width - 4));
    const lineCount = Math.max(1, ...cellLines.map(lines => lines.length));
    const rowHeight = Math.max(6, lineCount * 3.3 + 2.4);

    if (y + rowHeight > bottomLimit) {
      doc.addPage();
      y = margin.top;
      drawHeaderRow();
    }

    if (index % 2 === 1) {
      doc.setFillColor(246, 248, 248);
      doc.rect(startX, y, tableWidth, rowHeight, 'F');
    }
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(ir, ig, ib);
    let cx = startX;
    columns.forEach((col, colIndex) => {
      doc.text(cellLines[colIndex], cx + 2, y + 4.2);
      cx += col.width;
    });
    y += rowHeight;
  });

  return y;
}

// Full-width "AVS Report Summary" scope table: Owner Name / Environment on
// the first row, Group / Type on the second, matching whichever dashboard
// filters are currently active (each defaulting to "All").
function avsReportDrawScopeTable(doc, margin, contentWidth, y) {
  const scope = avsReportScopeValues();
  const rowH = 9.5;
  const colW = contentWidth / 2;
  const rows = [
    [['Owner Name', scope.owner], ['Environment', scope.environment]],
    [['Group', scope.group], ['Type', scope.type]],
  ];

  const [dr, dg, db] = avsReportHexToRgb('#e4ecec');
  const [fr, fg, fb] = avsReportHexToRgb('#f7f9f9');
  doc.setDrawColor(dr, dg, db);
  doc.setFillColor(fr, fg, fb);
  doc.roundedRect(margin.left, y, contentWidth, rowH * 2, 1.6, 1.6, 'FD');
  doc.line(margin.left, y + rowH, margin.left + contentWidth, y + rowH);
  doc.line(margin.left + colW, y, margin.left + colW, y + rowH * 2);

  const [ir, ig, ib] = avsReportHexToRgb(AVS_REPORT_COLORS.ink);
  rows.forEach((row, rowIndex) => {
    row.forEach(([label, value], colIndex) => {
      const cx = margin.left + colIndex * colW + 5;
      const cy = y + rowIndex * rowH + rowH / 2 + 1.6;
      doc.setTextColor(ir, ig, ib);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.6);
      const labelText = `${label} : `;
      doc.text(labelText, cx, cy);
      doc.setFont('helvetica', 'normal');
      doc.text(String(value), cx + doc.getTextWidth(labelText), cy);
    });
  });

  return y + rowH * 2;
}

// "AVS Distribution" section: an enlarged donut on the left with the total
// application count centered in the hole, and a legend on the right showing
// each level's count + percentage plus a one-line executive summary -
// filling the horizontal space the old bare chart left empty.
function avsReportDrawDistributionSection(doc, apps, margin, contentWidth, y) {
  const total = apps.length;
  const low = apps.filter(a => a.level === 'Low').length;
  const medium = apps.filter(a => a.level === 'Medium').length;
  const high = apps.filter(a => a.level === 'High').length;
  const pct = count => (total ? Math.round((count / total) * 100) : 0);

  const donutSize = 56;
  const image = avsReportDistributionDonutImage({ Low: low, Medium: medium, High: high });
  if (image) doc.addImage(image, 'PNG', margin.left, y, donutSize, donutSize);

  const [ir, ig, ib] = avsReportHexToRgb(AVS_REPORT_COLORS.ink);
  const [mr, mg, mb] = avsReportHexToRgb(AVS_REPORT_COLORS.muted);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15);
  doc.setTextColor(ir, ig, ib);
  doc.text(String(total.toLocaleString()), margin.left + donutSize / 2, y + donutSize / 2 + 1, { align: 'center' });
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.6);
  doc.setTextColor(mr, mg, mb);
  doc.text('Applications', margin.left + donutSize / 2, y + donutSize / 2 + 5.4, { align: 'center' });

  const legendX = margin.left + donutSize + 10;
  const legendW = contentWidth - donutSize - 10;
  let ly = y + 2;
  [
    ['Low AVS', low, AVS_REPORT_COLORS.low],
    ['Medium AVS', medium, AVS_REPORT_COLORS.medium],
    ['High AVS', high, AVS_REPORT_COLORS.high],
  ].forEach(([label, count, color]) => {
    const [cr, cg, cb] = avsReportHexToRgb(color);
    doc.setFillColor(cr, cg, cb);
    doc.roundedRect(legendX, ly - 3, 4, 4, 1, 1, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(ir, ig, ib);
    doc.text(label, legendX + 7, ly);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.4);
    doc.setTextColor(mr, mg, mb);
    doc.text(`${count.toLocaleString()} Applications (${pct(count)}%)`, legendX + 7, ly + 4.6);
    ly += 13;
  });

  const summary = total
    ? `${pct(low)}% of applications are currently classified as Low AVS.${high ? ` ${pct(high)}% of applications are High AVS and require priority attention.` : ' No High AVS applications are present in the selected scope.'}`
    : 'No application data is available in the selected scope.';
  doc.setFont('helvetica', 'italic');
  doc.setFontSize(8.2);
  doc.setTextColor(mr, mg, mb);
  const wrapped = doc.splitTextToSize(summary, legendW);
  doc.text(wrapped, legendX, ly + 1);
  ly += wrapped.length * 4 + 2;

  return Math.max(y + donutSize, ly);
}

// "Top Applications by AVS Score": the enlarged horizontal bar chart (now
// using the space freed up by removing the "AVS Score by Team" chart) plus a
// readable Application Name / AVS Score / AVS Level / FundamentalClassification
// / Zone table underneath.
function avsReportDrawTopAppsSection(doc, apps, margin, contentWidth, y) {
  const top = apps.slice(0, 10);
  const chartH = 62;
  const drawnH = avsReportAddCanvasImage(doc, document.getElementById('avsTopAppsChart'), margin.left, y, contentWidth, chartH);
  y += Math.max(drawnH, 40) + 6;

  const columns = [
    { key: 'name', label: 'Application Name', width: contentWidth * 0.34 },
    { key: 'score', label: 'AVS Score', width: contentWidth * 0.14 },
    { key: 'level', label: 'AVS Level', width: contentWidth * 0.14 },
    { key: 'classification', label: 'FundamentalClassification', width: contentWidth * 0.22 },
    { key: 'zone', label: 'Zone', width: contentWidth * 0.16 },
  ];
  const rows = top.map(a => ({ name: a.name, score: a.score.toFixed(1), level: a.level, classification: a.fundamentalClassification || 'Other', zone: a.zone || 'Internal' }));
  return avsReportDrawTable(doc, { startX: margin.left, startY: y, columns, rows, margin });
}

function avsReportBuildSummaryPage(doc, { apps, margin, contentWidth }) {
  const pageWidth = doc.internal.pageSize.getWidth();
  let y = margin.top;

  const [br, bg, bb] = avsReportHexToRgb(AVS_REPORT_COLORS.brand);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(26);
  doc.setTextColor(br, bg, bb);
  doc.text('AVS Report', pageWidth / 2, y + 6, { align: 'center' });
  y += 13;

  const [mr, mg, mb] = avsReportHexToRgb(AVS_REPORT_COLORS.muted);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(mr, mg, mb);
  doc.text(`Generated ${new Date().toLocaleString()}`, pageWidth / 2, y, { align: 'center' });
  y += 11;

  avsReportSectionTitle(doc, margin.left, y, 'AVS Report Summary');
  y += 6;
  y = avsReportDrawScopeTable(doc, margin, contentWidth, y) + 10;

  const cardGap = 5;
  const cardW = (contentWidth - 3 * cardGap) / 4;
  const cardH = 24;
  const low = apps.filter(a => a.level === 'Low').length;
  const medium = apps.filter(a => a.level === 'Medium').length;
  const high = apps.filter(a => a.level === 'High').length;
  [
    ['Total Applications', apps.length, AVS_REPORT_COLORS.brand],
    ['Low AVS', low, AVS_REPORT_COLORS.low],
    ['Medium AVS', medium, AVS_REPORT_COLORS.medium],
    ['High AVS', high, AVS_REPORT_COLORS.high],
  ].forEach((card, index) => {
    avsReportKpiCard(doc, margin.left + index * (cardW + cardGap), y, cardW, cardH, card[0], card[1].toLocaleString(), card[2]);
  });
  y += cardH + 11;

  y = avsReportEnsureSpace(doc, y, 70, margin);
  avsReportSectionTitle(doc, margin.left, y, 'AVS Distribution');
  y += 6;
  y = avsReportDrawDistributionSection(doc, apps, margin, contentWidth, y) + 8;

  y = avsReportEnsureSpace(doc, y, 90, margin);
  avsReportSectionTitle(doc, margin.left, y, 'Top Applications by AVS Score');
  y += 6;
  avsReportDrawTopAppsSection(doc, apps, margin, contentWidth, y);
}

// Category breakdown table for an application page: Category / Vulnerability
// Count / Percentage / Export List, with a Total row, and one "Export CSV"
// link per row (clickable when a download URL was persisted, plain text
// otherwise - see avsReportBuildCategoryExportLinks()).
function avsReportDrawCategoryTable(doc, { startX, startY, tableW, drilldown, exportLinks }) {
  const columns = [tableW * 0.30, tableW * 0.20, tableW * 0.20, tableW * 0.30];
  const headers = ['Category', 'Vulnerability Count', 'Percentage', 'Export List'];
  const rowH = 7.6;
  let y = startY;

  const [hr, hg, hb] = avsReportHexToRgb(AVS_REPORT_COLORS.brand);
  doc.setFillColor(hr, hg, hb);
  doc.rect(startX, y, tableW, rowH, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.8);
  let hx = startX;
  headers.forEach((label, index) => { doc.text(label, hx + 2, y + rowH / 2 + 1.3, { maxWidth: columns[index] - 4 }); hx += columns[index]; });
  y += rowH;

  const rows = drilldown.categories.map(c => ({ name: c.name, count: c.count, percent: `${c.percent.toFixed(1)}%` }));
  rows.push({ name: 'Total', count: drilldown.total, percent: drilldown.total ? '100.0%' : '0.0%', isTotal: true });

  const [ir, ig, ib] = avsReportHexToRgb(AVS_REPORT_COLORS.ink);
  const [mr, mg, mb] = avsReportHexToRgb(AVS_REPORT_COLORS.muted);
  rows.forEach((row, index) => {
    if (row.isTotal) {
      doc.setFillColor(240, 242, 236);
      doc.rect(startX, y, tableW, rowH, 'F');
    } else if (index % 2 === 1) {
      doc.setFillColor(246, 248, 248);
      doc.rect(startX, y, tableW, rowH, 'F');
    }

    doc.setFont('helvetica', row.isTotal ? 'bold' : 'normal');
    doc.setFontSize(8);
    doc.setTextColor(ir, ig, ib);
    let cx = startX;
    doc.text(String(row.name), cx + 2, y + rowH / 2 + 1.3);
    cx += columns[0];
    doc.text(row.count.toLocaleString(), cx + 2, y + rowH / 2 + 1.3);
    cx += columns[1];
    doc.text(row.percent, cx + 2, y + rowH / 2 + 1.3);
    cx += columns[2];

    const link = exportLinks && exportLinks[row.name];
    doc.setFont('helvetica', 'bold');
    if (link) {
      doc.setTextColor(hr, hg, hb);
      doc.textWithLink('Export CSV', cx + 2, y + rowH / 2 + 1.3, { url: link });
    } else {
      doc.setTextColor(mr, mg, mb);
      doc.text('Export CSV', cx + 2, y + rowH / 2 + 1.3);
    }
    y += rowH;
  });

  const [dr, dg, db] = avsReportHexToRgb('#e4ecec');
  doc.setDrawColor(dr, dg, db);
  doc.rect(startX, startY, tableW, y - startY);
  return y;
}

function avsReportBuildApplicationPage(doc, { app, drilldown, exportLinks, margin, contentWidth }) {
  let y = margin.top;
  const [ir, ig, ib] = avsReportHexToRgb(AVS_REPORT_COLORS.ink);
  const [mr, mg, mb] = avsReportHexToRgb(AVS_REPORT_COLORS.muted);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.setTextColor(ir, ig, ib);
  doc.text(`${drilldown.name || app.name} (${app.appId})`, margin.left, y);
  y += 7;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(mr, mg, mb);
  doc.text(`App Owner: ${app.owner || 'Unknown'}`, margin.left, y);
  y += 5;
  doc.text(`FundamentalClassification: ${app.fundamentalClassification || 'Other'}   |   Zone: ${app.zone || 'Internal'}   |   Exploitable Unique Vulns: ${Number(drilldown.exploitable || 0).toLocaleString()}`, margin.left, y);
  y += 7;

  const levelColor = app.level === 'High' ? AVS_REPORT_COLORS.high : app.level === 'Medium' ? AVS_REPORT_COLORS.medium : AVS_REPORT_COLORS.low;
  const [lr, lg, lb] = avsReportHexToRgb(levelColor);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(ir, ig, ib);
  doc.text(`AVS Score: ${app.score.toFixed(1)}`, margin.left, y);
  doc.setTextColor(lr, lg, lb);
  doc.text(`AVS Level: ${app.level}`, margin.left + 60, y);
  y += 8;

  const [dr, dg, db] = avsReportHexToRgb('#e4ecec');
  doc.setDrawColor(dr, dg, db);
  doc.setLineWidth(0.4);
  doc.line(margin.left, y, margin.left + contentWidth, y);
  y += 7;

  const cardGap = 4;
  const cardW = (contentWidth - 3 * cardGap) / 4;
  const cardH = 21;
  [
    ['Total Unique Sev4/5 Vulns', drilldown.total, AVS_REPORT_COLORS.brand],
    ['Average Age (Days)', drilldown.averageAge, AVS_REPORT_COLORS.medium],
    ['Unique Sev4 Count', drilldown.sev4, AVS_REPORT_COLORS.medium],
    ['Unique Sev5 Count', drilldown.sev5, AVS_REPORT_COLORS.high],
  ].forEach((card, index) => {
    avsReportKpiCard(doc, margin.left + index * (cardW + cardGap), y, cardW, cardH, card[0], Number(card[1]).toLocaleString(), card[2]);
  });
  y += cardH + 9;

  avsReportSectionTitle(doc, margin.left, y, 'Category Distribution');
  y += 6;

  const pieSize = 58;
  const pieImage = avsReportCategoryPieImage(drilldown);
  if (pieImage) {
    doc.addImage(pieImage, 'PNG', margin.left, y, pieSize, pieSize);
  } else {
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(8.5);
    doc.setTextColor(mr, mg, mb);
    doc.text('No category data available.', margin.left, y + pieSize / 2);
  }

  const tableX = margin.left + pieSize + 8;
  const tableW = contentWidth - pieSize - 8;
  avsReportDrawCategoryTable(doc, { startX: tableX, startY: y, tableW, drilldown, exportLinks });
  y += pieSize + 9;

  doc.setFont('helvetica', 'italic');
  doc.setFontSize(7.6);
  doc.setTextColor(mr, mg, mb);
  doc.text('Use the Export CSV links above to download the detailed vulnerability list for each category.', margin.left, y);
}

// Turns an app id / category name into a filesystem-safe filename token.
function avsReportSafeFileToken(value) {
  return String(value || 'Unknown').replace(/[^a-z0-9]+/gi, '_').replace(/^_+|_+$/g, '') || 'Unknown';
}

// Persists one CSV export via the existing /api/export/filtered endpoint
// (the same endpoint and CSV shape the dashboard's "Export Filtered Report"
// action already uses - see dashboard.js#exportFilteredReport) and returns an
// absolute, directly downloadable archive URL for it, or null if the export
// could not be persisted (e.g. offline), so the PDF can fall back to plain
// "Export CSV" text per the no-hyperlink-support case.
async function avsReportPersistCsv(csvText, filenameHint) {
  try {
    const response = await fetch('/api/export/filtered', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csv: csvText, filename: filenameHint }),
    });
    if (!response.ok) return null;
    const disposition = response.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="?([^"]+)"?/);
    const filename = match ? match[1] : filenameHint;
    return `${window.location.origin}/api/archive/download/${encodeURIComponent(filename)}`;
  } catch (error) {
    return null;
  }
}

// Builds one persisted CSV export per drill-down category plus a "Total"
// export covering the application's complete AVS vulnerability list, reusing
// avsExportRecordsForCategory() (avs-core.js) and buildFilteredCsv()
// (dashboard.js) so no new export/filtering logic is introduced here.
// Returns a map of category name (including "Total") -> download URL.
async function avsReportBuildCategoryExportLinks(records, app) {
  const categories = [...AVS_DRILLDOWN_CATEGORIES, 'Total'];
  const entries = await Promise.all(categories.map(async category => {
    const rows = avsExportRecordsForCategory(records, app.appId, category);
    const csvText = buildFilteredCsv(rows);
    const filenameHint = `AVS_${avsReportSafeFileToken(app.appId)}_${avsReportSafeFileToken(category)}.csv`;
    const url = await avsReportPersistCsv(csvText, filenameHint);
    return [category, url];
  }));
  return Object.fromEntries(entries);
}

// Builds and downloads the AVS PDF report from the data already computed for
// the dashboard's current filters (avsLastApps/avsLastRecords from avs.js).
async function generateAvsReportPdf() {
  const JsPdfCtor = window.jspdf && window.jspdf.jsPDF;
  if (!JsPdfCtor) throw new Error('jsPDF failed to load');

  const records = (typeof avsLastRecords !== 'undefined' && avsLastRecords.length)
    ? avsLastRecords
    : (typeof filteredRecords !== 'undefined' ? filteredRecords : []);
  const apps = (typeof avsLastApps !== 'undefined' && avsLastApps.length)
    ? avsLastApps
    : computeAvsMetrics(records).sort((a, b) => b.score - a.score);

  const doc = new JsPdfCtor({ unit: 'mm', format: 'a4' });
  const contentWidth = doc.internal.pageSize.getWidth() - AVS_REPORT_MARGIN.left - AVS_REPORT_MARGIN.right;

  avsReportBuildSummaryPage(doc, { apps, margin: AVS_REPORT_MARGIN, contentWidth });

  for (const app of apps) {
    doc.addPage();
    const drilldown = computeAvsDrilldown(records, app.appId);
    const exportLinks = await avsReportBuildCategoryExportLinks(records, app);
    avsReportBuildApplicationPage(doc, { app, drilldown, exportLinks, margin: AVS_REPORT_MARGIN, contentWidth });
  }

  doc.save(avsReportFilename());
}

(function bindAvsReportButton() {
  const button = document.getElementById('generateAvsReport');
  if (!button || !button.addEventListener) return;
  button.addEventListener('click', async () => {
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = 'Generating...';
    try {
      await generateAvsReportPdf();
    } catch (error) {
      console.error('AVS report generation failed', error);
      window.alert('Could not generate the AVS report. Please try again.');
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
  });
})();
