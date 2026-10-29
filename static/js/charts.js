const COLORS = {
  Critical: '#d43a2c',
  High: '#de8324',
  Medium: '#e8b23c',
  Low: '#2f9d6c',
  Unknown: '#9aa9aa',
  Open: '#d66060',
  'In Progress': '#d5a735',
  Resolved: '#2f9d6c',
  Closed: '#f2661e',
};

// Deterministic palette for categorical charts whose labels are not known
// ahead of time (e.g. Environment names), so each distinct label gets a
// stable, distinguishable color instead of falling back to a single grey.
const CATEGORY_PALETTE = ['#f2661e', '#0f1b2d', '#5b6b8f', '#2f9d6c', '#e8b23c', '#8b5cf6', '#0ea5e9', '#c2410c', '#9aa9aa', '#d43a2c'];

function paletteColorMap(labels) {
  return Object.fromEntries(labels.map((label, index) => [label, CATEGORY_PALETTE[index % CATEGORY_PALETTE.length]]));
}

function setupCanvas(canvas) {
  const ratio = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(1, rect.width);
  const height = Math.max(1, rect.height);
  canvas.width = Math.floor(width * ratio);
  canvas.height = Math.floor(height * ratio);
  const ctx = canvas.getContext('2d');
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);
  return { ctx, w: width, h: height };
}

function shortNumber(value) {
  return Number(value).toLocaleString(undefined, { maximumFractionDigits: 1 });
}

function ellipsize(ctx, text, maxWidth) {
  const value = String(text || 'Unknown');
  if (ctx.measureText(value).width <= maxWidth) return value;
  let result = value;
  while (result.length > 3 && ctx.measureText(`${result.slice(0, -1)}...`).width > maxWidth) {
    result = result.slice(0, -1);
  }
  return `${result}...`;
}

function donut(canvas, values, colorMap) {
  const { ctx, w, h } = setupCanvas(canvas);
  const total = Object.values(values).reduce((a, b) => a + b, 0) || 1;
  const side = Math.min(w, h);
  const radius = side * .34;
  const lineWidth = Math.max(24, Math.min(38, side * .13));
  const resolveColor = label => (colorMap && colorMap[label]) || COLORS[label] || COLORS.Unknown;
  let start = -Math.PI / 2;

  ctx.lineCap = 'butt';
  Object.entries(values).forEach(([label, value]) => {
    if (!value) return;
    const angle = value / total * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(w / 2, h / 2, radius, start, start + angle);
    ctx.lineWidth = lineWidth;
    ctx.strokeStyle = resolveColor(label);
    ctx.stroke();
    start += angle;
  });

  if (!Object.values(values).some(Boolean)) {
    ctx.beginPath();
    ctx.arc(w / 2, h / 2, radius, 0, Math.PI * 2);
    ctx.lineWidth = lineWidth;
    ctx.strokeStyle = '#e4ecec';
    ctx.stroke();
  }
}

function groupedBars(canvas, groups, series, colors, max, values) {
  const { ctx, w, h } = setupCanvas(canvas);
  const left = 44;
  const right = 12;
  const top = 12;
  const bottom = 30;
  const chartW = Math.max(1, w - left - right);
  const chartH = Math.max(1, h - top - bottom);
  const groupW = chartW / Math.max(groups.length, 1);
  const band = groupW / (series.length + 1);
  const limit = max || 1;

  ctx.strokeStyle = '#dce4e5';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(left, top);
  ctx.lineTo(left, h - bottom);
  ctx.lineTo(w - right, h - bottom);
  ctx.stroke();

  ctx.font = '700 10px Manrope, Segoe UI, Arial';
  groups.forEach((group, i) => {
    const x = left + i * groupW + band * .45;
    ctx.fillStyle = '#71808a';
    ctx.textAlign = 'center';
    ctx.fillText(group, x + band * (series.length / 2), h - 9);

    series.forEach((key, j) => {
      const val = values[key]?.[group] || 0;
      const barH = val / limit * chartH;
      const barW = Math.max(6, band * .58);
      ctx.fillStyle = colors[j];
      ctx.fillRect(x + j * band, h - bottom - barH, barW, barH);
    });
  });
}

function horizontalBars(canvas, entries, color) {
  const { ctx, w, h } = setupCanvas(canvas);
  const rows = Math.max(entries.length, 1);
  const left = Math.min(Math.max(96, w * .28), 165);
  const right = 48;
  const top = 8;
  const bottom = 10;
  const rowH = Math.max(22, (h - top - bottom) / rows);
  const barH = Math.min(14, Math.max(9, rowH * .42));
  const max = Math.max(...entries.map(x => Number(x.total) || 0), 1);
  const chartW = Math.max(1, w - left - right);

  ctx.font = '700 10px Manrope, Segoe UI, Arial';
  if (!entries.length) {
    ctx.fillStyle = '#71808a';
    ctx.textAlign = 'center';
    ctx.fillText('No data', w / 2, h / 2);
    return;
  }

  entries.forEach((entry, i) => {
    const y = top + i * rowH + (rowH - barH) / 2;
    const value = Number(entry.total) || 0;
    const fillW = value / max * chartW;

    ctx.fillStyle = '#52656b';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.fillText(ellipsize(ctx, entry.name, left - 14), left - 8, y + barH / 2);

    ctx.fillStyle = '#eaf0ee';
    ctx.fillRect(left, y, chartW, barH);
    ctx.fillStyle = color;
    ctx.fillRect(left, y, fillW, barH);

    ctx.fillStyle = '#52656b';
    ctx.textAlign = 'left';
    const labelX = Math.min(left + fillW + 6, w - right + 6);
    ctx.fillText(shortNumber(value), labelX, y + barH / 2);
  });
}

// Filled pie chart. Returns slice geometry (in CSS pixels) so callers can map
// a click position back to a slice with pieSliceAt().
function pie(canvas, entries, colorMap, selected) {
  const { ctx, w, h } = setupCanvas(canvas);
  const total = entries.reduce((sum, e) => sum + (Number(e.value) || 0), 0);
  const cx = w / 2;
  const cy = h / 2;
  const radius = Math.max(10, Math.min(w, h) / 2 - 12);
  const geometry = { cx, cy, radius, slices: [] };

  if (!total) {
    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, Math.PI * 2);
    ctx.fillStyle = '#e4ecec';
    ctx.fill();
    ctx.fillStyle = '#71808a';
    ctx.font = '700 11px Manrope, Segoe UI, Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('No data', cx, cy);
    return geometry;
  }

  let start = -Math.PI / 2;
  entries.forEach(entry => {
    const value = Number(entry.value) || 0;
    if (!value) return;
    const angle = value / total * Math.PI * 2;
    const end = start + angle;
    const isSelected = selected === entry.label;
    const dimmed = selected && !isSelected;
    const mid = start + angle / 2;
    const offset = isSelected && angle < Math.PI * 2 ? 8 : 0;
    const ox = cx + Math.cos(mid) * offset;
    const oy = cy + Math.sin(mid) * offset;
    ctx.beginPath();
    ctx.moveTo(ox, oy);
    ctx.arc(ox, oy, radius - 8, start, end);
    ctx.closePath();
    ctx.globalAlpha = dimmed ? 0.45 : 1;
    ctx.fillStyle = (colorMap && colorMap[entry.label]) || COLORS[entry.label] || COLORS.Unknown;
    ctx.fill();
    ctx.globalAlpha = 1;
    ctx.lineWidth = 2;
    ctx.strokeStyle = '#ffffff';
    ctx.stroke();
    if (angle > 0.3) {
      ctx.fillStyle = '#ffffff';
      ctx.font = '800 11px Manrope, Segoe UI, Arial';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const labelR = (radius - 8) * 0.62;
      ctx.fillText(entry.text || shortNumber(value), ox + Math.cos(mid) * labelR, oy + Math.sin(mid) * labelR);
    }
    geometry.slices.push({ label: entry.label, start, end });
    start = end;
  });
  return geometry;
}

function pieSliceAt(geometry, x, y) {
  if (!geometry) return null;
  const dx = x - geometry.cx;
  const dy = y - geometry.cy;
  if (Math.sqrt(dx * dx + dy * dy) > geometry.radius) return null;
  let angle = Math.atan2(dy, dx);
  if (angle < -Math.PI / 2) angle += Math.PI * 2;
  const slice = geometry.slices.find(s => angle >= s.start && angle < s.end);
  return slice ? slice.label : null;
}

function lineChart(canvas, rows, series, tooltip) {
  const { ctx, w, h } = setupCanvas(canvas);
  const left = 58;
  const right = 24;
  const top = 20;
  const bottom = 48;
  const chartW = Math.max(1, w - left - right);
  const chartH = Math.max(1, h - top - bottom);
  const maximum = Math.max(1, ...rows.flatMap(row => series.map(item => Number(row[item.key]) || 0)));
  const xFor = index => left + (rows.length <= 1 ? chartW / 2 : index * chartW / (rows.length - 1));
  const yFor = value => top + chartH - (Number(value) || 0) / maximum * chartH;

  ctx.strokeStyle = '#dce4e5';
  ctx.fillStyle = '#71808a';
  ctx.font = '700 10px Manrope, Segoe UI, Arial';
  ctx.textAlign = 'right';
  for (let step = 0; step <= 4; step++) {
    const value = maximum * step / 4;
    const y = yFor(value);
    ctx.beginPath();
    ctx.moveTo(left, y);
    ctx.lineTo(w - right, y);
    ctx.stroke();
    ctx.fillText(shortNumber(value), left - 8, y + 3);
  }
  rows.forEach((row, index) => {
    ctx.fillStyle = '#71808a';
    ctx.textAlign = 'center';
    ctx.fillText(row.week, xFor(index), h - 18);
  });
  series.forEach(item => {
    ctx.strokeStyle = item.color;
    ctx.fillStyle = item.color;
    ctx.lineWidth = 3;
    ctx.beginPath();
    rows.forEach((row, index) => {
      const x = xFor(index);
      const y = yFor(row[item.key]);
      if (!index) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
    rows.forEach((row, index) => {
      ctx.beginPath();
      ctx.arc(xFor(index), yFor(row[item.key]), 4, 0, Math.PI * 2);
      ctx.fill();
    });
  });
  const points = rows.map((row, index) => ({ x: xFor(index), row }));
  canvas.onmousemove = event => {
    if (!rows.length || !tooltip) return;
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const point = points.reduce((best, candidate) => Math.abs(candidate.x - x) < Math.abs(best.x - x) ? candidate : best, points[0]);
    tooltip.innerHTML = `<strong>Week: ${escapeHtml(point.row.week)}</strong><span>New: ${shortNumber(point.row.new)}</span><span>Resolved: ${shortNumber(point.row.resolved)}</span><span>Unchanged: ${shortNumber(point.row.unchanged)}</span>`;
    tooltip.style.left = `${Math.min(rect.width - 150, Math.max(8, point.x + 10))}px`;
    tooltip.style.top = `${Math.max(8, event.clientY - rect.top - 75)}px`;
    tooltip.hidden = false;
  };
  canvas.onmouseleave = () => { if (tooltip) tooltip.hidden = true; };
}
