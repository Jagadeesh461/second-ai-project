// Most Risky Vulnerability movement, read from trend_history.json entries
// (mostRiskyNew / mostRiskyResolved / mostRiskyUnchanged + mostRiskyBreakdown)
// that are calculated once during Import Report. Nothing here compares reports;
// dashboard filters are applied to each week's stored breakdown instead.

const MOST_RISKY_MOVEMENT_SERIES = [
  { key: 'new', status: 'New', field: 'mostRiskyNew', label: 'New', color: '#d43a2c' },
  { key: 'resolved', status: 'Resolved', field: 'mostRiskyResolved', label: 'Resolved', color: '#2f9d6c' },
  { key: 'unchanged', status: 'Unchanged', field: 'mostRiskyUnchanged', label: 'Unchanged', color: '#de8324' },
];

function mostRiskyDimensionFilters(filters) {
  return Object.entries(filters || {}).filter(([key, values]) => key !== 'new_resolved_status' && values && values.length);
}

// One week's counts for the given dashboard filter object ({key: [values]}).
// `available` is false when the week predates this feature or its stored
// breakdown cannot represent the active filters.
function mostRiskyMovementWeek(entry, filters) {
  const row = { week: entry.week, new: 0, resolved: 0, unchanged: 0, available: true };
  const dimensions = mostRiskyDimensionFilters(filters);
  const breakdown = entry.mostRiskyBreakdown;
  if (!dimensions.length) {
    if (entry.mostRiskyNew === undefined) row.available = false;
    MOST_RISKY_MOVEMENT_SERIES.forEach(item => { row[item.key] = Number(entry[item.field]) || 0; });
  } else if (breakdown && Array.isArray(breakdown.fields) && dimensions.every(([key]) => breakdown.fields.includes(key))) {
    const indexes = dimensions.map(([key, values]) => [breakdown.fields.indexOf(key), values]);
    const offset = breakdown.fields.length;
    // Rows store indexes into `values`; older/raw rows may hold the strings directly.
    const lookup = Array.isArray(breakdown.values) ? breakdown.values : null;
    const decode = cell => String(lookup ? lookup[cell] : cell);
    (breakdown.rows || []).forEach(values => {
      if (!indexes.every(([index, selected]) => selected.includes(decode(values[index])))) return;
      MOST_RISKY_MOVEMENT_SERIES.forEach((item, position) => { row[item.key] += Number(values[offset + position]) || 0; });
    });
  } else {
    row.available = false;
  }
  // New / Resolved / Unchanged are always reported together; a status
  // selection only changes which series is highlighted, never the counts.
  return row;
}

function mostRiskyMovementHistory(history, filters) {
  return (history || []).map(entry => mostRiskyMovementWeek(entry, filters));
}

// All three series stay on the chart; a selected status is emphasised and
// the others are muted.
function mostRiskyMovementChartSeries(selectedStatus) {
  return MOST_RISKY_MOVEMENT_SERIES.map(item => {
    if (!selectedStatus) return { ...item, alpha: 1, lineWidth: 3 };
    const active = item.status === selectedStatus;
    return { ...item, active, alpha: active ? 1 : 0.25, lineWidth: active ? 4 : 2 };
  });
}

// Direction of the Most Risky population: compares the open Most Risky
// population (new + unchanged) with the previous available week, falling back
// to the latest week's net movement (new - resolved).
function mostRiskyMovementDirection(rows) {
  const available = (rows || []).filter(row => row.available);
  const latest = available[available.length - 1];
  if (!latest) return { direction: 'unknown', change: 0, net: 0 };
  const previous = available.length > 1 ? available[available.length - 2] : null;
  const net = latest.new - latest.resolved;
  const change = previous ? (latest.new + latest.unchanged) - (previous.new + previous.unchanged) : net;
  const direction = change > 0 ? 'increasing' : change < 0 ? 'decreasing' : 'stable';
  return { direction, change, net, latest, previous };
}
