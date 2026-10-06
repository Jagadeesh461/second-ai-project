// AVS (Application Vulnerability Score) calculation core.
// The scoring rules mirror avs_calculator.py exactly so every browser-side
// consumer (AVS dashboard section, AI assistant) computes identical numbers
// from the currently filtered records. Source of truth for the constants
// below is avs_calculator.py. This file contains no DOM access.
const AVS_ZONE_RATINGS = { 'External': 5, 'Internal': 1, 'Internal & Protected': 0.2 };
const AVS_ASSET_RATINGS = { 'Essential': 2, 'Fundamental': 2, 'Other': 1 };
const AVS_BLANK_VALUES = new Set(['', 'N/A', 'Unknown']);
const AVS_AGE_THRESHOLD_DAYS = 45;

function avsClassify(score) {
  if (score < 500) return 'Low';
  if (score <= 1000) return 'Medium';
  return 'High';
}

// Shared AVS inclusion rule: Severity 4/5 (normalized to "Critical") and
// older than the age threshold. Used by both the AVS score and the drill-down.
function avsQualifies(r) {
  return r.Severity === 'Critical' && Number(r['Vulnerability Age']) > AVS_AGE_THRESHOLD_DAYS;
}

// Shared AVS uniqueness key: CVE, falling back to Vendor when CVE is blank.
// Returns '' when neither is usable (such rows are not counted).
function avsDedupKey(r) {
  const cve = (r.CVE || '').trim();
  const key = AVS_BLANK_VALUES.has(cve) ? (r.Vendor || '').trim() : cve;
  return AVS_BLANK_VALUES.has(key) ? '' : key;
}

function computeAvsMetrics(records) {
  const byApp = {};
  records.forEach(r => {
    const appId = r.AppSpaceId || 'Unknown';
    if (!byApp[appId]) {
      byApp[appId] = {
        name: r.AppSpaceName || 'Unknown',
        team: r.AppSpaceTeam || 'Unknown',
        assetType: r['AVS Asset Type'] || 'Other',
        zone: r['AVS Zone'] || 'Internal',
        keys: new Set(),
      };
    }
    if (!avsQualifies(r)) return;
    const dedupKey = avsDedupKey(r);
    if (!dedupKey) return;
    byApp[appId].keys.add(dedupKey);
  });
  return Object.entries(byApp).map(([appId, info]) => {
    const uniqueCount = info.keys.size;
    const zoneRating = AVS_ZONE_RATINGS[info.zone] ?? AVS_ZONE_RATINGS.Internal;
    const assetRating = AVS_ASSET_RATINGS[info.assetType] ?? AVS_ASSET_RATINGS.Other;
    const score = uniqueCount * zoneRating * assetRating;
    return { appId, name: info.name, team: info.team, assetType: info.assetType, zone: info.zone, uniqueCount, score, level: avsClassify(score) };
  });
}

// ---------------------------------------------------------------------------
// Application drill-down (AVS List row -> category pie -> detail table).
// Uses exactly the same avsQualifies/avsDedupKey rules as computeAvsMetrics,
// so a drill-down total always equals that app's "Unique Vulnerabilities".
// ---------------------------------------------------------------------------
const AVS_DRILLDOWN_CATEGORIES = ['CoreOS', 'Java', 'Agents', 'ThirdParty', 'Others'];

// Maps the source Category column (exposed as "Type Category") to one of the
// five drill-down buckets; anything unrecognised falls into "Others".
function avsCategory(value) {
  const key = String(value || '').toLowerCase().replace(/[^a-z]/g, '');
  if (key === 'coreos') return 'CoreOS';
  if (key === 'java') return 'Java';
  if (key === 'agent' || key === 'agents') return 'Agents';
  if (key === 'thirdparty' || key === 'thirdpartycomponent') return 'ThirdParty';
  return 'Others';
}

// Raw source severity ("4"/"5") kept alongside the normalized "Critical".
function avsSeverityLevel(r) {
  const raw = String(r['Severity Level'] == null ? '' : r['Severity Level']).trim().toLowerCase().replace(/^sev(erity)?\s*/, '');
  return raw === '4' || raw === '5' ? raw : '';
}

// Largest-remainder rounding to one decimal so displayed percentages always
// sum to exactly 100.0 whenever there is at least one vulnerability.
function avsPercentages(counts) {
  const total = counts.reduce((a, b) => a + b, 0);
  if (!total) return counts.map(() => 0);
  const scaled = counts.map(c => c * 1000 / total);
  const floors = scaled.map(Math.floor);
  let remaining = 1000 - floors.reduce((a, b) => a + b, 0);
  scaled
    .map((value, index) => ({ index, remainder: value - floors[index] }))
    .sort((a, b) => b.remainder - a.remainder || a.index - b.index)
    .forEach(item => { if (remaining > 0) { floors[item.index] += 1; remaining -= 1; } });
  return floors.map(f => f / 10);
}

// Each unique vulnerability is reported once, at its highest source severity
// (Sev5 wins over Sev4), so unique Sev4 + Sev5 counts always equal the total.
function avsUniqueSeverity(hasSev4, hasSev5) {
  if (hasSev5) return 'Sev5';
  if (hasSev4) return 'Sev4';
  return 'Critical';
}

function computeAvsDrilldown(records, appId) {
  const groups = new Map();
  let appName = null;
  records.forEach(r => {
    if ((r.AppSpaceId || 'Unknown') !== appId) return;
    if (appName === null) appName = r.AppSpaceName || 'Unknown';
    if (!avsQualifies(r)) return;
    const key = avsDedupKey(r);
    if (!key) return;
    let group = groups.get(key);
    if (!group) {
      group = { key, cve: '', names: new Map(), categories: new Map(), hasSev4: false, hasSev5: false, firstDetected: null, age: 0, solution: '' };
      groups.set(key, group);
    }
    const cve = (r.CVE || '').trim();
    if (!group.cve && !AVS_BLANK_VALUES.has(cve)) group.cve = cve;
    const name = r['Vulnerability Name'] || 'Unknown';
    group.names.set(name, (group.names.get(name) || 0) + 1);
    const category = avsCategory(r['Type Category']);
    group.categories.set(category, (group.categories.get(category) || 0) + 1);
    const level = avsSeverityLevel(r);
    if (level === '4') group.hasSev4 = true;
    if (level === '5') group.hasSev5 = true;
    const first = r['First Detected'];
    if (first && (!group.firstDetected || first < group.firstDetected)) group.firstDetected = first;
    group.age = Math.max(group.age, Number(r['Vulnerability Age']) || 0);
    if (!group.solution && r.Solution) group.solution = String(r.Solution).trim();
  });

  const mostFrequent = (map, order) => {
    let best = null;
    let bestCount = -1;
    map.forEach((count, label) => {
      const better = count > bestCount || (count === bestCount && order && order.indexOf(label) < order.indexOf(best));
      if (better) { best = label; bestCount = count; }
    });
    return best;
  };

  // Each unique vulnerability lands in exactly one category (its dominant
  // one) so category counts add up to the app's unique total.
  const vulnerabilities = Array.from(groups.values()).map(g => ({
    key: g.key,
    name: mostFrequent(g.names),
    cve: g.cve || 'N/A',
    category: mostFrequent(g.categories, AVS_DRILLDOWN_CATEGORIES),
    severity: avsUniqueSeverity(g.hasSev4, g.hasSev5),
    firstDetected: g.firstDetected,
    age: g.age,
    solution: g.solution,
  })).sort((a, b) => b.age - a.age || a.key.localeCompare(b.key));

  const counts = AVS_DRILLDOWN_CATEGORIES.map(name => vulnerabilities.filter(v => v.category === name).length);
  const percents = avsPercentages(counts);
  const total = vulnerabilities.length;
  const ageSum = vulnerabilities.reduce((sum, v) => sum + v.age, 0);
  return {
    appId,
    name: appName === null ? 'Unknown' : appName,
    total,
    averageAge: total ? Math.round(ageSum / total) : 0,
    sev4: vulnerabilities.filter(v => v.severity === 'Sev4').length,
    sev5: vulnerabilities.filter(v => v.severity === 'Sev5').length,
    categories: AVS_DRILLDOWN_CATEGORIES.map((name, index) => ({ name, count: counts[index], percent: percents[index] })),
    vulnerabilities,
  };
}

function avsDrilldownCategoryRows(drilldown, category) {
  return drilldown.vulnerabilities.filter(v => v.category === category);
}

// Unique Sev4 / Sev5 counts for a list of drill-down vulnerabilities.
function avsSeverityCounts(vulnerabilities) {
  return {
    sev4: vulnerabilities.filter(v => v.severity === 'Sev4').length,
    sev5: vulnerabilities.filter(v => v.severity === 'Sev5').length,
  };
}
