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
    const qualifies = r.Severity === 'Critical' && Number(r['Vulnerability Age']) > AVS_AGE_THRESHOLD_DAYS;
    if (!qualifies) return;
    const cve = (r.CVE || '').trim();
    const dedupKey = AVS_BLANK_VALUES.has(cve) ? (r.Vendor || '').trim() : cve;
    if (AVS_BLANK_VALUES.has(dedupKey)) return;
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
