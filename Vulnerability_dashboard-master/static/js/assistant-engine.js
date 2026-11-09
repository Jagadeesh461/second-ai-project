// Rule-based AI assistant logic for the vulnerability dashboard.
// Pure data in / structured answer out: this file never touches the DOM and
// never calls an external service. Answers are derived from the records the
// dashboard has already filtered, so the assistant always reflects the
// currently active filters and search scope.

const ASSISTANT_QUESTIONS = [
  { id: 'summary', label: 'Summarize vulnerability report', keywords: ['summar', 'overview', 'report', 'posture', 'brief', 'total'] },
  { id: 'critical', label: 'Show Critical vulnerabilities', keywords: ['critical'] },
  { id: 'top-appspaces', label: 'Top 10 vulnerable AppSpaces', keywords: ['appspace', 'app space', 'top 10', 'most vulnerable', 'vulnerable app'] },
  { id: 'high-avs', label: 'Applications with High AVS', keywords: ['high avs', 'avs high', 'application avs', 'apps with high', 'risky application'] },
  { id: 'sla-breach', label: 'SLA breach summary', keywords: ['sla', 'breach', 'overdue', 'due date', 'late'] },
  { id: 'remediation', label: 'Top remediation actions', keywords: ['remediat', 'fix', 'patch', 'action', 'priorit', 'next step'] },
  { id: 'avs-explained', label: 'AVS score explanation', keywords: ['avs score', 'explain', 'what is avs', 'how is avs', 'calculat', 'formula', 'meaning'] },
];

const ASSISTANT_SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];
const ASSISTANT_STATUSES = ['Open', 'In Progress', 'Resolved', 'Closed'];
const ASSISTANT_MIN_MATCH_SCORE = 1;

// --- Natural language -> dashboard filter mapping -------------------------
// The chatbot never defines its own filtering rules. It only figures out
// which of the dashboard's own filters (see FILTER_FIELDS/recordMatchesFilters
// in filters.js) a question refers to, then asks that same filter predicate
// to narrow the records. This guarantees the chatbot and the dashboard filter
// controls always agree on the same result set for the same criteria.

// Cue phrases used only to break ties when one literal value happens to
// match more than one filter field's known values (e.g. a person's name that
// is also used as a team name).
const ASSISTANT_FILTER_FIELD_CUES = {
  app_space_owner: ['appspace owner', 'app space owner', 'owned by', 'owner'],
  app_space_team: ['team'],
  app_space_name: ['appspace', 'app space', 'application', 'app'],
  environment: ['environment', 'env'],
  remit_team: ['remit team', 'remit'],
  fundamental_classification: ['fundamental classification', 'classification'],
  zone: ['zone'],
  operating_system: ['operating system', 'os'],
  type_category: ['category'],
  group: ['group'],
};

// Fields whose values are free text and must be recognised from the actual
// dataset rather than a fixed vocabulary.
const ASSISTANT_FREE_TEXT_FIELDS = ['app_space_owner', 'app_space_team', 'app_space_name', 'remit_team', 'operating_system', 'type_category', 'environment', 'group', 'fundamental_classification', 'zone'];

function assistantFieldOptions(records, key) {
  // Reuses the dashboard's own option-listing helper (filters.js) so every
  // value the chatbot recognises is guaranteed to be a real, currently valid
  // filter value - never a value invented by the chatbot itself.
  return typeof optionValues === 'function' ? optionValues(records, key) : [];
}

function assistantFindCue(lowerQuery, cues) {
  return (cues || []).some(cue => lowerQuery.includes(cue));
}

// Recognises free-text filter values (AppSpace, Owner, Team, Remit Team,
// OS, Category, Environment) by checking whether any real value already present
// in the dataset appears verbatim in the question.
function assistantExtractFieldFilters(query, records) {
  const lowerQuery = query.toLowerCase();
  const matchesByField = {};
  ASSISTANT_FREE_TEXT_FIELDS.forEach(key => {
    assistantFieldOptions(records, key).forEach(value => {
      if (value && lowerQuery.includes(String(value).toLowerCase())) {
        (matchesByField[key] = matchesByField[key] || []).push(value);
      }
    });
  });
  const resolved = {};
  Object.entries(matchesByField).forEach(([key, values]) => {
    // Prefer the longest (most specific) matching value for that field.
    resolved[key] = values.sort((a, b) => b.length - a.length)[0];
  });
  // If the same literal value matched several fields, use an explicit cue
  // word from the question (e.g. "owner", "team") to pick the right one.
  const fieldsByValue = {};
  Object.entries(resolved).forEach(([key, value]) => {
    const normalized = value.toLowerCase();
    (fieldsByValue[normalized] = fieldsByValue[normalized] || []).push(key);
  });
  Object.values(fieldsByValue).forEach(keys => {
    if (keys.length <= 1) return;
    const cued = keys.filter(key => assistantFindCue(lowerQuery, ASSISTANT_FILTER_FIELD_CUES[key]));
    const keep = cued.length ? cued : [keys[0]];
    keys.forEach(key => { if (!keep.includes(key)) delete resolved[key]; });
  });
  const filters = {};
  Object.entries(resolved).forEach(([key, value]) => { filters[key] = [value]; });
  return filters;
}

// AVS Level ("High AVS", "AVS above ...") is computed, not a raw record
// field, so it is resolved separately from FILTER_FIELDS and applied to the
// AVS builder instead of recordMatchesFilters.
function assistantExtractAvsLevel(lowerQuery) {
  const match = lowerQuery.match(/\b(high|medium|low)\s+avs\b/) || lowerQuery.match(/\bavs\b[\s\w]{0,12}?\b(high|medium|low)\b/);
  if (!match) return null;
  const level = match[1];
  return level.charAt(0).toUpperCase() + level.slice(1);
}

// Recognises the dashboard's enumerated filters (Severity, Status, PCI
// Required, SLA Breach, Exploit) directly from a fixed vocabulary.
function assistantExtractEnumeratedFilters(query, avsLevel) {
  const lowerQuery = query.toLowerCase();
  const avsMention = avsLevel
    ? new RegExp(`\\b${avsLevel.toLowerCase()}\\s+avs\\b|\\bavs\\b[\\s\\w]{0,12}?\\b${avsLevel.toLowerCase()}\\b`)
    : null;
  const withoutAvsMention = avsMention ? lowerQuery.replace(avsMention, ' ') : lowerQuery;
  const filters = {};
  const movement = withoutAvsMention.match(/\b(new|resolved|unchanged)\b/);
  const movementQuery = /\b(weekly|movement|trend|last week|with status|movement status)\b/.test(withoutAvsMention);
  if (movement && movementQuery) {
    filters.new_resolved_status = [movement[1].charAt(0).toUpperCase() + movement[1].slice(1)];
  }
  const severity = ASSISTANT_SEVERITIES.find(level => new RegExp(`\\b${level.toLowerCase()}\\b`).test(withoutAvsMention));
  if (severity) filters.severity = [severity];
  const status = ASSISTANT_STATUSES.find(value => withoutAvsMention.includes(value.toLowerCase()) && !(movementQuery && value === 'Resolved'));
  if (status) filters.status = [status];
  if (/\bpci\b/.test(lowerQuery) && /\brequired\b|\bneeded\b/.test(lowerQuery)) filters.pci_required = ['Yes'];
  if (/\bexploit(s|able|ed)?\b/.test(lowerQuery)) filters.exploit = [/\b(non|not)[\s-]?exploit/.test(lowerQuery) ? 'FALSE' : 'TRUE'];
  if (/\bsla\b[\s\S]{0,20}\bbreach/.test(lowerQuery) || /\bbreach(ed|es)?\b[\s\S]{0,20}\bsla\b/.test(lowerQuery)) filters.sla_breach = ['Yes'];
  return filters;
}

// Single entry point: turns a free-text question into the dashboard filter
// object accepted by recordMatchesFilters(), plus any AVS level mentioned.
function assistantExtractFilters(query, records) {
  const avsLevel = assistantExtractAvsLevel(String(query || '').toLowerCase());
  const filters = { ...assistantExtractFieldFilters(query, records), ...assistantExtractEnumeratedFilters(query, avsLevel) };
  return { filters, avsLevel };
}

// Extra response-type intents beyond the seven suggested questions
// (ASSISTANT_QUESTIONS stays limited to those for the suggestion chips).
//
// `fieldFilters` (the free-text AppSpace/Owner/Team/Remit Team/OS/Category/
// Environment values already recognised for this question) are stripped out
// before falling back to the keyword-based question matcher, so a field name
// used purely as a filter cue (e.g. the word "AppSpace" in "AppSpace owner
// Aisha Khan") is never mistaken for an intent keyword (e.g. "AppSpace" also
// being part of the "Top 10 vulnerable AppSpaces" question's keywords).
function assistantResolveIntent(text, fieldFilters) {
  const query = String(text || '').toLowerCase().trim();
  if (/\b(weekly vulnerability movement|weekly movement|last 7 weeks|last seven weeks|weekly improvement)\b/.test(query) ||
      (/\btrend\b/.test(query) && /\b(new|resolved|unchanged)\b/.test(query)) ||
      (/\blast week\b/.test(query) && /\bresolved\b/.test(query))) return 'weekly-movement';
  if (/\bvulnerabilit/.test(query) && /\b(with status|movement status)\b/.test(query) && /\b(new|resolved|unchanged)\b/.test(query)) return 'movement-status';
  if (/\bmost\s+risky\b|\briskiest\s+vulnerabilit/.test(query)) return 'most-risky';
  if (!query) return null;
  if (/\bhow many\b/.test(query) || /\btotal\b/.test(query) || /\bcount\b/.test(query)) return 'count';
  if (/\boldest\b/.test(query) && /\bopen\b/.test(query)) return 'oldest-open';
  if (/\btop\b/.test(query) && /\bteams?\b/.test(query)) return 'top-teams';
  if (/\bavs\b/.test(query) && /\bsummary\b/.test(query)) return 'avs-summary';
  if (/\bcompar/.test(query)) return 'comparison';
  return assistantMatchQuestion(assistantStripFieldFilterText(text, fieldFilters));
}

function assistantMostRiskyRecords(records) {
  const unique = {};
  records.forEach(record => {
    if (!['4', '5'].includes(String(record['Severity Level'] || '')) ||
        !['Essential', 'Fundamental'].includes(record.FundamentalClassification) ||
        !assistantIsTrue(record.PatchAvailable) || !assistantIsTrue(record.SLABreach ?? record.SIABreach) ||
        record.Zone !== 'External' || !assistantIsExploit(record) ||
        !record['VULN COUNT'] || unique[record['VULN COUNT']]) return;
    unique[record['VULN COUNT']] = record;
  });
  return Object.keys(unique).map(key => unique[key]);
}

function assistantIsTrue(value) {
  if (value === true || value === 1) return true;
  if (value === false || value === 0 || value === null || value === undefined) return false;
  const s = String(value).trim().toUpperCase();
  return s === 'TRUE' || s === '1' || s === 'YES' || s === 'T' || s === 'Y';
}

function assistantMostRiskyAnswer(records) {
  const risky = assistantMostRiskyRecords(records);
  const apps = assistantTopEntries(assistantCountBy(risky, r => r.AppSpaceName), 10);
  return {
    id: 'most-risky',
    title: 'Most Risky Vulnerabilities',
    summary: `${assistantNumber(risky.length)} unique Most Risky Vulnerabilities match the current criteria.`,
    stats: [
      { label: 'Total', value: assistantNumber(risky.length) },
      { label: 'Applications', value: assistantNumber(new Set(risky.map(r => r.AppSpaceName)).size) },
      { label: 'Average age', value: `${risky.length ? Math.round(risky.reduce((sum, r) => sum + Number(r['Vulnerability Age'] || r['Days Open'] || 0), 0) / risky.length) : 0} days` },
    ],
    items: apps.map(([name, count]) => ({ label: name, value: `${assistantNumber(count)} findings` })),
    notes: ['Criteria: severity 4/5, Essential/Fundamental, PatchAvailable, SLABreach, External and Exploit.'],
  };
}

function assistantEscapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function assistantStripFieldFilterText(text, fieldFilters) {
  let residual = String(text || '');
  Object.entries(fieldFilters || {}).forEach(([key, values]) => {
    (values || []).forEach(value => {
      residual = residual.replace(new RegExp(assistantEscapeRegExp(value), 'ig'), ' ');
    });
    (ASSISTANT_FILTER_FIELD_CUES[key] || []).forEach(cue => {
      residual = residual.replace(new RegExp(assistantEscapeRegExp(cue), 'ig'), ' ');
    });
  });
  return residual;
}

function assistantNumber(value) {
  return Number(value || 0).toLocaleString();
}

function assistantPercent(part, total) {
  if (!total) return '0%';
  return `${Math.round((part / total) * 1000) / 10}%`;
}

function assistantCountBy(records, keyOf) {
  const counts = {};
  records.forEach(record => {
    const key = keyOf(record);
    if (key === undefined || key === null || key === '' || key === 'N/A' || key === 'Unknown') return;
    counts[key] = (counts[key] || 0) + 1;
  });
  return counts;
}

function assistantTopEntries(counts, limit) {
  return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, limit);
}

function assistantIsExploit(record) {
  return record.Exploit === true || String(record.Exploit).trim().toUpperCase() === 'TRUE';
}

function assistantSeverityCounts(records) {
  return Object.fromEntries(ASSISTANT_SEVERITIES.map(severity => [severity, records.filter(r => r.Severity === severity).length]));
}

// Turns the dashboard's active filter selections into a single readable line
// that is attached to every answer, so the user always knows the answer scope.
function assistantScopeLabel(context) {
  const parts = (context.filters || [])
    .filter(entry => entry && entry.values && entry.values.length)
    .map(entry => `${entry.label}: ${entry.values.join(', ')}`);
  if (context.search) parts.push(`Search: "${context.search}"`);
  return parts.length ? `Scope - ${parts.join(' | ')}` : 'Scope - all findings (no filters applied)';
}

function assistantMatchQuestion(text) {
  const query = String(text || '').toLowerCase().trim();
  if (!query) return null;
  const exact = ASSISTANT_QUESTIONS.find(question => question.id === query || question.label.toLowerCase() === query);
  if (exact) return exact.id;
  let best = null;
  let bestScore = 0;
  ASSISTANT_QUESTIONS.forEach(question => {
    const score = question.keywords.reduce((total, keyword) => (query.includes(keyword) ? total + keyword.length : total), 0);
    if (score > bestScore) {
      bestScore = score;
      best = question.id;
    }
  });
  return bestScore >= ASSISTANT_MIN_MATCH_SCORE ? best : null;
}

function assistantAvsApps(records) {
  if (typeof computeAvsMetrics !== 'function') return [];
  return computeAvsMetrics(records).sort((a, b) => b.score - a.score);
}

function assistantEmptyAnswer(id, title) {
  return {
    id,
    title,
    summary: 'No findings match the current filters. Clear or widen the dashboard filters and ask again.',
    stats: [],
    items: [],
    notes: [],
  };
}

function assistantSummaryAnswer(records) {
  const severity = assistantSeverityCounts(records);
  const breached = records.filter(r => r.SLABreach).length;
  const overdue = records.filter(r => r.Overdue).length;
  const open = records.filter(r => r.Status === 'Open' || r.Status === 'In Progress').length;
  const resolved = records.filter(r => r.Status === 'Resolved' || r.Status === 'Closed').length;
  const topApps = assistantTopEntries(assistantCountBy(records, r => r.AppSpaceName), 5);
  const avsApps = assistantAvsApps(records);
  const avsCounts = {
    High: avsApps.filter(app => app.level === 'High').length,
    Medium: avsApps.filter(app => app.level === 'Medium').length,
    Low: avsApps.filter(app => app.level === 'Low').length,
  };
  return {
    id: 'summary',
    title: 'Vulnerability report summary',
    summary: `${assistantNumber(records.length)} findings in scope across ${assistantNumber(new Set(records.map(r => r.AppSpaceName)).size)} AppSpaces and ${assistantNumber(new Set(records.map(r => r.ServerName)).size)} servers.`,
    stats: [
      ...ASSISTANT_SEVERITIES.map(name => ({ label: name, value: assistantNumber(severity[name]) })),
      { label: 'Open / In progress', value: assistantNumber(open) },
      { label: 'Resolved / Closed', value: assistantNumber(resolved) },
      { label: 'SLA breached', value: `${assistantNumber(breached)} (${assistantPercent(breached, records.length)})` },
      { label: 'Overdue', value: assistantNumber(overdue) },
      { label: 'PCI required', value: assistantNumber(records.filter(r => r['PCI Required']).length) },
      { label: 'Exploitable', value: assistantNumber(records.filter(assistantIsExploit).length) },
      { label: 'Unique vuln instances', value: assistantNumber(new Set(records.map(r => r['VULN COUNT']).filter(Boolean)).size) },
      { label: 'AVS High', value: assistantNumber(avsCounts.High) },
      { label: 'AVS Medium', value: assistantNumber(avsCounts.Medium) },
      { label: 'AVS Low', value: assistantNumber(avsCounts.Low) },
    ],
    items: topApps.map(([name, total]) => ({ label: name, value: `${assistantNumber(total)} findings` })),
    notes: [`${assistantPercent(severity.Critical + severity.High, records.length)} of findings in scope are Critical or High severity.`],
  };
}

function assistantCriticalAnswer(records) {
  const criticals = records.filter(r => r.Severity === 'Critical');
  if (!criticals.length) {
    return {
      id: 'critical',
      title: 'Critical vulnerabilities',
      summary: 'No Critical findings in the current scope.',
      stats: [],
      items: [],
      notes: [],
    };
  }
  const breached = criticals.filter(r => r.SLABreach).length;
  const sorted = [...criticals].sort((a, b) => Number(b.SLABreach) - Number(a.SLABreach) || Number(b['Days Open'] || 0) - Number(a['Days Open'] || 0));
  return {
    id: 'critical',
    title: 'Critical vulnerabilities',
    summary: `${assistantNumber(criticals.length)} Critical findings (${assistantPercent(criticals.length, records.length)} of the current scope).`,
    stats: [
      { label: 'SLA breached', value: assistantNumber(breached) },
      { label: 'Overdue', value: assistantNumber(criticals.filter(r => r.Overdue).length) },
      { label: 'Unresolved', value: assistantNumber(criticals.filter(r => r.Status === 'Open' || r.Status === 'In Progress').length) },
      { label: 'Servers affected', value: assistantNumber(new Set(criticals.map(r => r.ServerName)).size) },
    ],
    items: sorted.slice(0, 5).map(record => ({
      label: `${record.ServerName} - ${record['Vulnerability Name']}`,
      value: `${assistantNumber(record['Days Open'])}d open`,
      detail: `${record.AppSpaceName || 'Unknown AppSpace'} | ${record.SLABreach ? `SLA breached by ${assistantNumber(record['Days Overdue'])}d` : `SLA due ${record['SLA Due Date'] || 'unknown'}`}`,
    })),
    notes: ['Showing the 5 oldest breached Critical findings. Use the Critical table on the dashboard for the full list.'],
  };
}

function assistantTopAppSpacesAnswer(records) {
  const counts = assistantCountBy(records, r => r.AppSpaceName);
  const top = assistantTopEntries(counts, 10);
  if (!top.length) return assistantEmptyAnswer('top-appspaces', 'Top 10 vulnerable AppSpaces');
  return {
    id: 'top-appspaces',
    title: 'Top 10 vulnerable AppSpaces',
    summary: `Ranked by finding count within the current scope (${assistantNumber(records.length)} findings).`,
    stats: [],
    items: top.map(([name, total], index) => {
      const appRecords = records.filter(r => r.AppSpaceName === name);
      return {
        label: `${String(index + 1).padStart(2, '0')}. ${name}`,
        value: `${assistantNumber(total)} findings`,
        detail: `${assistantNumber(appRecords.filter(r => r.Severity === 'Critical').length)} Critical | ${assistantNumber(appRecords.filter(r => r.Severity === 'High').length)} High | ${assistantNumber(appRecords.filter(r => r.SLABreach).length)} breached`,
      };
    }),
    notes: [],
  };
}

function assistantHighAvsAnswer(records, level) {
  const targetLevel = level || 'High';
  const apps = assistantAvsApps(records);
  if (!apps.length) return assistantEmptyAnswer('high-avs', `Applications with ${targetLevel} AVS`);
  const matched = apps.filter(app => app.level === targetLevel);
  const shown = matched.length ? matched : apps.slice(0, 5);
  const rangeNote = targetLevel === 'High' ? ' (AVS above 1000)' : targetLevel === 'Medium' ? ' (AVS 500-1000)' : ' (AVS below 500)';
  return {
    id: 'high-avs',
    title: `Applications with ${targetLevel} AVS`,
    summary: matched.length
      ? `${assistantNumber(matched.length)} of ${assistantNumber(apps.length)} applications score ${targetLevel}${rangeNote} in the current scope.`
      : `No application scores ${targetLevel}${rangeNote} in the current scope. Showing the highest scoring applications instead.`,
    stats: [
      { label: 'High', value: assistantNumber(apps.filter(app => app.level === 'High').length) },
      { label: 'Medium', value: assistantNumber(apps.filter(app => app.level === 'Medium').length) },
      { label: 'Low', value: assistantNumber(apps.filter(app => app.level === 'Low').length) },
    ],
    items: shown.slice(0, 10).map(app => ({
      label: app.name,
      value: `AVS ${app.score.toFixed(1)}`,
      detail: `${app.team} | ${app.uniqueCount} qualifying vulns | Zone ${app.zone} | ${app.fundamentalClassification}`,
    })),
    notes: matched.length ? ['Prioritise these applications first: AVS combines Zone exposure and FundamentalClassification.'] : [],
  };
}

// Aggregated count answer for "how many"/"total"/"count" style questions.
// Works on whatever records were already narrowed down by dashboard filters
// (active UI selections and/or filters extracted from the question itself).
function assistantCountAnswer(records) {
  if (!records.length) return assistantEmptyAnswer('count', 'Vulnerability count');
  const appCounts = assistantTopEntries(assistantCountBy(records, r => r.AppSpaceName), 10);
  return {
    id: 'count',
    title: 'Vulnerability count',
    summary: `${assistantNumber(records.length)} findings match the current criteria across ${assistantNumber(new Set(records.map(r => r.AppSpaceName)).size)} affected AppSpaces.`,
    stats: [
      { label: 'Total', value: assistantNumber(records.length) },
      ...ASSISTANT_SEVERITIES.map(name => ({ label: name, value: assistantNumber(records.filter(r => r.Severity === name).length) })),
      { label: 'SLA breached', value: assistantNumber(records.filter(r => r.SLABreach).length) },
      { label: 'Exploitable', value: assistantNumber(records.filter(assistantIsExploit).length) },
      { label: 'Unique vuln instances', value: assistantNumber(new Set(records.map(r => r['VULN COUNT']).filter(Boolean)).size) },
    ],
    items: appCounts.map(([name, total]) => ({ label: name, value: `${assistantNumber(total)} findings` })),
    notes: ['Affected AppSpaces, ranked by finding count within the current criteria.'],
  };
}

function assistantTopTeamsAnswer(records) {
  const counts = assistantCountBy(records, r => r.AppSpaceTeam);
  const top = assistantTopEntries(counts, 10);
  if (!top.length) return assistantEmptyAnswer('top-teams', 'Top teams by vulnerability count');
  return {
    id: 'top-teams',
    title: 'Top teams by vulnerability count',
    summary: `Ranked by finding count within the current scope (${assistantNumber(records.length)} findings).`,
    stats: [],
    items: top.map(([name, total], index) => {
      const teamRecords = records.filter(r => r.AppSpaceTeam === name);
      return {
        label: `${String(index + 1).padStart(2, '0')}. ${name}`,
        value: `${assistantNumber(total)} findings`,
        detail: `${assistantNumber(teamRecords.filter(r => r.Severity === 'Critical').length)} Critical | ${assistantNumber(teamRecords.filter(r => r.SLABreach).length)} breached`,
      };
    }),
    notes: [],
  };
}

function assistantOldestOpenAnswer(records) {
  const open = records.filter(r => r.Status === 'Open' || r.Status === 'In Progress');
  if (!open.length) return assistantEmptyAnswer('oldest-open', 'Oldest open vulnerabilities');
  const sorted = [...open].sort((a, b) => Number(b['Days Open'] || 0) - Number(a['Days Open'] || 0));
  return {
    id: 'oldest-open',
    title: 'Oldest open vulnerabilities',
    summary: `${assistantNumber(open.length)} open or in-progress findings in scope, oldest first.`,
    stats: [
      { label: 'Oldest', value: `${assistantNumber(sorted[0]['Days Open'])}d` },
      { label: 'SLA breached', value: assistantNumber(open.filter(r => r.SLABreach).length) },
    ],
    items: sorted.slice(0, 10).map(record => ({
      label: `${record.ServerName} - ${record['Vulnerability Name']}`,
      value: `${assistantNumber(record['Days Open'])}d open`,
      detail: `${record.AppSpaceName || 'Unknown AppSpace'} | ${record.Severity}`,
    })),
    notes: [],
  };
}

function assistantAvsSummaryAnswer(records) {
  const apps = assistantAvsApps(records);
  if (!apps.length) return assistantEmptyAnswer('avs-summary', 'AVS summary');
  const counts = {
    High: apps.filter(app => app.level === 'High').length,
    Medium: apps.filter(app => app.level === 'Medium').length,
    Low: apps.filter(app => app.level === 'Low').length,
  };
  return {
    id: 'avs-summary',
    title: 'AVS summary',
    summary: `${assistantNumber(apps.length)} applications scored in the current scope.`,
    stats: [
      { label: 'High', value: assistantNumber(counts.High) },
      { label: 'Medium', value: assistantNumber(counts.Medium) },
      { label: 'Low', value: assistantNumber(counts.Low) },
    ],
    items: apps.slice(0, 5).map(app => ({ label: app.name, value: `AVS ${app.score.toFixed(1)}`, detail: `${app.level} | ${app.team}` })),
    notes: [],
  };
}

function assistantComparisonAnswer(records) {
  if (!records.length) return assistantEmptyAnswer('comparison', 'Comparison');
  const severity = assistantSeverityCounts(records);
  const status = Object.fromEntries(ASSISTANT_STATUSES.map(name => [name, records.filter(r => r.Status === name).length]));
  return {
    id: 'comparison',
    title: 'Comparison',
    summary: `Comparing severity and status distribution across ${assistantNumber(records.length)} findings in the current scope.`,
    stats: [
      ...ASSISTANT_SEVERITIES.map(name => ({ label: `Severity: ${name}`, value: assistantNumber(severity[name]) })),
      ...ASSISTANT_STATUSES.map(name => ({ label: `Status: ${name}`, value: assistantNumber(status[name]) })),
    ],
    items: [],
    notes: [],
  };
}

function assistantSlaAnswer(records) {
  const breached = records.filter(r => r.SLABreach);
  if (!records.length) return assistantEmptyAnswer('sla-breach', 'SLA breach summary');
  const daysOverdue = breached.map(r => Number(r['Days Overdue'] || 0));
  const averageOverdue = daysOverdue.length ? Math.round(daysOverdue.reduce((total, days) => total + days, 0) / daysOverdue.length) : 0;
  const topApps = assistantTopEntries(assistantCountBy(breached, r => r.AppSpaceName), 5);
  return {
    id: 'sla-breach',
    title: 'SLA breach summary',
    summary: `${assistantNumber(breached.length)} of ${assistantNumber(records.length)} findings (${assistantPercent(breached.length, records.length)}) have breached their SLA.`,
    stats: [
      ...ASSISTANT_SEVERITIES.map(severity => ({ label: `${severity} breached`, value: assistantNumber(breached.filter(r => r.Severity === severity).length) })),
      { label: 'Average days overdue', value: assistantNumber(averageOverdue) },
      { label: 'Worst overdue', value: `${assistantNumber(daysOverdue.length ? Math.max(...daysOverdue) : 0)}d` },
    ],
    items: topApps.map(([name, total]) => ({ label: name, value: `${assistantNumber(total)} breached` })),
    notes: ['SLA targets: Critical 7 days, High 30 days, Medium 60 days, Low 90 days.'],
  };
}

function assistantRemediationAnswer(records) {
  if (!records.length) return assistantEmptyAnswer('remediation', 'Top remediation actions');
  const unresolved = records.filter(r => r.Status === 'Open' || r.Status === 'In Progress');
  // Rank remediation work by the vulnerability groups that carry the most
  // weight: unresolved findings, weighted towards Critical and breached items.
  const groups = {};
  unresolved.forEach(record => {
    const name = record['Vulnerability Name'] || record.QID || 'Unknown finding';
    if (!groups[name]) groups[name] = { total: 0, critical: 0, breached: 0, servers: new Set(), qid: record.QID };
    const group = groups[name];
    group.total += 1;
    if (record.Severity === 'Critical') group.critical += 1;
    if (record.SLABreach) group.breached += 1;
    group.servers.add(record.ServerName);
  });
  const ranked = Object.entries(groups)
    .map(([name, group]) => ({ name, ...group, weight: group.critical * 3 + group.breached * 2 + group.total }))
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 7);
  return {
    id: 'remediation',
    title: 'Top remediation actions',
    summary: `${assistantNumber(unresolved.length)} unresolved findings in scope. Fixing the items below clears ${assistantPercent(ranked.reduce((total, group) => total + group.total, 0), unresolved.length || 1)} of them.`,
    stats: ASSISTANT_STATUSES.map(status => ({ label: status, value: assistantNumber(records.filter(r => r.Status === status).length) })),
    items: ranked.map((group, index) => ({
      label: `${index + 1}. ${group.name}`,
      value: `${assistantNumber(group.total)} findings`,
      detail: `${group.servers.size} servers | ${group.critical} Critical | ${group.breached} SLA breached${group.qid ? ` | ${group.qid}` : ''}`,
    })),
    notes: ['Ranking weights Critical findings x3 and SLA breached findings x2 against the total count.'],
  };
}

function assistantAvsExplanationAnswer(records) {
  const apps = assistantAvsApps(records);
  const top = apps[0];
  return {
    id: 'avs-explained',
    title: 'How the AVS score works',
    summary: 'AVS (Application Vulnerability Score) = qualifying vulnerabilities x Zone rating x FundamentalClassification rating, calculated per AppSpace.',
    stats: [
      { label: 'External zone', value: 'x5' },
      { label: 'Internal zone', value: 'x1' },
      { label: 'Internal & Protected', value: 'x0.2' },
      { label: 'Essential / Fundamental classification', value: 'x2' },
      { label: 'Other classification', value: 'x1' },
    ],
    items: [
      { label: 'Qualifying vulnerability', value: 'Critical severity and older than 45 days' },
      { label: 'Deduplication', value: 'Unique Vuln Name per application (CVE, or VendorReference when no CVE exists)' },
      { label: 'Low', value: 'Score below 500' },
      { label: 'Medium', value: 'Score from 500 to 1000' },
      { label: 'High', value: 'Score above 1000' },
    ],
    notes: top
      ? [`Highest scoring application in the current scope: ${top.name} at AVS ${top.score.toFixed(1)} (${top.level}), driven by ${top.uniqueCount} qualifying vulnerabilities in the ${top.zone} zone.`]
      : ['No application in the current scope has qualifying vulnerabilities, so every AVS score is 0.'],
  };
}

function assistantWeeklyMovementAnswer(records, avsLevel, context) {
  const history = context.trendHistory || [];
  if (!history.length) return assistantEmptyAnswer('weekly-movement', 'Weekly vulnerability movement');
  const latest = history[history.length - 1];
  const previous = history.length > 1 ? history[history.length - 2] : null;
  const net = Number(latest.resolved || 0) - Number(latest.new || 0);
  return {
    id: 'weekly-movement',
    title: 'Weekly vulnerability movement',
    summary: `For the week of ${latest.week}, ${assistantNumber(latest.new)} vulnerabilities were new, ${assistantNumber(latest.resolved)} were resolved and ${assistantNumber(latest.unchanged)} were unchanged.`,
    stats: [
      { label: 'New', value: assistantNumber(latest.new) },
      { label: 'Resolved', value: assistantNumber(latest.resolved) },
      { label: 'Unchanged', value: assistantNumber(latest.unchanged) },
      { label: 'Net improvement', value: assistantNumber(net) },
    ],
    items: history.slice().reverse().map(item => ({
      label: item.week,
      value: `${assistantNumber(item.new)} new | ${assistantNumber(item.resolved)} resolved | ${assistantNumber(item.unchanged)} unchanged`,
    })),
    notes: [
      net >= 0 ? `Resolved exceeded new vulnerabilities by ${assistantNumber(net)}.` : `New vulnerabilities exceeded resolved vulnerabilities by ${assistantNumber(Math.abs(net))}.`,
      previous ? `Previous week resolved: ${assistantNumber(previous.resolved)}.` : 'This is the first recorded reporting week.',
    ],
  };
}

function assistantMovementStatusAnswer(records) {
  const status = records[0]?.NewResolvedStatus || 'selected';
  return {
    id: 'movement-status',
    title: `${status} vulnerabilities`,
    summary: `${assistantNumber(records.length)} vulnerabilities match the requested weekly movement status.`,
    stats: [{ label: status, value: assistantNumber(records.length) }],
    items: records.slice(0, 10).map(record => ({
      label: record['Vulnerability Name'] || record.QID || 'Unknown vulnerability',
      value: record.ServerName || '',
      detail: `${record.AppSpaceName || 'Unknown AppSpace'} | ${record.QID || 'Unknown QID'}`,
    })),
    notes: records.length > 10 ? [`Showing the first 10 of ${assistantNumber(records.length)} matching vulnerabilities.`] : [],
  };
}

function assistantFallbackAnswer() {
  return {
    id: 'fallback',
    title: "Sorry, I couldn't understand that request",
    summary: "Sorry, I couldn't understand that request. Try asking about AppSpace, Owner, Team, Severity, SLA, AVS or Vulnerability Summary.",
    stats: [],
    items: ASSISTANT_QUESTIONS.map(question => ({ label: question.label, value: '' })),
    notes: [],
  };
}

const ASSISTANT_ANSWER_BUILDERS = {
  'summary': assistantSummaryAnswer,
  'critical': assistantCriticalAnswer,
  'top-appspaces': assistantTopAppSpacesAnswer,
  'high-avs': assistantHighAvsAnswer,
  'sla-breach': assistantSlaAnswer,
  'remediation': assistantRemediationAnswer,
  'avs-explained': assistantAvsExplanationAnswer,
  'count': assistantCountAnswer,
  'top-teams': assistantTopTeamsAnswer,
  'oldest-open': assistantOldestOpenAnswer,
  'avs-summary': assistantAvsSummaryAnswer,
  'comparison': assistantComparisonAnswer,
  'most-risky': assistantMostRiskyAnswer,
  'weekly-movement': assistantWeeklyMovementAnswer,
  'movement-status': assistantMovementStatusAnswer,
};

// Some intents already apply their own filtering as part of the answer they
// build (e.g. the Critical answer only ever looks at Critical findings, the
// SLA breach summary needs the full set to compute a breached/total ratio).
// When the matched intent owns a field, a bare mention of that field's
// vocabulary in the question (e.g. the word "critical" that triggered the
// intent itself) should not also be re-applied as a pre-filter.
const ASSISTANT_INTENT_OWNED_FIELDS = {
  'critical': ['severity'],
  'sla-breach': ['sla_breach'],
  'remediation': ['status'],
};

// Single entry point used by the widget: question text plus the dashboard
// context ({records, allRecords, rawFilters, filters, search, meta})
// produces a structured answer.
//
// Any filter criteria named in the question (AppSpace, Owner, Team,
// Environment, Severity, Status, Remit Team, Group, OS, Category, PCI, SLA
// Breach, Exploit, FundamentalClassification, Zone, AVS Level) are converted into the dashboard's own filter object and
// applied with the dashboard's own recordMatchesFilters() predicate (filters.js).
// The chatbot never re-implements filtering: it only decides *which*
// dashboard filters a question means, then reuses the exact same logic the
// filter dropdowns use, so both surfaces always agree on the result set.
function answerAssistantQuestion(question, context) {
  const scope = { ...(context || {}) };
  const allRecords = scope.allRecords || scope.records || [];
  const activeFilters = scope.rawFilters || {};
  const { filters: extractedFilters, avsLevel } = assistantExtractFilters(question, allRecords);
  const freeTextFilters = Object.fromEntries(
    Object.entries(extractedFilters).filter(([key]) => ASSISTANT_FREE_TEXT_FIELDS.includes(key))
  );

  let matchedId = assistantResolveIntent(question, freeTextFilters);
  const ownedFields = ASSISTANT_INTENT_OWNED_FIELDS[matchedId] || [];
  const nlFilters = Object.fromEntries(Object.entries(extractedFilters).filter(([key]) => !ownedFields.includes(key)));
  const hasNlFilters = Object.keys(nlFilters).length > 0;
  const mergedFilters = { ...activeFilters, ...nlFilters };
  const records = hasNlFilters && typeof recordMatchesFilters === 'function'
    ? allRecords.filter(record => recordMatchesFilters(record, mergedFilters))
    : (scope.records || []);

  if (!matchedId && (hasNlFilters || avsLevel)) matchedId = avsLevel ? 'high-avs' : 'summary';

  const builder = ASSISTANT_ANSWER_BUILDERS[matchedId];
  if (!builder) return { ...assistantFallbackAnswer(), scope: assistantScopeLabel(scope) };
  if (!records.length && !['avs-explained', 'weekly-movement'].includes(matchedId)) {
    const label = (ASSISTANT_QUESTIONS.find(item => item.id === matchedId) || {}).label || 'Answer';
    return { ...assistantEmptyAnswer(matchedId, label), scope: assistantScopeLabel(scope) };
  }
  const answer = builder(records, avsLevel, scope);
  if (hasNlFilters) {
    const described = Object.entries(nlFilters).map(([key, values]) => {
      const definition = typeof filterDefinition === 'function' ? filterDefinition(key) : null;
      return `${definition ? definition.label : key} = ${values.join(', ')}`;
    });
    if (avsLevel) described.push(`AVS = ${avsLevel}`);
    answer.notes = [`Applied dashboard filters from your question: ${described.join(' | ')}`, ...(answer.notes || [])];
  }
  return { ...answer, scope: assistantScopeLabel(scope) };
}
