let policies = [];
let archives = [];
let legalHolds = [];

function getPolicies() { return policies; }

function savePolicy(body) {
  const policy = { id: String(policies.length + 1), name: body.name || 'policy', type: body.type || 'rolling', retentionDays: body.retentionDays || 90, ...body };
  policies.push(policy);
  return policy;
}

function deletePolicy(id) { policies = policies.filter((p) => p.id !== id); }

function getArchives() { return archives; }

function getArchiveStats() {
  return { totalArchives: archives.length, totalSize: '1.2 TB', oldestArchive: '2024-01-01', newestArchive: new Date().toISOString() };
}

function restoreArchive(id) {
  return { id, status: 'restoring', startedAt: new Date().toISOString() };
}

function deleteArchive(id) { archives = archives.filter((a) => a.id !== id); }

function getLegalHolds() { return legalHolds; }

function addLegalHold(body) {
  const hold = { id: String(legalHolds.length + 1), caseName: body.caseName || 'case', ...body, createdAt: new Date().toISOString() };
  legalHolds.push(hold);
  return hold;
}

function removeLegalHold(id) { legalHolds = legalHolds.filter((h) => h.id !== id); }

function runOnce() {
  return { status: 'completed', archived: policies.length, freed: '500 MB', timestamp: new Date().toISOString() };
}

function getRetentionReport() {
  return { policies, archives, legalHolds, summary: { totalPolicies: policies.length, totalArchived: archives.length, totalHolds: legalHolds.length } };
}

function getStorageForecast(days) {
  return Array.from({ length: Math.min(days || 30, 365) }, (_, i) => ({
    day: i + 1, projectedUsage: `${(100 + i * 2)} GB`, timestamp: new Date(Date.now() + i * 86400000).toISOString(),
  }));
}

module.exports = { getPolicies, savePolicy, deletePolicy, getArchives, getArchiveStats, restoreArchive, deleteArchive, getLegalHolds, addLegalHold, removeLegalHold, runOnce, getRetentionReport, getStorageForecast };
