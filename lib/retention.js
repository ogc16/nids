const fs = require('fs');
const path = require('path');
const config = require('./config');
const db = require('./db');
const { AppError, ValidationError } = require('./errors');

const archiveDir = path.join(config.dataDir, 'archive');
const policiesTable = '_retention_policies';
const purgeLogTable = '_purge_log';
const legalHoldsTable = '_legal_holds';
const retentionSettingsTable = '_retention_settings';

function ensureArchiveDir() {
  if (!fs.existsSync(archiveDir)) {
    fs.mkdirSync(archiveDir, { recursive: true });
  }
}

let _defaultsInitialized = false;
function getPolicies() {
    if (!_defaultsInitialized) { initDefaults(); _defaultsInitialized = true; }
    return db.readTableSafe(policiesTable);
}

function savePolicy(policy) {
  if (!policy.name || !policy.table || !policy.retentionDays) {
    throw new ValidationError('Policy requires name, table, and retentionDays');
  }
  const validActions = ['delete', 'archive', 'compress', 'anonymize'];
  if (policy.action && !validActions.includes(policy.action)) {
    throw new ValidationError(`Invalid action. Must be one of: ${validActions.join(', ')}`);
  }
  const policies = getPolicies();
  if (policy.id) {
    const idx = policies.findIndex(p => p.id === policy.id);
    if (idx === -1) throw new AppError(404, 'Policy not found');
    policies[idx] = { ...policies[idx], ...policy, updatedAt: new Date().toISOString() };
  } else {
    policy.id = db.nextId(policies);
    policy.createdAt = new Date().toISOString();
    policy.enabled = policy.enabled !== false;
    policy.action = policy.action || 'delete';
    policy.priority = policy.priority || 0;
    policies.push(policy);
  }
  db.writeTable(policiesTable, policies);
  return policy;
}

function deletePolicy(policyId) {
  const policies = getPolicies();
  const idx = policies.findIndex(p => p.id === policyId);
  if (idx === -1) throw new AppError(404, 'Policy not found');
  policies.splice(idx, 1);
  db.writeTable(policiesTable, policies);
  return true;
}

function archiveData(policy) {
  ensureArchiveDir();
  const data = db.readTableSafe(policy.table);
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - policy.archiveAfterDays);
  const cutoffTs = cutoff.getTime();
  const toArchive = data.filter(r => {
    const ts = new Date(r.timestamp || r.createdAt || r.date || 0).getTime();
    return ts < cutoffTs;
  });
  if (toArchive.length === 0) return { archived: 0 };
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const archiveFile = path.join(archiveDir, `${policy.table}-${timestamp}.json`);
  const archiveRecord = {
    id: path.basename(archiveFile, '.json'),
    table: policy.table,
    policyId: policy.id,
    file: archiveFile,
    recordCount: toArchive.length,
    createdAt: new Date().toISOString(),
    sizeBytes: 0
  };
  fs.writeFileSync(archiveFile, JSON.stringify(toArchive, null, 2), 'utf8');
  archiveRecord.sizeBytes = fs.statSync(archiveFile).size;
  const archives = getArchives();
  archives.push(archiveRecord);
  db.writeTable('_archives', archives);
  const remaining = data.filter(r => {
    const ts = new Date(r.timestamp || r.createdAt || r.date || 0).getTime();
    return ts >= cutoffTs;
  });
  db.writeTable(policy.table, remaining);
  return { archived: toArchive.length, archiveFile };
}

function getArchives() {
  return db.readTableSafe('_archives');
}

function restoreArchive(archiveId) {
  const archives = getArchives();
  const archive = archives.find(a => a.id === archiveId);
  if (!archive) throw new AppError(404, 'Archive not found');
  if (!fs.existsSync(archive.file)) throw new AppError(404, 'Archive file not found');
  const raw = fs.readFileSync(archive.file, 'utf8');
  const data = JSON.parse(raw);
  const existing = db.readTableSafe(archive.table);
  const combined = [...existing, ...data];
  db.writeTable(archive.table, combined);
  return { restored: data.length, table: archive.table };
}

function deleteArchive(archiveId) {
  const archives = getArchives();
  const idx = archives.findIndex(a => a.id === archiveId);
  if (idx === -1) throw new AppError(404, 'Archive not found');
  const archive = archives[idx];
  if (fs.existsSync(archive.file)) {
    fs.unlinkSync(archive.file);
  }
  archives.splice(idx, 1);
  db.writeTable('_archives', archives);
  return true;
}

function getArchiveStats() {
  const archives = getArchives();
  if (archives.length === 0) {
    return { totalArchives: 0, totalSize: 0, oldest: null, newest: null };
  }
  const totalSize = archives.reduce((sum, a) => sum + (a.sizeBytes || 0), 0);
  const sorted = [...archives].sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());
  return {
    totalArchives: archives.length,
    totalSize,
    oldest: sorted[0].createdAt,
    newest: sorted[sorted.length - 1].createdAt
  };
}

function purgeData(policy) {
  const data = db.readTableSafe(policy.table);
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - policy.retentionDays);
  const cutoffTs = cutoff.getTime();
  const toDelete = data.filter(r => {
    const ts = new Date(r.timestamp || r.createdAt || r.date || 0).getTime();
    return ts < cutoffTs;
  });
  const holds = getLegalHolds();
  const lockedIds = new Set();
  for (const hold of holds) {
    if (hold.criteria.tables && !hold.criteria.tables.includes(policy.table)) continue;
    for (const r of toDelete) {
      if (matchesHold(r, hold)) lockedIds.add(r.id);
    }
  }
  const deletable = toDelete.filter(r => !lockedIds.has(r.id));
  if (deletable.length === 0) return { purged: 0, held: toDelete.length - deletable.length };
  const remaining = data.filter(r => {
    const ts = new Date(r.timestamp || r.createdAt || r.date || 0).getTime();
    if (ts >= cutoffTs) return true;
    return lockedIds.has(r.id);
  });
  db.writeTable(policy.table, remaining);
  const logEntry = {
    id: db.nextId(getPurgeHistory()),
    table: policy.table,
    policyId: policy.id,
    purgedCount: deletable.length,
    heldCount: toDelete.length - deletable.length,
    purgedAt: new Date().toISOString()
  };
  const log = getPurgeHistory();
  log.push(logEntry);
  db.writeTable(purgeLogTable, log);
  return { purged: deletable.length, held: toDelete.length - deletable.length };
}

function purgeAll() {
  const policies = getPolicies().filter(p => p.enabled);
  const results = [];
  for (const policy of policies) {
    const result = purgeData(policy);
    results.push({ policy: policy.name, ...result });
  }
  const lastRun = { lastRunAt: new Date().toISOString() };
  const settings = getSettings();
  settings.lastRunAt = lastRun.lastRunAt;
  saveSettings(settings);
  return results;
}

function getPurgeHistory(limit) {
  const log = db.readTableSafe(purgeLogTable);
  if (limit && limit > 0) {
    return log.slice(-limit);
  }
  return log;
}

function compactTable(table) {
  const data = db.readTableSafe(table);
  const cleaned = data.filter(r => !r._deleted && !r._expired);
  if (cleaned.length < data.length) {
    db.writeTable(table, cleaned);
  }
  return { removed: data.length - cleaned.length, remaining: cleaned.length };
}

function vacuumDatabase() {
  db.vacuum();
  return true;
}

function getTableSizes() {
  const tables = db.getTableNames();
  const d = db.getDb();
  return tables.map(t => {
    const row = d.prepare(`SELECT COUNT(*) as cnt FROM "${t}"`).get();
    let size = 0;
    try {
      const st = d.prepare(`SELECT SUM(LENGTH(id) + LENGTH(data)) as total FROM "${t}"`).get();
      size = st.total || 0;
    } catch {}
    return { table: t, records: row.cnt, sizeBytes: size };
  });
}

function addLegalHold(criteria) {
  if (!criteria.caseName || !criteria.createdBy) {
    throw new ValidationError('Legal hold requires caseName and createdBy');
  }
  const holds = getLegalHolds();
  const hold = {
    id: db.nextId(holds),
    caseName: criteria.caseName,
    createdBy: criteria.createdBy,
    createdAt: new Date().toISOString(),
    expiresAt: criteria.expiresAt || null,
    criteria: {
      tables: criteria.tables || [],
      dateRange: criteria.dateRange || {},
      keywords: criteria.keywords || []
    },
    affectedRecords: 0
  };
  holds.push(hold);
  db.writeTable(legalHoldsTable, holds);
  return hold;
}

function removeLegalHold(holdId) {
  const holds = getLegalHolds();
  const idx = holds.findIndex(h => h.id === holdId);
  if (idx === -1) throw new AppError(404, 'Legal hold not found');
  holds.splice(idx, 1);
  db.writeTable(legalHoldsTable, holds);
  return true;
}

function getLegalHolds() {
  return db.readTableSafe(legalHoldsTable);
}

function matchesHold(record, hold) {
  if (hold.criteria.dateRange && hold.criteria.dateRange.start && hold.criteria.dateRange.end) {
    const ts = new Date(record.timestamp || record.createdAt || record.date || 0).getTime();
    const start = new Date(hold.criteria.dateRange.start).getTime();
    const end = new Date(hold.criteria.dateRange.end).getTime();
    if (ts >= start && ts <= end) return true;
  }
  if (hold.criteria.keywords && hold.criteria.keywords.length > 0) {
    const recordStr = JSON.stringify(record).toLowerCase();
    for (const kw of hold.criteria.keywords) {
      if (recordStr.includes(kw.toLowerCase())) return true;
    }
  }
  return false;
}

let schedulerInterval = null;

function startScheduler() {
  if (schedulerInterval) return false;
  schedulerInterval = setInterval(() => {
    try {
      purgeAll();
    } catch (err) {
      console.error('[Retention] Scheduler error:', err.message);
    }
  }, 3600000);
  return true;
}

function stopScheduler() {
  if (!schedulerInterval) return false;
  clearInterval(schedulerInterval);
  schedulerInterval = null;
  return true;
}

function runOnce() {
  return purgeAll();
}

function getLastRun() {
  const settings = getSettings();
  return settings.lastRunAt || null;
}

function getSettings() {
  try {
    const stored = db.readTableSafe(retentionSettingsTable);
    return stored.length > 0 ? stored[0] : {};
  } catch {
    return {};
  }
}

function saveSettings(settings) {
  db.writeTable(retentionSettingsTable, [settings]);
}

function getRetentionReport() {
  const policies = getPolicies();
  const archives = getArchives();
  const holds = getLegalHolds();
  const tableSizes = getTableSizes();
  const totalDataSize = tableSizes.reduce((sum, t) => sum + t.sizeBytes, 0);
  const policiesByTable = {};
  for (const p of policies) {
    if (!policiesByTable[p.table]) policiesByTable[p.table] = [];
    policiesByTable[p.table].push(p);
  }
  let nextPurgeDate = null;
  if (policies.length > 0) {
    const soonest = policies.reduce((min, p) => {
      if (!p.enabled) return min;
      return typeof p.retentionDays === 'number' && (min === null || p.retentionDays < min) ? p.retentionDays : min;
    }, null);
    if (soonest !== null) {
      const d = new Date();
      d.setDate(d.getDate() + soonest);
      nextPurgeDate = d.toISOString();
    }
  }
  return {
    totalDataSize,
    archiveCount: archives.length,
    nextPurgeDate,
    policiesByTable,
    legalHoldsActive: holds.length
  };
}

function getStorageForecast(days) {
  const tableSizes = getTableSizes();
  const current = tableSizes.reduce((sum, t) => sum + t.sizeBytes, 0);
  const policies = getPolicies();
  const growthRate = 0.05;
  const forecast = [];
  for (let i = 0; i <= days; i += 7) {
    const date = new Date();
    date.setDate(date.getDate() + i);
    const estimatedSize = current * Math.pow(1 + growthRate, i / 30);
    const purgeEstimate = policies.filter(p => p.enabled).length > 0 ? estimatedSize * 0.3 : 0;
    forecast.push({
      date: date.toISOString().split('T')[0],
      daysFromNow: i,
      estimatedSize: Math.round(estimatedSize),
      estimatedSizeAfterPurge: Math.round(estimatedSize - purgeEstimate)
    });
  }
  return {
    currentSize: current,
    tableSizes,
    forecast,
    growthRate
  };
}

function initDefaults() {
  const existing = getPolicies();
  if (existing.length > 0) return;
  const defaults = [
    { name: 'Incidents Retention', table: 'incidents', retentionDays: 365, archiveAfterDays: 90, action: 'archive', priority: 10 },
    { name: 'Network Traffic Retention', table: 'network-traffic', retentionDays: 90, archiveAfterDays: 30, action: 'archive', priority: 9 },
    { name: 'Audit Logs Retention', table: 'audit-logs', retentionDays: 180, archiveAfterDays: 60, action: 'archive', priority: 8 },
    { name: 'PCAP Captures Retention', table: 'pcap-captures', retentionDays: 30, archiveAfterDays: 7, action: 'delete', priority: 7 },
    { name: 'Threat Intel Retention', table: 'threat-intel', retentionDays: 365, archiveAfterDays: 180, action: 'archive', priority: 6 },
    { name: 'Detection Rules Retention', table: 'detection-rules', retentionDays: 730, archiveAfterDays: 365, action: 'archive', priority: 5 },
    { name: 'Automations Log Retention', table: 'automations-log', retentionDays: 90, archiveAfterDays: 30, action: 'delete', priority: 4 },
    { name: 'Asset Logs Retention', table: 'asset-logs', retentionDays: 180, archiveAfterDays: 60, action: 'archive', priority: 3 },
    { name: 'Security Policies Retention', table: 'security-policies', retentionDays: 730, archiveAfterDays: 365, action: 'archive', priority: 2 },
    { name: 'Network Assets Retention', table: 'network-assets', retentionDays: 365, archiveAfterDays: 90, action: 'archive', priority: 1 }
  ];
  const policies = [];
  for (const d of defaults) {
    d.id = db.nextId(policies);
    d.enabled = true;
    d.createdAt = new Date().toISOString();
    d.action = d.action || 'delete';
    policies.push(d);
  }
  db.writeTable(policiesTable, policies);
}

module.exports = {
  getPolicies,
  savePolicy,
  deletePolicy,
  archiveData,
  getArchives,
  restoreArchive,
  deleteArchive,
  getArchiveStats,
  purgeData,
  purgeAll,
  getPurgeHistory,
  compactTable,
  vacuumDatabase,
  getTableSizes,
  addLegalHold,
  removeLegalHold,
  getLegalHolds,
  startScheduler,
  stopScheduler,
  runOnce,
  getLastRun,
  getRetentionReport,
  getStorageForecast
};
