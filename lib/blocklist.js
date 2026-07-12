const fs = require('fs');
const path = require('path');

const DATA_FILE = path.join(__dirname, '..', 'data', 'blocked-ips.json');
let entries = [];

function load() {
  try {
    entries = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    entries = [];
  }
}

function save() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(entries, null, 2));
}

function getAll() { return entries; }

function getBlocked() { return entries.filter(e => e.blocked); }

function getFlagged() { return entries.filter(e => !e.blocked); }

function isBlocked(ip) {
  const entry = entries.find(e => e.ip === ip);
  return entry ? entry.blocked : false;
}

function getEntry(ip) {
  return entries.find(e => e.ip === ip) || null;
}

function flag(ip, reason, severity, tags, flaggedBy) {
  const existing = entries.find(e => e.ip === ip);
  if (existing) {
    existing.reason = reason || existing.reason;
    existing.severity = severity || existing.severity;
    existing.tags = tags || existing.tags;
    existing.flaggedBy = flaggedBy || existing.flaggedBy;
    existing.flaggedAt = new Date().toISOString();
    save();
    return existing;
  }
  const entry = {
    ip,
    reason: reason || 'Flagged for investigation',
    severity: severity || 'medium',
    flaggedBy: flaggedBy || 'analyst',
    flaggedAt: new Date().toISOString(),
    blocked: false,
    blockedAt: null,
    tags: tags || [],
    hits: 0
  };
  entries.push(entry);
  save();
  return entry;
}

function block(ip) {
  const entry = entries.find(e => e.ip === ip);
  if (!entry) return null;
  entry.blocked = true;
  entry.blockedAt = new Date().toISOString();
  save();
  return entry;
}

function unblock(ip) {
  const entry = entries.find(e => e.ip === ip);
  if (!entry) return null;
  entry.blocked = false;
  entry.blockedAt = null;
  save();
  return entry;
}

function remove(ip) {
  const idx = entries.findIndex(e => e.ip === ip);
  if (idx === -1) return false;
  entries.splice(idx, 1);
  save();
  return true;
}

function incrementHits(ip) {
  const entry = entries.find(e => e.ip === ip);
  if (entry) {
    entry.hits = (entry.hits || 0) + 1;
    save();
  }
}

function getStats() {
  const blocked = entries.filter(e => e.blocked).length;
  const flagged = entries.filter(e => !e.blocked).length;
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  entries.forEach(e => { bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1; });
  const totalHits = entries.reduce((s, e) => s + (e.hits || 0), 0);
  return { total: entries.length, blocked, flagged, bySeverity, totalHits };
}

load();

module.exports = { getAll, getBlocked, getFlagged, isBlocked, getEntry, flag, block, unblock, remove, incrementHits, getStats, load };
