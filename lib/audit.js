const fs = require('fs');
const path = require('path');
const config = require('./config');

const AUDIT_FILE = path.join(config.dataDir, 'audit-log.jsonl');

function audit(event, req, extra = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    event,
    user: req.user ? { id: req.user.id, username: req.user.username, role: req.user.role } : { id: null, username: 'anonymous', role: null },
    ip: req.ip || req.connection?.remoteAddress,
    method: req.method,
    path: req.originalUrl || req.url,
    ...extra
  };

  try {
    fs.appendFileSync(AUDIT_FILE, JSON.stringify(entry) + '\n', 'utf8');
  } catch (err) {
    console.error('[AUDIT] Failed to write audit log:', err.message);
  }

  if (process.env.NODE_ENV !== 'production') {
    const label = entry.user.username === 'anonymous' ? '[AUDIT]' : `[AUDIT:${entry.user.username}]`;
    console.log(`${label} ${event} — ${req.method} ${req.path}`);
  }
}

function getAuditLog(limit = 100, offset = 0) {
  try {
    if (!fs.existsSync(AUDIT_FILE)) return [];
    const raw = fs.readFileSync(AUDIT_FILE, 'utf8').trim();
    if (!raw) return [];
    const lines = raw.split('\n').filter(Boolean);
    const entries = lines.map(line => JSON.parse(line));
    return entries.reverse().slice(offset, offset + limit);
  } catch {
    return [];
  }
}

module.exports = { audit, getAuditLog };
