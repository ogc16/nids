const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../lib/auth');
const { audit } = require('../lib/audit');
const db = require('../lib/db');

function logAutomation(type, data) {
  try {
    const logs = db.readTable('automation-logs');
    logs.push({ id: db.nextId(logs), type, data, timestamp: new Date().toISOString() });
    db.writeTable('automation-logs', logs);
  } catch {}
}

router.get('/automations/status', authenticate, (req, res) => {
  const data = db.readTable('automations');
  res.json(data.length > 0 ? data[0] : { enabled: true, autoSimulate: false, interval: 5000, webhookUrl: '', lastRun: null });
});

router.put('/automations/status', authenticate, authorize('admin'), (req, res) => {
  const data = db.readTable('automations');
  const current = data.length > 0 ? data[0] : { enabled: true, autoSimulate: false, interval: 5000, webhookUrl: '', lastRun: null };
  const updated = { ...current, ...req.body, updatedAt: new Date().toISOString() };
  if (data.length > 0) data[0] = updated; else data.push(updated);
  db.writeTable('automations', data);
  audit('automation_updated', req, { changes: Object.keys(req.body) });
  res.json(updated);
});

router.get('/automations/logs', authenticate, (req, res) => {
  const logs = db.readTable('automation-logs');
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(100, parseInt(req.query.limit) || 20);
  const type = req.query.type || '';
  const search = req.query.search || '';
  let filtered = logs;
  if (type) filtered = filtered.filter(l => l.type === type);
  if (search) filtered = filtered.filter(l => JSON.stringify(l.data).toLowerCase().includes(search.toLowerCase()));
  res.json({ items: filtered.slice((page - 1) * limit, (page - 1) * limit + limit), total: filtered.length, page, limit });
});

router.get('/automations/metrics', authenticate, (req, res) => {
  const logs = db.readTable('automation-logs');
  const typeCounts = {}; const hourly = {};
  logs.forEach(l => {
    typeCounts[l.type] = (typeCounts[l.type] || 0) + 1;
    const hour = l.timestamp ? l.timestamp.slice(0, 13) : 'unknown';
    hourly[hour] = (hourly[hour] || 0) + 1;
  });
  res.json({
    totalEvents: logs.length,
    byType: Object.entries(typeCounts).map(([type, count]) => ({ type, count })),
    hourly: Object.entries(hourly).sort((a, b) => a[0].localeCompare(b[0])).map(([hour, count]) => ({ hour, count })),
    lastEvent: logs.length > 0 ? logs[logs.length - 1] : null
  });
});

router.post('/automations/clear-logs', authenticate, authorize('admin'), (req, res) => {
  db.writeTable('automation-logs', []);
  audit('automation_logs_cleared', req);
  res.json({ status: 'ok' });
});

module.exports = { router, logAutomation };
