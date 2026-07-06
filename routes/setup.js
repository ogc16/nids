const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../lib/auth');
const { audit } = require('../lib/audit');
const config = require('../lib/config');
const db = require('../lib/db');

router.get('/settings', authenticate, (req, res) => {
  const settings = db.readTable('settings');
  res.json(settings.length > 0 ? settings[0] : config.defaults || {});
});

router.put('/settings', authenticate, authorize('admin'), (req, res) => {
  const data = db.readTable('settings');
  const current = data.length > 0 ? data[0] : {};
  const updated = { ...current, ...req.body, updatedAt: new Date().toISOString() };
  if (data.length > 0) data[0] = updated; else data.push(updated);
  db.writeTable('settings', data);
  audit('settings_updated', req, { changes: Object.keys(req.body) });
  if (req.body.theme) { try { config.set('theme', req.body.theme); } catch {} }
  res.json(updated);
});

router.post('/seed', authenticate, authorize('admin'), (req, res) => {
  try {
    require('../lib/seed')();
    audit('data_seeded', req);
    res.json({ status: 'ok', message: 'Seed data generated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/reset', authenticate, authorize('admin'), (req, res) => {
  try {
    const tables = ['incidents', 'detection-rules', 'threat-intel', 'network-traffic', 'engineering-tasks', 'network-assets', 'qa-tests', 'playbooks', 'security-policies', 'security-standards', 'automation-logs'];
    const auditLog = db.readTable('audit-logs');
    tables.forEach(t => db.writeTable(t, []));
    audit('data_reset', req, { cleared_tables: tables });
    res.json({ status: 'ok', message: `Cleared ${tables.length} tables` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/audit-logs', authenticate, (req, res) => {
  const logs = db.readTable('audit-logs');
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(100, parseInt(req.query.limit) || 20);
  const action = req.query.action || '';
  const userId = req.query.userId || '';
  let filtered = logs;
  if (action) filtered = filtered.filter(l => l.action === action);
  if (userId) filtered = filtered.filter(l => String(l.userId) === userId);
  res.json({ items: filtered.slice((page - 1) * limit, (page - 1) * limit + limit), total: filtered.length, page, limit });
});

router.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    memory: process.memoryUsage(),
    version: config.version || '2.0.0',
    node: process.version
  });
});

router.get('/config', authenticate, authorize('admin'), (req, res) => {
  res.json(config.getAll());
});

module.exports = router;
