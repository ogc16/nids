const express = require('express');
const router = express.Router();
const { authenticate, authorize, optionalAuth } = require('../lib/auth');
const { audit } = require('../lib/audit');
const snort = require('../lib/snort');
const db = require('../lib/db');

router.get('/snort/sample-rules', optionalAuth, (req, res, next) => {
  try {
    res.json(snort.sampleRules || []);
  } catch (err) { next(err); }
});

router.get('/snort/rules', authenticate, (req, res, next) => {
  try {
    const rules = db.readTable('detection-rules');
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(500, parseInt(req.query.limit) || 100);
    const search = req.query.search || '';
    let filtered = rules;
    if (search) filtered = filtered.filter(r => r.name?.toLowerCase().includes(search.toLowerCase()) || r.description?.toLowerCase().includes(search.toLowerCase()) || r.sid?.toString().includes(search));
    res.json({ items: filtered.slice((page - 1) * limit, (page - 1) * limit + limit), total: filtered.length, page, limit });
  } catch (err) { next(err); }
});

router.post('/snort/validate', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const { rule } = req.body;
    if (!rule) return res.status(400).json({ error: 'rule string is required' });
    const result = snort.validateRule(rule);
    res.json({ valid: result.valid !== false, errors: result.errors || [] });
  } catch (err) { next(err); }
});

router.post('/snort/parse', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const { rule } = req.body;
    if (!rule) return res.status(400).json({ error: 'rule string is required' });
    const result = snort.parseRule(rule);
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/snort/convert', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const { snortRule } = req.body;
    if (!snortRule) return res.status(400).json({ error: 'snortRule is required' });
    const result = snort.convertToNidsRule(snortRule);
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/snort/correlate', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const { flow } = req.body;
    if (!flow) return res.status(400).json({ error: 'flow is required' });
    const rules = db.readTable('detection-rules');
    const result = snort.correlateAlert(flow, rules);
    res.json(result);
  } catch (err) { next(err); }
});

router.get('/snort/correlation-stats', authenticate, (req, res, next) => {
  try {
    res.json(snort.getCorrelationStats());
  } catch (err) { next(err); }
});

module.exports = router;
