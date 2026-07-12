const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../lib/auth');
const { audit } = require('../lib/audit');
const blocklist = require('../lib/blocklist');

router.get('/blocklist', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(blocklist.getAll());
  } catch (err) { next(err); }
});

router.get('/blocklist/stats', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(blocklist.getStats());
  } catch (err) { next(err); }
});

router.get('/blocklist/blocked', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(blocklist.getBlocked());
  } catch (err) { next(err); }
});

router.get('/blocklist/flagged', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(blocklist.getFlagged());
  } catch (err) { next(err); }
});

router.get('/blocklist/check/:ip', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const entry = blocklist.getEntry(req.params.ip);
    res.json({ ip: req.params.ip, blocked: blocklist.isBlocked(req.params.ip), entry });
  } catch (err) { next(err); }
});

router.post('/blocklist', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const { ip, reason, severity, tags } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP address is required' });
    const entry = blocklist.flag(ip, reason, severity, tags, req.user?.username || 'analyst');
    audit('ip_flagged', req, { ip, reason, severity });
    res.status(201).json(entry);
  } catch (err) { next(err); }
});

router.post('/blocklist/:ip/block', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const entry = blocklist.block(req.params.ip);
    if (!entry) return res.status(404).json({ error: 'IP not found in blocklist' });
    audit('ip_blocked', req, { ip: req.params.ip });
    res.json(entry);
  } catch (err) { next(err); }
});

router.post('/blocklist/:ip/unblock', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const entry = blocklist.unblock(req.params.ip);
    if (!entry) return res.status(404).json({ error: 'IP not found in blocklist' });
    audit('ip_unblocked', req, { ip: req.params.ip });
    res.json(entry);
  } catch (err) { next(err); }
});

router.patch('/blocklist/:ip', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const entry = blocklist.getEntry(req.params.ip);
    if (!entry) return res.status(404).json({ error: 'IP not found in blocklist' });
    const { reason, severity, tags } = req.body;
    if (reason !== undefined) entry.reason = reason;
    if (severity !== undefined) entry.severity = severity;
    if (tags !== undefined) entry.tags = tags;
    audit('ip_blocklist_updated', req, { ip: req.params.ip });
    res.json(entry);
  } catch (err) { next(err); }
});

router.delete('/blocklist/:ip', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const removed = blocklist.remove(req.params.ip);
    if (!removed) return res.status(404).json({ error: 'IP not found in blocklist' });
    audit('ip_removed_from_blocklist', req, { ip: req.params.ip });
    res.status(204).end();
  } catch (err) { next(err); }
});

module.exports = router;
