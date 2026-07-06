const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../lib/auth');
const { audit } = require('../lib/audit');
const syslog = require('../lib/syslog');

router.get('/syslog', authenticate, (req, res, next) => {
  try {
    const limit = Math.min(100, parseInt(req.query.limit) || 50);
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    res.json(syslog.getCollectedLogs(limit, offset));
  } catch (err) { next(err); }
});

router.get('/syslog/stats', authenticate, (req, res, next) => {
  try {
    res.json(syslog.getLogStats());
  } catch (err) { next(err); }
});

router.get('/syslog/status', authenticate, (req, res, next) => {
  try {
    const logs = syslog.getEventLogs();
    res.json({ logs, total: logs.length });
  } catch (err) { next(err); }
});

router.post('/syslog/clear', authenticate, authorize('admin'), (req, res, next) => {
  try {
    syslog.clearLogs();
    audit('syslog_cleared', req);
    res.json({ status: 'ok' });
  } catch (err) { next(err); }
});

router.post('/syslog/forward', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });
    syslog.forwardToEndpoint(url).then(result => res.json(result)).catch(err => next(err));
  } catch (err) { next(err); }
});

router.post('/syslog/start', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const result = syslog.startSyslogServer(req.body || {});
    audit('syslog_started', req);
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/syslog/stop', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const result = syslog.stopSyslogServer();
    audit('syslog_stopped', req);
    res.json(result);
  } catch (err) { next(err); }
});

router.get('/syslog/windows-events', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const events = await syslog.getWindowsEvents(req.query);
    res.json(events);
  } catch (err) { next(err); }
});

router.get('/syslog/windows-logs', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const logs = syslog.getEventLogs();
    res.json(logs);
  } catch (err) { next(err); }
});

module.exports = router;
