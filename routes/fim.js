const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../lib/auth');
const { audit } = require('../lib/audit');
const fim = require('../lib/fim');

router.get('/fim/baseline', authenticate, (req, res, next) => {
  try {
    res.json(fim.getBaseline());
  } catch (err) { next(err); }
});

router.post('/fim/baseline', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const { paths } = req.body;
    if (!paths) return res.status(400).json({ error: 'paths (array of directories) is required' });
    const result = fim.createBaseline(paths);
    audit('fim_baseline_created', req, { paths });
    res.status(201).json(result);
  } catch (err) { next(err); }
});

router.post('/fim/baseline/add', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const { filePath } = req.body;
    if (!filePath) return res.status(400).json({ error: 'filePath is required' });
    const result = fim.addToBaseline(filePath);
    audit('fim_baseline_added', req, { filePath });
    res.status(201).json(result);
  } catch (err) { next(err); }
});

router.post('/fim/scan', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const result = fim.runScan();
    audit('fim_scan_run', req);
    res.json(result);
  } catch (err) { next(err); }
});

router.get('/fim/report', authenticate, (req, res, next) => {
  try {
    res.json(fim.getFIMReport());
  } catch (err) { next(err); }
});

router.get('/fim/scans', authenticate, (req, res, next) => {
  try {
    res.json(fim.getScanHistory());
  } catch (err) { next(err); }
});

router.get('/fim/last-scan', authenticate, (req, res, next) => {
  try {
    const result = fim.getLastScan();
    if (!result) return res.status(404).json({ error: 'No scans yet' });
    res.json(result);
  } catch (err) { next(err); }
});

router.get('/fim/config', authenticate, (req, res, next) => {
  try {
    res.json(fim.getConfig());
  } catch (err) { next(err); }
});

router.put('/fim/config', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const result = fim.saveConfig(req.body);
    audit('fim_config_updated', req);
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/fim/watch/start', authenticate, authorize('admin'), (req, res, next) => {
  try {
    fim.startWatcher(req.body?.intervalMs);
    audit('fim_watcher_started', req);
    res.json({ status: 'started' });
  } catch (err) { next(err); }
});

router.post('/fim/watch/stop', authenticate, authorize('admin'), (req, res, next) => {
  try {
    fim.stopWatcher();
    audit('fim_watcher_stopped', req);
    res.json({ status: 'stopped' });
  } catch (err) { next(err); }
});

router.delete('/fim/baseline', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const { filePath } = req.body;
    if (filePath) {
      fim.removeFromBaseline(filePath);
      audit('fim_baseline_removed', req, { filePath });
    } else {
      fim.clearBaseline();
      audit('fim_baseline_cleared', req);
    }
    res.status(204).send();
  } catch (err) { next(err); }
});

module.exports = router;
