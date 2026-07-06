const express = require('express');
const router = express.Router();
const { authenticate, authorize, optionalAuth } = require('../lib/auth');
const { audit } = require('../lib/audit');
const vulnscan = require('../lib/vulnscan');

router.post('/vulnscan/scan', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const { targets } = req.body;
    if (!targets) return res.status(400).json({ error: 'targets (array) is required' });
    const scanId = vulnscan.startScan(targets);
    audit('vulnscan_started', req, { targets });
    res.json({ scanId, status: 'started' });
  } catch (err) { next(err); }
});

router.get('/vulnscan/scan/:scanId', authenticate, (req, res, next) => {
  try {
    const result = vulnscan.getScanStatus(req.params.scanId);
    if (!result) return res.status(404).json({ error: 'Scan not found' });
    res.json(result);
  } catch (err) { next(err); }
});

router.get('/vulnscan/scan/:scanId/results', authenticate, (req, res, next) => {
  try {
    const result = vulnscan.getScanResults(req.params.scanId);
    if (!result) return res.status(404).json({ error: 'Scan not found' });
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/vulnscan/scan/:scanId/cancel', authenticate, authorize('admin'), (req, res, next) => {
  try {
    vulnscan.cancelScan(req.params.scanId);
    audit('vulnscan_cancelled', req, { scanId: req.params.scanId });
    res.json({ status: 'cancelled' });
  } catch (err) { next(err); }
});

router.get('/vulnscan/scans', authenticate, (req, res, next) => {
  try {
    res.json(vulnscan.getScanHistory());
  } catch (err) { next(err); }
});

router.get('/vulnscan/vulnerabilities', optionalAuth, (req, res, next) => {
  try {
    const filters = {};
    if (req.query.severity) filters.severity = req.query.severity;
    if (req.query.minScore) filters.minScore = parseFloat(req.query.minScore);
    if (req.query.maxScore) filters.maxScore = parseFloat(req.query.maxScore);
    if (req.query.search) filters.search = req.query.search;
    res.json(vulnscan.getVulnerabilityReport(filters));
  } catch (err) { next(err); }
});

router.post('/vulnscan/assess-asset', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const { asset } = req.body;
    if (!asset) return res.status(400).json({ error: 'asset object is required' });
    const result = vulnscan.assessAsset(asset);
    audit('vulnscan_assessed', req, { assetId: result.assetId });
    res.json(result);
  } catch (err) { next(err); }
});

router.get('/vulnscan/report', authenticate, (req, res, next) => {
  try {
    const filters = {};
    if (req.query.severity) filters.severity = req.query.severity;
    res.json(vulnscan.getVulnerabilityReport(filters));
  } catch (err) { next(err); }
});

module.exports = router;
