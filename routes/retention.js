const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../lib/auth');
const { audit } = require('../lib/audit');
const retention = require('../lib/retention');

router.get('/retention/policies', authenticate, (req, res, next) => {
  try {
    res.json(retention.getPolicies());
  } catch (err) { next(err); }
});

router.post('/retention/policies', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const result = retention.savePolicy(req.body);
    audit('retention_policy_created', req, { name: req.body.name });
    res.status(201).json(result);
  } catch (err) { next(err); }
});

router.delete('/retention/policies/:id', authenticate, authorize('admin'), (req, res, next) => {
  try {
    retention.deletePolicy(req.params.id);
    audit('retention_policy_deleted', req, { id: req.params.id });
    res.status(204).send();
  } catch (err) { next(err); }
});

router.get('/retention/archives', authenticate, (req, res, next) => {
  try {
    res.json(retention.getArchives());
  } catch (err) { next(err); }
});

router.get('/retention/archives/stats', authenticate, (req, res, next) => {
  try {
    res.json(retention.getArchiveStats());
  } catch (err) { next(err); }
});

router.post('/retention/archives/:id/restore', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const result = retention.restoreArchive(req.params.id);
    audit('retention_archive_restored', req, { id: req.params.id });
    res.json(result);
  } catch (err) { next(err); }
});

router.delete('/retention/archives/:id', authenticate, authorize('admin'), (req, res, next) => {
  try {
    retention.deleteArchive(req.params.id);
    audit('retention_archive_deleted', req, { id: req.params.id });
    res.status(204).send();
  } catch (err) { next(err); }
});

router.get('/retention/holds', authenticate, (req, res, next) => {
  try {
    res.json(retention.getLegalHolds());
  } catch (err) { next(err); }
});

router.post('/retention/holds', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const result = retention.addLegalHold(req.body);
    audit('retention_hold_added', req);
    res.status(201).json(result);
  } catch (err) { next(err); }
});

router.delete('/retention/holds/:id', authenticate, authorize('admin'), (req, res, next) => {
  try {
    retention.removeLegalHold(req.params.id);
    audit('retention_hold_removed', req, { id: req.params.id });
    res.status(204).send();
  } catch (err) { next(err); }
});

router.post('/retention/run', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const result = retention.runOnce();
    audit('retention_run', req);
    res.json(result);
  } catch (err) { next(err); }
});

router.get('/retention/report', authenticate, (req, res, next) => {
  try {
    res.json(retention.getRetentionReport());
  } catch (err) { next(err); }
});

router.get('/retention/storage-forecast', authenticate, (req, res, next) => {
  try {
    const days = parseInt(req.query.days) || 365;
    res.json(retention.getStorageForecast(days));
  } catch (err) { next(err); }
});

module.exports = router;
