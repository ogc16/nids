const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../lib/auth');
const { audit } = require('../lib/audit');
const wlan = require('../lib/wlan');

router.get('/wlan/report', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    audit('wlan_report_viewed', req, {});
    res.json(wlan.getWlanReport());
  } catch (err) { next(err); }
});

router.get('/wlan/access-points', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(wlan.getAccessPoints());
  } catch (err) { next(err); }
});

router.get('/wlan/clients', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(wlan.getClients());
  } catch (err) { next(err); }
});

router.get('/wlan/channels', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(wlan.getChannelMap());
  } catch (err) { next(err); }
});

router.get('/wlan/anomalies', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(wlan.getAnomalies());
  } catch (err) { next(err); }
});

router.get('/wlan/security', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(wlan.getSecurityAudit());
  } catch (err) { next(err); }
});

module.exports = router;
