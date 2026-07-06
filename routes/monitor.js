const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../lib/auth');
const { audit } = require('../lib/audit');
const monitor = require('../lib/monitor');

router.get('/monitor/system', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(monitor.getSystemInfo());
  } catch (err) { next(err); }
});

router.get('/monitor/connections', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(monitor.getConnections());
  } catch (err) { next(err); }
});

router.get('/monitor/ports', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(monitor.getOpenPorts());
  } catch (err) { next(err); }
});

router.get('/monitor/process/:pid', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const result = monitor.getProcessDetail(req.params.pid);
    if (!result) return res.status(404).json({ error: 'Process not found' });
    res.json(result);
  } catch (err) { next(err); }
});

router.get('/monitor/interfaces', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(monitor.getNetworkInterfaces());
  } catch (err) { next(err); }
});

router.get('/monitor/bandwidth', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(monitor.getBandwidthUsage());
  } catch (err) { next(err); }
});

router.get('/monitor/arp', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(monitor.getArpTable());
  } catch (err) { next(err); }
});

router.get('/monitor/dns-cache', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(monitor.getDnsCache());
  } catch (err) { next(err); }
});

router.get('/monitor/routing-table', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    res.json(monitor.getRoutingTable());
  } catch (err) { next(err); }
});

router.post('/monitor/scan', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const { subnet } = req.body;
    if (!subnet) return res.status(400).json({ error: 'subnet is required' });
    const result = monitor.scanNetwork(subnet);
    audit('network_scan', req, { subnet });
    res.json(result);
  } catch (err) { next(err); }
});

module.exports = router;
