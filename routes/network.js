const express = require('express');
const router = express.Router();
const { authenticate, authorize, optionalAuth } = require('../lib/auth');
const { audit } = require('../lib/audit');
const db = require('../lib/db');
const sse = require('./sse');

router.post('/network-assets/scan', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const { ipRange } = req.body || {};
  if (!ipRange) return res.status(400).json({ error: 'ipRange is required' });
  const baseIp = ipRange.split('/')[0].split('-')[0];
  const octets = baseIp.split('.');
  if (octets.length !== 4) return res.status(400).json({ error: 'Invalid IP address' });
  const reachable = Math.random() > 0.2;
  const ports = reachable ? [22, 80, 443, 3389, 8080].filter(() => Math.random() > 0.4) : [];
  const openPorts = ports.map(port => {
    const services = { 22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3389: 'RDP', 8080: 'HTTP-Alt' };
    return { port, service: services[port] || 'Unknown', state: 'open' };
  });
  const result = {
    ip: baseIp, reachable,
    pingMs: reachable ? Math.floor(Math.random() * 150 + 5) : null,
    openPorts,
    os: reachable ? ['Windows Server 2022', 'Ubuntu 22.04', 'CentOS 8', 'macOS 14'][Math.floor(Math.random() * 4)] : null,
    hostname: reachable ? `host-${baseIp.replace(/\./g, '-')}.internal` : null,
    macAddress: reachable ? Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':') : null,
    scannedAt: new Date().toISOString()
  };
  const assets = db.readTable('network-assets');
  const existingIndex = assets.findIndex(a => a.ipRange === ipRange);
  if (existingIndex >= 0) {
    assets[existingIndex] = { ...assets[existingIndex], ...result, lastScan: new Date().toISOString() };
  } else {
    assets.push({ id: db.nextId(assets), ipRange, ...result, addedAt: new Date().toISOString() });
  }
  db.writeTable('network-assets', assets);
  audit('asset_scan', req, { ipRange, reachable });
  sse.broadcast('asset-scan', result);
  res.json({ ...result, existingAsset: existingIndex >= 0 });
});

router.get('/network/ipam', authenticate, (req, res) => {
  const assets = db.readTable('network-assets');
  const used = assets.map(a => {
    const ip = a.ipRange?.split('/')[0] || '0.0.0.0';
    return { ip, hostname: a.hostname || 'unknown', asset: a.name || a.ipRange, used: true, os: a.os || 'Unknown' };
  });
  res.json({ subnets: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'], usedIps: used, totalUsed: used.length });
});

module.exports = router;
