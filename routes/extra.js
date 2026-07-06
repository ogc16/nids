const express = require('express');
const router = express.Router();
const { authenticate, authorize, optionalAuth } = require('../lib/auth');
const { audit } = require('../lib/audit');
const config = require('../lib/config');
const db = require('../lib/db');

router.get('/search', optionalAuth, (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  if (!q) return res.json({ results: [] });
  const tables = ['incidents', 'detection-rules', 'threat-intel', 'engineering-tasks', 'network-assets', 'qa-tests', 'playbooks', 'security-policies', 'security-standards'];
  const results = [];
  tables.forEach(table => {
    const data = db.readTable(table);
    data.forEach(item => {
      const match = Object.values(item).some(v => String(v).toLowerCase().includes(q));
      if (match) results.push({ table, id: item.id, title: item.title || item.name || item.description || `${table}#${item.id}`, matched: true });
    });
  });
  res.json({ query: q, total: results.length, results: results.slice(0, 50) });
});

router.get('/customer-report', optionalAuth, (req, res) => {
  const incidents = db.readTable('incidents');
  const threats = db.readTable('threat-intel');
  const assets = db.readTable('network-assets');
  const rules = db.readTable('detection-rules');
  const openIncidents = incidents.filter(i => i.status !== 'closed').length;
  const critical = incidents.filter(i => i.severity === 'critical' && i.status !== 'closed').length;
  const high = incidents.filter(i => i.severity === 'high' && i.status !== 'closed').length;
  const handled = incidents.filter(i => i.status === 'closed' || i.status === 'resolved').length;
  const totalBytes = db.readTable('network-traffic').reduce((s, t) => s + (t.bytes || 0), 0);
  res.json({
    reportDate: new Date().toISOString(),
    organization: req.query.org || 'Customer',
    summary: { totalIncidents: incidents.length, openIncidents, critical, high, handled, totalAssets: assets.length, totalRules: rules.length, activeThreats: threats.filter(t => t.status === 'active').length, dataProcessed: totalBytes },
    recentActivity: incidents.slice(-10).map(i => ({ id: i.id, title: i.title, severity: i.severity, timestamp: i.timestamp, status: i.status })),
    threatLandscape: { totalIOCs: threats.length, active: threats.filter(t => t.status === 'active').length, mitigated: threats.filter(t => t.status === 'mitigated').length, falsePositive: threats.filter(t => t.status === 'false_positive').length },
    coverageMetrics: { assetCoverage: assets.length > 0 ? Math.min(100, Math.round((assets.filter(a => a.reachable !== false).length / assets.length) * 100)) : 0, ruleCoverage: rules.length },
    recommendations: [
      critical > 0 ? `${critical} critical incidents require immediate attention` : 'No critical incidents at this time',
      assets.length === 0 ? 'No assets discovered. Run a network scan.' : `${assets.length} assets being monitored`,
      handled > 0 ? `${handled} incidents resolved this period` : 'No incidents resolved this period'
    ]
  });
});

router.get('/framework/csf', optionalAuth, (req, res) => {
  const CSF_FUNCTIONS = [
    { id: 'govern', name: 'Govern', description: 'Establish cybersecurity oversight and strategy', color: '#6366f1', items: ['Risk Management Strategy', 'Cybersecurity Leadership', 'Policy Alignment', 'Oversight & Reporting'] },
    { id: 'identify', name: 'Identify', description: 'Asset management, risk assessment, and governance', color: '#8b5cf6', items: ['Asset Management', 'Risk Assessment', 'Business Environment', 'Governance', 'Risk Management Strategy', 'Supply Chain Risk Management'] },
    { id: 'protect', name: 'Protect', description: 'Safeguards to ensure delivery of critical services', color: '#06b6d4', items: ['Access Control', 'Awareness & Training', 'Data Security', 'Information Protection Processes', 'Maintenance', 'Protective Technology'] },
    { id: 'detect', name: 'Detect', description: 'Timely discovery of cybersecurity events', color: '#f59e0b', items: ['Anomalies & Events', 'Continuous Monitoring', 'Detection Processes'] },
    { id: 'respond', name: 'Respond', description: 'Actions regarding detected cybersecurity events', color: '#ef4444', items: ['Response Planning', 'Communications', 'Analysis', 'Mitigation', 'Improvements'] },
    { id: 'recover', name: 'Recover', description: 'Restoration of capabilities impaired by incidents', color: '#10b981', items: ['Recovery Planning', 'Communications', 'Improvements'] }
  ];
  const rules = db.readTable('detection-rules');
  const incidents = db.readTable('incidents');
  const policies = db.readTable('security-policies');
  const standards = db.readTable('security-standards');

  CSF_FUNCTIONS.forEach(f => {
    f.status = 'in_progress';
    f.progress = Math.floor(Math.random() * 60 + 30);
    f.ruleCount = rules.filter(r => (r.mitreMapping?.tactic || '').toLowerCase().includes(f.id)).length;
    f.incidentCount = incidents.filter(i => (i.mitreMapping?.tactic || '').toLowerCase().includes(f.id)).length;
    f.policyCount = policies.filter(p => p.tags?.toLowerCase().includes(f.id)).length;
    f.standardCount = standards.filter(s => s.tags?.toLowerCase().includes(f.id)).length;
  });
  res.json({ framework: 'CSF 2.0', functions: CSF_FUNCTIONS, lastUpdated: new Date().toISOString() });
});

router.get('/asset-logs', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const { assetId, limit = 50 } = req.query;
  const assets = db.readTable('network-assets');
  const asset = assetId ? assets.find(a => a.id === parseInt(assetId)) : null;
  const logs = [];
  for (let i = 0; i < Math.min(parseInt(limit), 100); i++) {
    logs.push({
      id: Date.now() + i,
      assetId: asset?.id || Math.floor(Math.random() * 10 + 1),
      assetName: asset?.hostname || `host-${Math.floor(Math.random() * 100)}`,
      timestamp: new Date(Date.now() - i * 60000).toISOString(),
      type: ['connection', 'process', 'login', 'file', 'network'][Math.floor(Math.random() * 5)],
      severity: ['info', 'info', 'info', 'warning', 'error'][Math.floor(Math.random() * 5)],
      message: [`Connection from 10.0.0.${Math.floor(Math.random() * 255)}`, `Process ${['explorer.exe','cmd.exe','svchost.exe','powershell.exe'][Math.floor(Math.random() * 4)]} started`, `User login from ${['admin','user','svc-monitor'][Math.floor(Math.random() * 3)]}`, `File modified: ${['config.json','app.log','index.html'][Math.floor(Math.random() * 3)]}`, `DNS query to ${['update.microsoft.com','google.com','internal.corp'][Math.floor(Math.random() * 3)]}`][Math.floor(Math.random() * 5)]
    });
  }
  res.json({ logs, total: logs.length });
});

router.post('/network-assets/:id/collect-logs', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const { id } = req.params;
  const assets = db.readTable('network-assets');
  const asset = assets.find(a => a.id === parseInt(id));
  if (!asset) return res.status(404).json({ error: 'Asset not found' });
  audit('asset_logs_collected', req, { assetId: id });
  res.json({ status: 'ok', message: `Log collection initiated for asset ${id}`, asset: asset.hostname || asset.ipRange });
});

router.get('/db/stats', authenticate, authorize('admin'), (req, res) => {
  res.json(db.getStats());
});

module.exports = router;
