const express = require('express');
const router = express.Router();
const { optionalAuth, authenticate } = require('../lib/auth');
const db = require('../lib/db');

function readTable(name) { return db.readTable(name); }

router.get('/stats', optionalAuth, (req, res) => {
  const incidents = readTable('incidents');
  const rules = readTable('detection-rules');
  const traffic = readTable('network-traffic');
  const assets = readTable('network-assets');

  const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  incidents.forEach(i => { const s = i.severity; if (s && severityCounts[s] !== undefined) severityCounts[s]++; });

  const openIncidents = incidents.filter(i => (i.status || '').toLowerCase() !== 'closed').length;

  const assetRiskCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  assets.forEach(a => { const r = a.riskLevel; if (r && assetRiskCounts[r] !== undefined) assetRiskCounts[r]++; });

  const statusCounts = {};
  incidents.forEach(i => { const s = i.status || 'Unknown'; statusCounts[s] = (statusCounts[s] || 0) + 1; });

  const attackTypeCounts = {};
  incidents.forEach(i => { const t = i.attackType || 'Other'; attackTypeCounts[t] = (attackTypeCounts[t] || 0) + 1; });

  const csfIncidentCounts = { GV: 0, ID: 0, PR: 0, DE: 0, RS: 0, RC: 0 };
  incidents.forEach(i => { const f = i.csfFunction; if (f && csfIncidentCounts[f] !== undefined) csfIncidentCounts[f]++; });

  const csfRuleCounts = { GV: 0, ID: 0, PR: 0, DE: 0, RS: 0, RC: 0 };
  rules.forEach(r => { const f = r.csfFunction; if (f && csfRuleCounts[f] !== undefined) csfRuleCounts[f]++; });

  res.json({
    severityCounts,
    openIncidents,
    activeRules: rules.length,
    assetRiskCounts,
    totalTrafficFlows: traffic.length,
    suspiciousTrafficFlows: traffic.filter(t => t.status === 'suspicious' || t.status === 'alert').length,
    blockedTrafficFlows: traffic.filter(t => t.status === 'blocked').length,
    statusCounts,
    attackTypeCounts,
    csfIncidentCounts,
    csfRuleCounts
  });
});

router.get('/dashboard/stats', optionalAuth, (req, res) => {
  const data = {
    incidents: readTable('incidents'),
    rules: readTable('detection-rules'),
    traffic: readTable('network-traffic'),
    assets: readTable('network-assets'),
    threatIntel: readTable('threat-intel'),
    engineeringTasks: readTable('engineering-tasks'),
    qaTests: readTable('qa-tests'),
    playbooks: readTable('playbooks'),
    securityPolicies: readTable('security-policies'),
    securityStandards: readTable('security-standards')
  };
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const criticalIncidents = data.incidents.filter(i => i.severity === 'critical' && i.status !== 'closed');
  const highIncidents = data.incidents.filter(i => i.severity === 'high' && i.status !== 'closed');
  const recentAlerts = data.incidents.filter(i => new Date(i.timestamp) > new Date(Date.now() - 86400000)).length;
  const activeThreats = data.threatIntel.filter(t => t.status === 'active').length;
  const mitreCoverage = data.rules.filter(r => r.mitreMapping && Object.keys(r.mitreMapping).length !== 0).length;
  const totalCoverage = data.rules.length;
  const uniqueTactics = [...new Set(data.rules.filter(r => r.mitreMapping?.tactic).map(r => r.mitreMapping.tactic))];
  const openIncidents = data.incidents.filter(i => i.status !== 'closed');
  const rulesBySeverity = {};
  data.rules.forEach(r => {
    const sev = r.severity || 'medium';
    rulesBySeverity[sev] = (rulesBySeverity[sev] || 0) + 1;
  });
  const topSources = data.incidents.reduce((acc, i) => {
    const src = i.source || 'unknown';
    if (!acc[src]) acc[src] = 0;
    acc[src]++;
    return acc;
  }, {});
  const topEventTypes = data.incidents.reduce((acc, i) => {
    const type = i.eventType || i.title || 'unknown';
    if (!acc[type]) acc[type] = 0;
    acc[type]++;
    return acc;
  }, {});

  res.json({
    totalIncidents: data.incidents.length,
    criticalIncidents: criticalIncidents.length,
    highIncidents: highIncidents.length,
    openIncidents: openIncidents.length,
    recentAlerts,
    activeThreats,
    mitreCoverage: { covered: mitreCoverage, total: totalCoverage, percentage: totalCoverage > 0 ? Math.round((mitreCoverage / totalCoverage) * 100) : 0, uniqueTactics: uniqueTactics.length },
    totalRules: data.rules.length,
    totalTraffic: data.traffic.length,
    totalAssets: data.assets.length,
    totalThreatIntel: data.threatIntel.length,
    totalEngineeringTasks: data.engineeringTasks.length,
    totalQaTests: data.qaTests.length,
    totalPlaybooks: data.playbooks.length,
    totalSecurityPolicies: data.securityPolicies.length,
    totalSecurityStandards: data.securityStandards.length,
    rulesBySeverity,
    topSources: Object.entries(topSources).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, count]) => ({ name, count })),
    topEventTypes: Object.entries(topEventTypes).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, count]) => ({ name, count })),
    timestamp: now.toISOString()
  });
});

router.get('/dashboard/realtime', (req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'Access-Control-Allow-Origin': '*' });
  const id = setInterval(() => {
    const traffic = readTable('network-traffic').slice(-5);
    res.write(`data: ${JSON.stringify({ traffic })}\n\n`);
  }, 3000);
  req.on('close', () => clearInterval(id));
});

router.get('/traffic-metrics', optionalAuth, (req, res) => {
  const traffic = readTable('network-traffic');
  const timeRange = parseInt(req.query.range) || 3600000;
  const cutoff = new Date(Date.now() - timeRange).toISOString();
  const recent = traffic.filter(t => t.timestamp > cutoff);
  const protocolCounts = recent.reduce((acc, t) => {
    acc[t.protocol] = (acc[t.protocol] || 0) + 1;
    return acc;
  }, {});
  const statusCounts = recent.reduce((acc, t) => {
    acc[t.status] = (acc[t.status] || 0) + 1;
    return acc;
  }, {});
  const timeline = recent.reduce((acc, t) => {
    const minute = t.timestamp.slice(0, 16);
    if (!acc[minute]) acc[minute] = { timestamp: minute, count: 0, bytes: 0 };
    acc[minute].count++;
    acc[minute].bytes += t.bytes || 0;
    return acc;
  }, {});
  res.json({
    totalFlows: recent.length,
    protocolDistribution: Object.entries(protocolCounts).map(([protocol, count]) => ({ protocol, count, percent: recent.length > 0 ? Math.round(count / recent.length * 100) : 0 })),
    statusDistribution: Object.entries(statusCounts).map(([status, count]) => ({ status, count })),
    timeline: Object.values(timeline).sort((a, b) => a.timestamp.localeCompare(b.timestamp)),
    totalBytes: recent.reduce((sum, t) => sum + (t.bytes || 0), 0)
  });
});

router.get('/api/dashboard/incidents/mitre', optionalAuth, (req, res) => {
  const incidents = readTable('incidents');
  const mitreCounts = {};
  incidents.forEach(i => {
    const mapping = i.mitreMapping || {};
    const tactic = mapping.tactic || 'Unmapped';
    if (!mitreCounts[tactic]) mitreCounts[tactic] = { tactic, count: 0, severity: {} };
    mitreCounts[tactic].count++;
    const sev = i.severity || 'low';
    mitreCounts[tactic].severity[sev] = (mitreCounts[tactic].severity[sev] || 0) + 1;
  });
  res.json({ tactics: Object.values(mitreCounts) });
});

module.exports = router;
