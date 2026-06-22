const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const http = require('http');

const app = express();
const PORT = 3000;
const DATA_DIR = path.join(__dirname, 'data');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const tables = ['incidents', 'detection-rules', 'threat-intel', 'engineering-tasks', 'network-assets', 'qa-tests', 'network-traffic', 'playbooks'];

function readTable(name) {
  const file = path.join(DATA_DIR, `${name}.json`);
  const raw = fs.readFileSync(file, 'utf8');
  return JSON.parse(raw);
}

function writeTable(name, data) {
  const file = path.join(DATA_DIR, `${name}.json`);
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

function nextId(data) {
  return data.reduce((max, d) => Math.max(max, d.id), 0) + 1;
}

app.get('/api/network-traffic/stats', (req, res) => {
  const traffic = readTable('network-traffic');
  const totalBytes = traffic.reduce((sum, t) => sum + t.bytes, 0);
  res.json({
    totalFlows: traffic.length,
    suspiciousCount: traffic.filter(t => t.status === 'suspicious').length,
    blockedCount: traffic.filter(t => t.status === 'blocked').length,
    allowedCount: traffic.filter(t => t.status === 'allowed').length,
    totalBytes,
    uniqueProtocols: [...new Set(traffic.map(t => t.protocol))].length
  });
});

tables.forEach(table => {
  const route = `/api/${table}`;

  app.get(route, (req, res) => {
    const data = readTable(table);
    res.json(data);
  });

  app.get(`${route}/:id`, (req, res) => {
    const data = readTable(table);
    const item = data.find(d => d.id === parseInt(req.params.id));
    if (!item) return res.status(404).json({ error: 'Not found' });
    res.json(item);
  });

  app.post(route, (req, res) => {
    const data = readTable(table);
    const item = { id: nextId(data), ...req.body };
    data.push(item);
    writeTable(table, data);

    if (table === 'incidents') {
      runAutomations('incident.created', item, data);
    }
    if (table === 'engineering-tasks') {
      runAutomations('task.created', item, data);
    }

    res.status(201).json(item);
  });

  app.put(`${route}/:id`, (req, res) => {
    const data = readTable(table);
    const idx = data.findIndex(d => d.id === parseInt(req.params.id));
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    const oldItem = { ...data[idx] };
    data[idx] = { ...data[idx], ...req.body, id: data[idx].id };
    writeTable(table, data);

    if (table === 'incidents') {
      runAutomations('incident.updated', data[idx], data, oldItem);
    }
    if (table === 'engineering-tasks') {
      runAutomations('task.updated', data[idx], data, oldItem);
    }

    res.json(data[idx]);
  });

  app.delete(`${route}/:id`, (req, res) => {
    const data = readTable(table);
    const idx = data.findIndex(d => d.id === parseInt(req.params.id));
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    data.splice(idx, 1);
    writeTable(table, data);
    res.status(204).send();
  });
});

app.get('/api/stats', (req, res) => {
  const incidents = readTable('incidents');
  const rules = readTable('detection-rules');
  const tasks = readTable('engineering-tasks');
  const assets = readTable('network-assets');

  const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  incidents.forEach(i => { severityCounts[i.severity] = (severityCounts[i.severity] || 0) + 1; });

  const statusCounts = { New: 0, Investigating: 0, Resolved: 0, Closed: 0 };
  incidents.forEach(i => { statusCounts[i.status] = (statusCounts[i.status] || 0) + 1; });

  const ruleStatusCounts = { Active: 0, 'In Development': 0, Deprecated: 0 };
  rules.forEach(r => { ruleStatusCounts[r.status] = (ruleStatusCounts[r.status] || 0) + 1; });

  const traffic = readTable('network-traffic');

  const taskStatusCounts = { 'To Do': 0, 'In Progress': 0, Done: 0 };
  tasks.forEach(t => { taskStatusCounts[t.status] = (taskStatusCounts[t.status] || 0) + 1; });

  const assetRiskCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  assets.forEach(a => { assetRiskCounts[a.riskLevel] = (assetRiskCounts[a.riskLevel] || 0) + 1; });

  const attackTypeCounts = {};
  incidents.forEach(i => { attackTypeCounts[i.attackType] = (attackTypeCounts[i.attackType] || 0) + 1; });

  const statusCountsFiltered = { New: 0, Investigating: 0, Resolved: 0, Closed: 0 };
  incidents.forEach(i => { statusCountsFiltered[i.status] = (statusCountsFiltered[i.status] || 0) + 1; });

  res.json({
    totalIncidents: incidents.length,
    openIncidents: incidents.filter(i => i.status !== 'Resolved' && i.status !== 'Closed').length,
    severityCounts,
    statusCounts: statusCountsFiltered,
    ruleStatusCounts,
    taskStatusCounts,
    assetRiskCounts,
    attackTypeCounts,
    activeRules: rules.filter(r => r.status === 'Active').length,
    openTasks: tasks.filter(t => t.status !== 'Done').length,
    criticalAssets: assets.filter(a => a.riskLevel === 'Critical').length,
    totalTrafficFlows: traffic.length,
    suspiciousTrafficFlows: traffic.filter(t => t.status === 'suspicious').length,
    blockedTrafficFlows: traffic.filter(t => t.status === 'blocked').length
  });
});

app.get('/api/customer-report', (req, res) => {
  const incidents = readTable('incidents');
  const resolved = incidents.filter(i => i.status === 'Resolved' && i.cvssScore != null);
  res.json(resolved);
});

app.get('/api/automations/log', (req, res) => {
  const logFile = path.join(DATA_DIR, 'automations-log.json');
  try {
    const raw = fs.readFileSync(logFile, 'utf8');
    res.json(JSON.parse(raw));
  } catch {
    res.json([]);
  }
});

function ipInRange(ip, range) {
  if (!range.includes('-')) return false;
  const [start, end] = range.split('-');
  const ipNum = ip.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0);
  const startNum = start.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0);
  const endNum = end.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0);
  return ipNum >= startNum && ipNum <= endNum;
}

function logAutomation(action, details) {
  const logFile = path.join(DATA_DIR, 'automations-log.json');
  let log = [];
  try {
    const raw = fs.readFileSync(logFile, 'utf8');
    log = JSON.parse(raw);
  } catch {
    log = [];
  }
  log.push({
    id: log.length + 1,
    action,
    details,
    timestamp: new Date().toISOString()
  });
  fs.writeFileSync(logFile, JSON.stringify(log, null, 2), 'utf8');
  console.log(`[Automation] ${action}: ${JSON.stringify(details)}`);
}

function runAutomations(event, item, allData, oldItem) {
  if (event === 'incident.created' || event === 'incident.updated') {
    if (item.severity === 'Critical' && item.status !== 'Resolved' && item.status !== 'Closed') {
      logAutomation('critical_severity_alert', {
        incidentId: item.id,
        title: item.title,
        message: `CRITICAL: Incident #${item.id} "${item.title}" requires immediate attention. Assigned to ${item.assignee}.`,
        severity: item.severity,
        attackType: item.attackType,
        sourceIp: item.sourceIp
      });
    }

    if (item.status === 'Resolved' && item.cvssScore != null) {
      logAutomation('incident_resolved_cvss_scored', {
        incidentId: item.id,
        title: item.title,
        cvssScore: item.cvssScore,
        message: `Incident #${item.id} resolved with CVSS score ${item.cvssScore}. Available for customer reporting.`
      });
    }

    try {
      const playbooks = readTable('playbooks');
      const matching = playbooks.filter(p =>
        p.status === 'Active' &&
        p.triggerOnAttackTypes &&
        p.triggerOnAttackTypes.includes(item.attackType)
      );
      if (matching.length > 0) {
        logAutomation('playbook_suggested', {
          incidentId: item.id,
          attackType: item.attackType,
          suggestedPlaybooks: matching.map(p => ({ id: p.id, name: p.name })),
          message: `Incident #${item.id} (${item.attackType}) matches ${matching.length} active playbook(s): ${matching.map(p => p.name).join(', ')}`
        });
      }
    } catch (err) {
      console.error('[Automation] Playbook suggestion failed:', err.message);
    }

    try {
      const assets = readTable('network-assets');
      const matchingAsset = assets.find(a =>
        item.sourceIp && a.ipRange && (
          item.sourceIp.startsWith(a.ipRange.split('/')[0].replace('.0', '')) ||
          item.sourceIp === a.ipRange.split('/')[0] ||
          (a.ipRange.includes('-') && ipInRange(item.sourceIp, a.ipRange))
        )
      );
      if (matchingAsset) {
        const openIncidents = allData.filter(i =>
          i.sourceIp && matchingAsset.ipRange && (
            i.sourceIp.startsWith(matchingAsset.ipRange.split('/')[0].replace('.0', '')) ||
            i.sourceIp === matchingAsset.ipRange.split('/')[0] ||
            (matchingAsset.ipRange.includes('-') && ipInRange(i.sourceIp, matchingAsset.ipRange))
          ) &&
          i.status !== 'Resolved' && i.status !== 'Closed'
        ).length;
        const assetIdx = assets.findIndex(a => a.id === matchingAsset.id);
        if (assetIdx !== -1) {
          assets[assetIdx].openIncidentCount = openIncidents;
          assets[assetIdx].lastIncidentDate = item.detectedAt || new Date().toISOString();
          writeTable('network-assets', assets);
          logAutomation('asset_incident_count_updated', {
            assetId: matchingAsset.id,
            assetName: matchingAsset.assetName,
            openIncidentCount: openIncidents,
            message: `Asset "${matchingAsset.assetName}" open incident count updated to ${openIncidents}`
          });
        }
      }
    } catch (err) {
      console.error('[Automation] Asset incident tracking failed:', err.message);
    }
  }

  if (event === 'task.updated' && item.status === 'Done' && item.ruleId) {
    try {
      const rules = readTable('detection-rules');
      const ruleIdx = rules.findIndex(r => r.id === item.ruleId);
      if (ruleIdx !== -1 && rules[ruleIdx].status === 'In Development') {
        rules[ruleIdx].status = 'Active';
        rules[ruleIdx].lastUpdated = new Date().toISOString().split('T')[0];
        writeTable('detection-rules', rules);
        logAutomation('ci_cd_rule_promotion', {
          taskId: item.id,
          taskName: item.taskName,
          ruleId: item.ruleId,
          ruleName: rules[ruleIdx].name,
          message: `CI/CD: Task #${item.id} "${item.taskName}" completed. Rule #${item.ruleId} "${rules[ruleIdx].name}" promoted to Active.`
        });
      }
    } catch (err) {
      console.error('[Automation] CI/CD rule promotion failed:', err.message);
    }
  }
}

app.post('/api/automations/trigger/severity-critical', (req, res) => {
  const incidents = readTable('incidents');
  const critical = incidents.filter(i => i.severity === 'Critical' && i.status !== 'Resolved' && i.status !== 'Closed');
  if (critical.length === 0) {
    return res.json({ triggered: false, message: 'No critical open incidents found' });
  }
  critical.forEach(i => {
    logAutomation('manual_critical_severity_alert', {
      incidentId: i.id,
      title: i.title,
      message: `CRITICAL ALERT: Incident #${i.id} "${i.title}" - ${i.attackType} from ${i.sourceIp}. Assigned to ${i.assignee}.`
    });
  });
  res.json({ triggered: true, count: critical.length, incidents: critical.map(i => i.id) });
});

app.post('/api/automations/trigger/resolved-asset-update', (req, res) => {
  const incidents = readTable('incidents');
  const assets = readTable('network-assets');
  const resolved = incidents.filter(i => i.status === 'Resolved');

  let updatedCount = 0;
  resolved.forEach(inc => {
    const matchingAsset = assets.find(a =>
      inc.sourceIp && a.ipRange && (
        inc.sourceIp.startsWith(a.ipRange.split('/')[0].replace('.0', '')) ||
        inc.sourceIp === a.ipRange.split('/')[0]
      )
    );
    if (matchingAsset) {
      logAutomation('resolved_asset_link', {
        incidentId: inc.id,
        assetId: matchingAsset.id,
        assetName: matchingAsset.assetName,
        message: `Resolved incident #${inc.id} linked to asset "${matchingAsset.assetName}".`
      });
      updatedCount++;
    }
  });
  res.json({ triggered: true, updatedCount, message: `${updatedCount} resolved incidents linked to assets` });
});

// Setup / Settings API
const SETTINGS_FILE = path.join(DATA_DIR, 'system-settings.json');
const PROFILE_FILE = path.join(DATA_DIR, 'operator-profile.json');

function readJsonFile(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}
function writeJsonFile(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

app.get('/api/setup/settings', (req, res) => {
  const settings = readJsonFile(SETTINGS_FILE) || {
    dashboardRefresh: 30,
    monitoringRefresh: 10,
    autoSimulate: 'off',
    maxTrafficDisplay: 100
  };
  res.json(settings);
});

app.put('/api/setup/settings', (req, res) => {
  writeJsonFile(SETTINGS_FILE, req.body);
  res.json({ status: 'ok' });
});

app.get('/api/setup/profile', (req, res) => {
  const profile = readJsonFile(PROFILE_FILE) || {
    operatorName: '',
    operatorRole: 'SOC Analyst',
    operatorTeam: ''
  };
  res.json(profile);
});

app.put('/api/setup/profile', (req, res) => {
  writeJsonFile(PROFILE_FILE, req.body);
  res.json({ status: 'ok' });
});

const SEED_DATA = {
  incidents: [
    { id: 1, title: 'Suspicious Outbound C2 Traffic', severity: 'Critical', status: 'New', attackType: 'C2 Communication', sourceIp: '10.0.1.45', assignee: 'Alice Chen', detectedAt: new Date(Date.now() - 3600000).toISOString(), description: 'Repeated beaconing to known malicious IP range', resolutionNotes: '', cvssScore: 9.8, ruleId: 1 },
    { id: 2, title: 'SQL Injection Attempt on Web App', severity: 'High', status: 'Investigating', attackType: 'SQL Injection', sourceIp: '203.0.113.50', assignee: 'Bob Martinez', detectedAt: new Date(Date.now() - 7200000).toISOString(), description: 'SQLi payload detected in login form', resolutionNotes: 'WAF blocking triggered', cvssScore: 8.5, ruleId: 2 }
  ],
  'detection-rules': [
    { id: 1, name: 'C2 Beaconing Detection', status: 'Active', severity: 'Critical', attackType: 'C2 Communication', ruleLogic: 'alert tcp any any -> any any (msg:"C2 Beaconing"; threshold:type both, track by_src, count 5, seconds 60;)', lastUpdated: '2026-06-15', createdBy: 'Bob Martinez' },
    { id: 2, name: 'SQL Injection Pattern Match', status: 'Active', severity: 'High', attackType: 'SQL Injection', ruleLogic: 'alert tcp any any -> any 80 (msg:"SQL Injection"; content:"union select"; nocase;)', lastUpdated: '2026-06-10', createdBy: 'Carol Nguyen' }
  ],
  'threat-intel': [
    { id: 1, indicator: '185.220.101.0/24', type: 'IP Range', severity: 'Critical', confidence: 95, status: 'Active', source: 'AlienVault OTX', firstSeen: '2026-05-01', lastUpdated: '2026-06-20', description: 'Known C2 infrastructure cluster', mitreTactics: ['TA0011'] }
  ],
  'engineering-tasks': [
    { id: 1, taskName: 'Implement C2 beaconing rule', status: 'In Progress', priority: 'Critical', assignee: 'Alice Chen', sprint: 'Sprint 24', ruleId: 1, description: 'Deploy the C2 detection rule to production sensors', createdAt: new Date(Date.now() - 86400000).toISOString(), dueDate: new Date(Date.now() + 86400000).toISOString() }
  ],
  'network-assets': [
    { id: 1, assetName: 'Core Web Server', ipRange: '10.0.1.0/24', type: 'Server', riskLevel: 'Critical', monitoringStatus: 'Online', owner: 'Platform Engineering', openIncidentCount: 1, lastIncidentDate: new Date().toISOString(), lastScanned: new Date(Date.now() - 86400000).toISOString() },
    { id: 2, assetName: 'Corporate Firewall', ipRange: '10.0.0.1', type: 'Firewall', riskLevel: 'High', monitoringStatus: 'Online', owner: 'Network Team', openIncidentCount: 0, lastIncidentDate: null, lastScanned: new Date(Date.now() - 172800000).toISOString() }
  ],
  'qa-tests': [
    { id: 1, testName: 'C2 Rule QA Validation', ruleId: 1, status: 'pending', testCases: ['Generate test C2 traffic', 'Verify alert fires', 'Check false positive rate'], testedBy: 'Carol Nguyen', notes: 'Awaiting test environment', createdAt: new Date(Date.now() - 86400000).toISOString() }
  ],
  'network-traffic': [
    { id: 1, srcIp: '10.0.1.45', destIp: '185.220.101.22', srcPort: 49152, destPort: 443, protocol: 'HTTPS', bytes: 45000, packets: 120, duration: 5.2, timestamp: new Date(Date.now() - 1800000).toISOString(), status: 'blocked', application: 'Web', assetId: 1, ruleId: 1, country: 'RU' }
  ],
  playbooks: [
    { id: 1, name: 'C2 Containment', category: 'Incident Response', severity: 'Critical', status: 'Active', createdBy: 'Alice Chen', description: 'Isolate and investigate C2 communication', triggerOnAttackTypes: ['C2 Communication'], steps: [{ order: 1, action: 'Isolate affected host from network', assignee: 'SOC Tier 1', duration: '5 min' }, { order: 2, action: 'Collect network flow logs', assignee: 'SOC Tier 2', duration: '15 min' }, { order: 3, action: 'Analyze C2 payload and update IOCs', assignee: 'Threat Intel', duration: '30 min' }], runCount: 3, lastRun: new Date(Date.now() - 3600000).toISOString(), createdAt: new Date(Date.now() - 604800000).toISOString() }
  ]
};

app.post('/api/setup/seed', (req, res) => {
  let count = 0;
  let tableCount = 0;
  Object.keys(SEED_DATA).forEach(table => {
    const existing = readTable(table);
    if (existing.length > 0) return;
    const items = SEED_DATA[table].map(item => ({ ...item }));
    writeTable(table, items);
    count += items.length;
    tableCount++;
  });
  res.json({ status: 'ok', message: `Loaded ${count} seed records across ${tableCount} tables` });
});

app.post('/api/setup/reset', (req, res) => {
  tables.forEach(table => {
    writeTable(table, []);
  });
  try { fs.unlinkSync(SETTINGS_FILE); } catch {}
  try { fs.unlinkSync(PROFILE_FILE); } catch {}
  try { fs.unlinkSync(path.join(DATA_DIR, 'automations-log.json')); } catch {}
  res.json({ status: 'ok', message: 'All data reset successfully' });
});

const PROTOCOLS = ['HTTPS', 'HTTP', 'DNS', 'SSH', 'SMB', 'RDP', 'TCP', 'SMTP', 'NTP', 'MODBUS'];
const APPS = ['Web', 'DNS', 'Remote Access', 'File Sharing', 'Email', 'Infrastructure', 'SCADA', 'P2P'];
const STATUSES = ['allowed', 'allowed', 'allowed', 'blocked', 'suspicious'];
const COUNTRIES = ['US', 'US', 'US', 'CN', 'RU', 'DE', 'FR', 'GB', 'NL', 'BR'];

let sseClients = [];

app.get('/api/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  res.write('data: {"type":"connected"}\n\n');
  const id = Date.now();
  const client = { id, res };
  sseClients.push(client);
  req.on('close', () => { sseClients = sseClients.filter(c => c.id !== id); });
});

function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(c => { try { c.res.write(msg); } catch {} });
}

app.post('/api/network-traffic/simulate', (req, res) => {
  const assets = readTable('network-assets');
  const asset = assets[Math.floor(Math.random() * assets.length)];
  const isExternal = Math.random() > 0.5;
  const flow = {
    id: nextId(readTable('network-traffic')),
    srcIp: isExternal ? `${Math.floor(Math.random() * 223 + 1)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}` : asset.ipRange.split('/')[0],
    destIp: isExternal ? asset.ipRange.split('/')[0] : `${Math.floor(Math.random() * 223 + 1)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
    srcPort: Math.floor(Math.random() * 60000 + 1024),
    destPort: [80, 443, 22, 53, 445, 3389, 25, 123][Math.floor(Math.random() * 8)],
    protocol: PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)],
    bytes: Math.floor(Math.random() * 10000000 + 500),
    packets: Math.floor(Math.random() * 8000 + 10),
    duration: parseFloat((Math.random() * 300 + 0.1).toFixed(1)),
    timestamp: new Date().toISOString(),
    status: STATUSES[Math.floor(Math.random() * STATUSES.length)],
    application: APPS[Math.floor(Math.random() * APPS.length)],
    assetId: asset.id,
    ruleId: Math.random() > 0.7 ? Math.floor(Math.random() * 10 + 1) : null,
    country: COUNTRIES[Math.floor(Math.random() * COUNTRIES.length)]
  };
  const traffic = readTable('network-traffic');
  traffic.push(flow);
  writeTable('network-traffic', traffic);
  broadcast('traffic-flow', flow);
  if (flow.status === 'suspicious' || flow.status === 'blocked') {
    logAutomation('realtime_traffic_alert', {
      message: `${flow.status.toUpperCase()} traffic: ${flow.srcIp}:${flow.srcPort} -> ${flow.destIp}:${flow.destPort} (${flow.protocol})`,
      srcIp: flow.srcIp,
      destIp: flow.destIp,
      protocol: flow.protocol,
      status: flow.status
    });
  }
  res.status(201).json(flow);
});

app.post('/api/network-traffic/auto-simulate', (req, res) => {
  const { interval = 5000 } = req.body || {};
  const timer = setInterval(() => {
    http.request({ method: 'POST', hostname: 'localhost', port: PORT, path: '/api/network-traffic/simulate', headers: { 'Content-Type': 'application/json' } }, r => { r.resume(); }).end();
  }, interval);
  req.on('close', () => clearInterval(timer));
  res.json({ status: 'simulation_started', interval });
});

app.listen(PORT, () => {
  console.log(`NIDS Workspace running at http://localhost:${PORT}`);
});
