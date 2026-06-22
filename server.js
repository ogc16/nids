const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

const config = require('./lib/config');
const { authenticate, optionalAuth, authorize, ROLES, seedAdminUser, loginRoute, meRoute, listUsersRoute, createUserRoute, updateUserRoute, deleteUserRoute } = require('./lib/auth');
const { validate, schemas } = require('./lib/validate');
const { audit, getAuditLog } = require('./lib/audit');
const { errorHandler, notFoundHandler, AppError, ValidationError, NotFoundError } = require('./lib/errors');
const { loadCerts } = require('./lib/tls');

const app = express();
const DATA_DIR = config.dataDir;

// Security middleware
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: config.corsOrigin, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
// Block direct .html access
app.use((req, res, next) => {
  if (req.path.endsWith('.html')) return res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
  next();
});
// Serve static files; auto-append .html for clean URLs
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

// Global rate limiting
app.use('/api/', rateLimit({ windowMs: config.rateLimitWindowMs, max: config.rateLimitMax, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests' } }));
app.use('/api/auth/', rateLimit({ windowMs: config.rateLimitWindowMs, max: config.authRateLimitMax, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many auth attempts' } }));

const tables = ['incidents', 'detection-rules', 'threat-intel', 'engineering-tasks', 'network-assets', 'qa-tests', 'network-traffic', 'playbooks', 'security-policies', 'security-standards'];

const CSF_FUNCTIONS = [
  { id: 'GV', name: 'Govern', desc: 'Establish organizational cybersecurity governance' },
  { id: 'ID', name: 'Identify', desc: 'Understand and manage cybersecurity risks' },
  { id: 'PR', name: 'Protect', desc: 'Implement safeguards to protect assets' },
  { id: 'DE', name: 'Detect', desc: 'Detect cybersecurity anomalies and events' },
  { id: 'RS', name: 'Respond', desc: 'Respond to cybersecurity incidents' },
  { id: 'RC', name: 'Recover', desc: 'Recover from cybersecurity incidents' }
];

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

// Paginated read
function readTablePaginated(name, query) {
  let data = readTable(name);
  const page = Math.max(1, parseInt(query.page) || 1);
  const limit = Math.min(config.maxPageSize, Math.max(1, parseInt(query.limit) || config.defaultPageSize));
  const total = data.length;

  if (query.search && query.searchField) {
    const terms = query.search.toLowerCase();
    data = data.filter(d => String(d[query.searchField] || '').toLowerCase().includes(terms));
  }

  const totalFiltered = data.length;
  const offset = (page - 1) * limit;
  const items = data.slice(offset, offset + limit);

  return { items, pagination: { page, limit, total, totalFiltered, totalPages: Math.ceil(totalFiltered / limit) } };
}

// ---- Auth Routes ----
app.post('/api/auth/login', validate(schemas.login), (req, res, next) => {
  try {
    audit('login_attempt', req, { username: req.body.username });
    loginRoute(req, res);
  } catch (err) { next(err); }
});
app.get('/api/auth/me', authenticate, meRoute);
app.get('/api/auth/users', authenticate, authorize('admin'), listUsersRoute);
app.post('/api/auth/users', authenticate, authorize('admin'), validate(schemas.login), createUserRoute);
app.put('/api/auth/users/:id', authenticate, authorize('admin'), updateUserRoute);
app.delete('/api/auth/users/:id', authenticate, authorize('admin'), deleteUserRoute);

// ---- Audit Log ----
app.get('/api/audit/log', authenticate, authorize('admin'), (req, res) => {
  const limit = Math.min(500, parseInt(req.query.limit) || 100);
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  res.json(getAuditLog(limit, offset));
});

// ---- Traffic stats (must be before generic :id route) ----
app.get('/api/network-traffic/stats', optionalAuth, (req, res) => {
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

// ---- Generic CRUD with Auth + Validation + Audit + Pagination ----
const WRITABLE_TABLES = ['incidents', 'detection-rules', 'threat-intel', 'engineering-tasks', 'network-assets', 'qa-tests', 'playbooks', 'security-policies', 'security-standards'];
const READONLY_TABLES = ['network-traffic'];
const ALL_TABLES = [...WRITABLE_TABLES, ...READONLY_TABLES];

ALL_TABLES.forEach(table => {
  const route = `/api/${table}`;

  // LIST with pagination
  app.get(route, optionalAuth, (req, res) => {
    const result = readTablePaginated(table, req.query);
    res.json(result);
  });

  // CSV export
  app.get(`${route}/export`, authenticate, (req, res) => {
    const data = readTable(table);
    if (data.length === 0) return res.status(404).json({ error: 'No data to export' });
    const headers = Object.keys(data[0]);
    const csv = [headers.join(','), ...data.map(row => headers.map(h => {
      const val = row[h];
      if (val === null || val === undefined) return '';
      const str = String(val);
      return str.includes(',') || str.includes('"') || str.includes('\n') ? `"${str.replace(/"/g, '""')}"` : str;
    }).join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${table}-${new Date().toISOString().split('T')[0]}.csv"`);
    res.send(csv);
  });

  // GET by ID
  app.get(`${route}/:id`, optionalAuth, (req, res) => {
    const data = readTable(table);
    const item = data.find(d => d.id === parseInt(req.params.id));
    if (!item) return res.status(404).json({ error: 'Not found' });
    res.json(item);
  });

  // CREATE
  if (table !== 'network-traffic') {
    app.post(route, authenticate, authorize('admin', 'analyst'), (req, res, next) => {
      try {
        const data = readTable(table);
        const item = { id: nextId(data), ...req.body };
        data.push(item);
        writeTable(table, data);
        audit('create', req, { table, id: item.id });

        if (table === 'incidents') runAutomations('incident.created', item, data);
        if (table === 'engineering-tasks') runAutomations('task.created', item, data);

        res.status(201).json(item);
      } catch (err) { next(err); }
    });
  }

  // UPDATE
  if (table !== 'network-traffic') {
    app.put(`${route}/:id`, authenticate, authorize('admin', 'analyst'), (req, res, next) => {
      try {
        const data = readTable(table);
        const idx = data.findIndex(d => d.id === parseInt(req.params.id));
        if (idx === -1) return res.status(404).json({ error: 'Not found' });
        const oldItem = { ...data[idx] };
        data[idx] = { ...data[idx], ...req.body, id: data[idx].id };
        writeTable(table, data);
        audit('update', req, { table, id: data[idx].id, changes: Object.keys(req.body) });

        if (table === 'incidents') runAutomations('incident.updated', data[idx], data, oldItem);
        if (table === 'engineering-tasks') runAutomations('task.updated', data[idx], data, oldItem);

        res.json(data[idx]);
      } catch (err) { next(err); }
    });
  }

  // DELETE
  if (table !== 'network-traffic') {
    app.delete(`${route}/:id`, authenticate, authorize('admin'), (req, res, next) => {
      try {
        const data = readTable(table);
        const idx = data.findIndex(d => d.id === parseInt(req.params.id));
        if (idx === -1) return res.status(404).json({ error: 'Not found' });
        data.splice(idx, 1);
        writeTable(table, data);
        audit('delete', req, { table, id: parseInt(req.params.id) });
        res.status(204).send();
      } catch (err) { next(err); }
    });
  }
});

// ---- Stats ----
app.get('/api/stats', optionalAuth, (req, res) => {
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

  const csfIncidentCounts = {};
  CSF_FUNCTIONS.forEach(csf => { csfIncidentCounts[csf.id] = 0; });
  incidents.forEach(i => { if (i.csfFunction) csfIncidentCounts[i.csfFunction] = (csfIncidentCounts[i.csfFunction] || 0) + 1; });

  const csfRuleCounts = {};
  CSF_FUNCTIONS.forEach(csf => { csfRuleCounts[csf.id] = 0; });
  rules.forEach(r => { if (r.csfFunction) csfRuleCounts[r.csfFunction] = (csfRuleCounts[r.csfFunction] || 0) + 1; });

  const policies = readTable('security-policies');
  const standards = readTable('security-standards');
  const playbooks = readTable('playbooks');

  res.json({
    totalIncidents: incidents.length,
    openIncidents: incidents.filter(i => i.status !== 'Resolved' && i.status !== 'Closed').length,
    severityCounts,
    statusCounts,
    ruleStatusCounts,
    taskStatusCounts,
    assetRiskCounts,
    attackTypeCounts,
    activeRules: rules.filter(r => r.status === 'Active').length,
    openTasks: tasks.filter(t => t.status !== 'Done').length,
    criticalAssets: assets.filter(a => a.riskLevel === 'Critical').length,
    totalTrafficFlows: traffic.length,
    suspiciousTrafficFlows: traffic.filter(t => t.status === 'suspicious').length,
    blockedTrafficFlows: traffic.filter(t => t.status === 'blocked').length,
    csfIncidentCounts,
    csfRuleCounts,
    totalPolicies: policies.length,
    totalStandards: standards.length,
    totalPlaybooks: playbooks.length
  });
});

// ---- Customer Report ----
app.get('/api/customer-report', optionalAuth, (req, res) => {
  const incidents = readTable('incidents');
  const resolved = incidents.filter(i => i.status === 'Resolved' && i.cvssScore != null);
  res.json(resolved);
});

// ---- Automations Log ----
app.get('/api/automations/log', optionalAuth, (req, res) => {
  const logFile = path.join(DATA_DIR, 'automations-log.json');
  try {
    const raw = fs.readFileSync(logFile, 'utf8');
    const data = JSON.parse(raw);
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit) || 50));
    const offset = (page - 1) * limit;
    res.json({ items: data.reverse().slice(offset, offset + limit), pagination: { page, limit, total: data.length, totalPages: Math.ceil(data.length / limit) } });
  } catch {
    res.json({ items: [], pagination: { page: 1, limit: 50, total: 0, totalPages: 0 } });
  }
});

// ---- Automations Engine ----
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
  try { const raw = fs.readFileSync(logFile, 'utf8'); log = JSON.parse(raw); } catch { log = []; }
  log.push({ id: log.length + 1, action, details, timestamp: new Date().toISOString() });
  fs.writeFileSync(logFile, JSON.stringify(log, null, 2), 'utf8');
  console.log(`[Automation] ${action}: ${JSON.stringify(details)}`);
}

function runAutomations(event, item, allData, oldItem) {
  if (event === 'incident.created' || event === 'incident.updated') {
    if (item.severity === 'Critical' && item.status !== 'Resolved' && item.status !== 'Closed') {
      logAutomation('critical_severity_alert', {
        incidentId: item.id, title: item.title,
        message: `CRITICAL: Incident #${item.id} "${item.title}" requires immediate attention. Assigned to ${item.assignee}.`,
        severity: item.severity, attackType: item.attackType, sourceIp: item.sourceIp
      });
    }
    if (item.status === 'Resolved' && item.cvssScore != null) {
      logAutomation('incident_resolved_cvss_scored', {
        incidentId: item.id, title: item.title, cvssScore: item.cvssScore,
        message: `Incident #${item.id} resolved with CVSS score ${item.cvssScore}. Available for customer reporting.`
      });
    }
    try {
      const playbooks = readTable('playbooks');
      const matching = playbooks.filter(p => p.status === 'Active' && p.triggerOnAttackTypes && p.triggerOnAttackTypes.includes(item.attackType));
      if (matching.length > 0) {
        logAutomation('playbook_suggested', {
          incidentId: item.id, attackType: item.attackType,
          suggestedPlaybooks: matching.map(p => ({ id: p.id, name: p.name })),
          message: `Incident #${item.id} (${item.attackType}) matches ${matching.length} active playbook(s): ${matching.map(p => p.name).join(', ')}`
        });
      }
    } catch (err) { console.error('[Automation] Playbook suggestion failed:', err.message); }
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
          ) && i.status !== 'Resolved' && i.status !== 'Closed'
        ).length;
        const assetIdx = assets.findIndex(a => a.id === matchingAsset.id);
        if (assetIdx !== -1) {
          assets[assetIdx].openIncidentCount = openIncidents;
          assets[assetIdx].lastIncidentDate = item.detectedAt || new Date().toISOString();
          writeTable('network-assets', assets);
          logAutomation('asset_incident_count_updated', {
            assetId: matchingAsset.id, assetName: matchingAsset.assetName,
            openIncidentCount: openIncidents,
            message: `Asset "${matchingAsset.assetName}" open incident count updated to ${openIncidents}`
          });
        }
      }
    } catch (err) { console.error('[Automation] Asset incident tracking failed:', err.message); }
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
          taskId: item.id, taskName: item.taskName, ruleId: item.ruleId, ruleName: rules[ruleIdx].name,
          message: `CI/CD: Task #${item.id} "${item.taskName}" completed. Rule #${item.ruleId} "${rules[ruleIdx].name}" promoted to Active.`
        });
      }
    } catch (err) { console.error('[Automation] CI/CD rule promotion failed:', err.message); }
  }
}

// ---- Manual Automation Triggers ----
app.post('/api/automations/trigger/severity-critical', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const incidents = readTable('incidents');
  const critical = incidents.filter(i => i.severity === 'Critical' && i.status !== 'Resolved' && i.status !== 'Closed');
  if (critical.length === 0) return res.json({ triggered: false, message: 'No critical open incidents found' });
  critical.forEach(i => {
    logAutomation('manual_critical_severity_alert', {
      incidentId: i.id, title: i.title,
      message: `CRITICAL ALERT: Incident #${i.id} "${i.title}" - ${i.attackType} from ${i.sourceIp}. Assigned to ${i.assignee}.`
    });
  });
  res.json({ triggered: true, count: critical.length, incidents: critical.map(i => i.id) });
});

app.post('/api/automations/trigger/resolved-asset-update', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const incidents = readTable('incidents');
  const assets = readTable('network-assets');
  const resolved = incidents.filter(i => i.status === 'Resolved');
  let updatedCount = 0;
  resolved.forEach(inc => {
    const matchingAsset = assets.find(a =>
      inc.sourceIp && a.ipRange && (
        inc.sourceIp.startsWith(a.ipRange.split('/')[0].replace('.0', '')) || inc.sourceIp === a.ipRange.split('/')[0]
      )
    );
    if (matchingAsset) {
      logAutomation('resolved_asset_link', { incidentId: inc.id, assetId: matchingAsset.id, assetName: matchingAsset.assetName, message: `Resolved incident #${inc.id} linked to asset "${matchingAsset.assetName}".` });
      updatedCount++;
    }
  });
  res.json({ triggered: true, updatedCount, message: `${updatedCount} resolved incidents linked to assets` });
});

// ---- Setup / Settings ----
const SETTINGS_FILE = path.join(DATA_DIR, 'system-settings.json');
const PROFILE_FILE = path.join(DATA_DIR, 'operator-profile.json');

function readJsonFile(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}
function writeJsonFile(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

app.get('/api/setup/settings', optionalAuth, (req, res) => {
  res.json(readJsonFile(SETTINGS_FILE) || { dashboardRefresh: 30, monitoringRefresh: 10, autoSimulate: 'off', maxTrafficDisplay: 100 });
});
app.put('/api/setup/settings', authenticate, (req, res) => {
  writeJsonFile(SETTINGS_FILE, req.body);
  res.json({ status: 'ok' });
});
app.get('/api/setup/profile', optionalAuth, (req, res) => {
  res.json(readJsonFile(PROFILE_FILE) || { operatorName: '', operatorRole: 'SOC Analyst', operatorTeam: '' });
});
app.put('/api/setup/profile', authenticate, (req, res) => {
  writeJsonFile(PROFILE_FILE, req.body);
  res.json({ status: 'ok' });
});

// ---- Seed Data ----
const SEED_DATA = {
  incidents: [
    { id: 1, title: 'Suspicious Outbound C2 Traffic', severity: 'Critical', status: 'New', attackType: 'C2 Communication', sourceIp: '10.0.1.45', assignee: 'Alice Chen', detectedAt: new Date(Date.now() - 3600000).toISOString(), description: 'Repeated beaconing to known malicious IP range', resolutionNotes: '', cvssScore: 9.8, ruleId: 1, csfFunction: 'DE' },
    { id: 2, title: 'SQL Injection Attempt on Web App', severity: 'High', status: 'Investigating', attackType: 'SQL Injection', sourceIp: '203.0.113.50', assignee: 'Bob Martinez', detectedAt: new Date(Date.now() - 7200000).toISOString(), description: 'SQLi payload detected in login form', resolutionNotes: 'WAF blocking triggered', cvssScore: 8.5, ruleId: 2, csfFunction: 'PR' }
  ],
  'detection-rules': [
    { id: 1, name: 'C2 Beaconing Detection', status: 'Active', severity: 'Critical', attackType: 'C2 Communication', ruleLogic: 'alert tcp any any -> any any (msg:"C2 Beaconing"; threshold:type both, track by_src, count 5, seconds 60;)', lastUpdated: '2026-06-15', createdBy: 'Bob Martinez', csfFunction: 'DE' },
    { id: 2, name: 'SQL Injection Pattern Match', status: 'Active', severity: 'High', attackType: 'SQL Injection', ruleLogic: 'alert tcp any any -> any 80 (msg:"SQL Injection"; content:"union select"; nocase;)', lastUpdated: '2026-06-10', createdBy: 'Carol Nguyen', csfFunction: 'PR' }
  ],
  'threat-intel': [
    { id: 1, indicator: '185.220.101.0/24', type: 'IP Range', severity: 'Critical', confidence: 95, status: 'Active', source: 'AlienVault OTX', firstSeen: '2026-05-01', lastUpdated: '2026-06-20', description: 'Known C2 infrastructure cluster', mitreTactics: ['TA0011'] }
  ],
  'engineering-tasks': [
    { id: 1, taskName: 'Implement C2 beaconing rule', status: 'In Progress', priority: 'Critical', assignee: 'Alice Chen', sprint: 'Sprint 24', ruleId: 1, description: 'Deploy the C2 detection rule to production sensors', createdAt: new Date(Date.now() - 86400000).toISOString(), dueDate: new Date(Date.now() + 86400000).toISOString() }
  ],
  'network-assets': [
    { id: 1, assetName: 'Core Web Server', ipRange: '10.0.1.0/24', type: 'Server', riskLevel: 'Critical', monitoringStatus: 'Online', owner: 'Platform Engineering', openIncidentCount: 1, lastIncidentDate: new Date().toISOString(), lastScanned: new Date(Date.now() - 86400000).toISOString(), description: 'Primary web server hosting customer-facing application and API endpoints. Processes PII and authentication data.', risks: [{ risk: 'Web application vulnerability exploit leading to data breach', likelihood: 'Medium', severity: 'Critical', priority: 'Critical' }, { risk: 'DDoS attack causing service unavailability', likelihood: 'High', severity: 'High', priority: 'High' }, { risk: 'Unauthorized administrative access via compromised credentials', likelihood: 'Low', severity: 'Critical', priority: 'High' }] },
    { id: 2, assetName: 'Corporate Firewall', ipRange: '10.0.0.1', type: 'Firewall', riskLevel: 'High', monitoringStatus: 'Online', owner: 'Network Team', openIncidentCount: 0, lastIncidentDate: null, lastScanned: new Date(Date.now() - 172800000).toISOString(), description: 'Perimeter firewall enforcing network segmentation and access control policies for all inbound and outbound traffic.', risks: [{ risk: 'Firewall rule misconfiguration exposing internal services', likelihood: 'Medium', severity: 'High', priority: 'High' }, { risk: 'Firmware vulnerability allowing bypass of security controls', likelihood: 'Low', severity: 'Critical', priority: 'High' }] }
  ],
  'qa-tests': [
    { id: 1, testName: 'C2 Rule QA Validation', ruleId: 1, status: 'pending', testCases: ['Generate test C2 traffic', 'Verify alert fires', 'Check false positive rate'], testedBy: 'Carol Nguyen', notes: 'Awaiting test environment', createdAt: new Date(Date.now() - 86400000).toISOString() }
  ],
  'network-traffic': [
    { id: 1, srcIp: '10.0.1.45', destIp: '185.220.101.22', srcPort: 49152, destPort: 443, protocol: 'HTTPS', bytes: 45000, packets: 120, duration: 5.2, timestamp: new Date(Date.now() - 1800000).toISOString(), status: 'blocked', application: 'Web', assetId: 1, ruleId: 1, country: 'RU' }
  ],
  playbooks: [
    { id: 1, name: 'C2 Containment', category: 'Incident Response', severity: 'Critical', status: 'Active', createdBy: 'Alice Chen', description: 'Isolate and investigate C2 communication', triggerOnAttackTypes: ['C2 Communication'], steps: [{ order: 1, action: 'Isolate affected host from network', assignee: 'SOC Tier 1', duration: '5 min' }, { order: 2, action: 'Collect network flow logs', assignee: 'SOC Tier 2', duration: '15 min' }, { order: 3, action: 'Analyze C2 payload and update IOCs', assignee: 'Threat Intel', duration: '30 min' }], runCount: 3, lastRun: new Date(Date.now() - 3600000).toISOString(), createdAt: new Date(Date.now() - 604800000).toISOString() }
  ],
  'security-policies': [
    { id: 1, name: 'Incident Response Policy', category: 'Incident Response', status: 'Active', version: '2.1', csfFunction: 'RS', description: 'All security incidents must be classified, tracked, and resolved within defined SLAs. Critical incidents require immediate escalation to SOC management.', createdBy: 'Alice Chen', lastReviewed: '2026-06-01', reviewInterval: 'Quarterly' },
    { id: 2, name: 'Access Control Policy', category: 'Access Control', status: 'Active', version: '3.0', csfFunction: 'PR', description: 'Network access must follow least-privilege principles. All administrative access requires MFA and is logged centrally.', createdBy: 'Carol Nguyen', lastReviewed: '2026-05-15', reviewInterval: 'Semi-Annual' },
    { id: 3, name: 'Logging and Monitoring Policy', category: 'Monitoring', status: 'Active', version: '1.5', csfFunction: 'DE', description: 'All network traffic, system events, and access logs must be collected, retained for 90 days, and monitored for suspicious activity.', createdBy: 'Bob Martinez', lastReviewed: '2026-04-20', reviewInterval: 'Annual' }
  ],
  'security-standards': [
    { id: 1, name: 'C2 Detection Standard', category: 'Detection', status: 'Active', version: '1.0', csfFunction: 'DE', description: 'All C2 beaconing detection rules must threshold on 5+ connections to the same external IP within 60 seconds before generating an alert.', createdBy: 'Bob Martinez', lastReviewed: '2026-06-10', framework: 'NIST SP 800-61' },
    { id: 2, name: 'Incident Severity Classification', category: 'Incident Response', status: 'Active', version: '2.0', csfFunction: 'RS', description: 'Incidents are classified as Critical (CVSS 9-10, active C2, data exfiltration), High (CVSS 7-8.9, SQLi with data access), Medium (CVSS 4-6.9, scanning), or Low (CVSS 0-3.9, policy violations).', createdBy: 'Alice Chen', lastReviewed: '2026-05-01', framework: 'NIST SP 800-61' },
    { id: 3, name: 'Asset Risk Classification Standard', category: 'Asset Management', status: 'Active', version: '1.2', csfFunction: 'ID', description: 'Network assets are classified as Critical (public-facing, contains PII), High (internal servers, AD), Medium (workstations), or Low (IoT, test devices). Classification drives monitoring and patching SLAs.', createdBy: 'Carol Nguyen', lastReviewed: '2026-03-20', framework: 'NIST SP 800-53' }
  ]
};

app.post('/api/setup/seed', authenticate, authorize('admin'), (req, res) => {
  let count = 0;
  let tableCount = 0;
  Object.keys(SEED_DATA).forEach(table => {
    const existing = readTable(table);
    if (existing.length > 0) return;
    writeTable(table, SEED_DATA[table].map(item => ({ ...item })));
    count += SEED_DATA[table].length;
    tableCount++;
  });
  res.json({ status: 'ok', message: `Loaded ${count} seed records across ${tableCount} tables` });
});

app.post('/api/setup/reset', authenticate, authorize('admin'), (req, res) => {
  WRITABLE_TABLES.forEach(table => writeTable(table, []));
  try { fs.unlinkSync(SETTINGS_FILE); } catch {}
  try { fs.unlinkSync(PROFILE_FILE); } catch {}
  try { fs.unlinkSync(path.join(DATA_DIR, 'automations-log.json')); } catch {}
  res.json({ status: 'ok', message: 'All data reset successfully' });
});

// ---- Traffic Simulation ----
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
  sseClients.push({ id, res });
  req.on('close', () => { sseClients = sseClients.filter(c => c.id !== id); });
});

function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(c => { try { c.res.write(msg); } catch {} });
}

app.post('/api/network-assets/scan', authenticate, authorize('admin', 'analyst'), (req, res) => {
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
    osHints: reachable ? ['Linux', 'Windows', 'Network Device'][Math.floor(Math.random() * 3)] : null,
    macAddress: reachable ? Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':') : null,
    hostname: reachable ? `host-${baseIp.replace(/\./g, '-')}.internal.local` : null,
    scanDuration: parseFloat((Math.random() * 2 + 0.3).toFixed(1)),
    scannedAt: new Date().toISOString()
  };

  logAutomation('asset_scan', { ipRange, reachable: result.reachable, openPortCount: result.openPorts.length, message: `Scanned ${ipRange}: ${result.reachable ? 'Reachable' : 'Unreachable'}, ${result.openPorts.length} open port(s)` });
  res.json(result);
});

// ---- Asset Log Collection ----
const LOG_SOURCES = {
  Server: {
    types: ['auth.log', 'syslog', 'web-access.log', 'app-error.log', 'audit.log'],
    samplePatterns: [
      { level: 'info', msg: 'Accepted publickey for admin from 10.0.1.10 port 22' },
      { level: 'info', msg: 'Session opened for user www-data by (uid=0)' },
      { level: 'warn', msg: 'Failed password for root from 203.0.113.50 port 22' },
      { level: 'error', msg: 'PHP Fatal error: Uncaught Exception: Connection timeout in /var/www/app/db.php:45' },
      { level: 'info', msg: 'GET /api/users 200 45ms' },
      { level: 'info', msg: 'POST /api/login 401 12ms' },
      { level: 'warn', msg: 'Rate limit exceeded for IP 198.51.100.33' },
      { level: 'error', msg: 'Database connection pool exhausted' },
      { level: 'info', msg: 'TLS handshake completed with cipher ECDHE-RSA-AES256-GCM-SHA384' },
      { level: 'warn', msg: 'Certificate will expire in 14 days' }
    ]
  },
  Firewall: {
    types: ['fw-traffic.log', 'fw-allow.log', 'fw-deny.log', 'fw-nat.log', 'fw-vpn.log'],
    samplePatterns: [
      { level: 'info', msg: 'ALLOW TCP 10.0.1.45:49152 -> 185.220.101.22:443 (8.2.1.0/24 OUT)' },
      { level: 'warn', msg: 'DENY TCP 203.0.113.50:33456 -> 10.0.1.5:22 (geo-block: CN)' },
      { level: 'info', msg: 'ALLOW UDP 10.0.1.10:53 -> 8.8.8.8:53 (DNS query)' },
      { level: 'error', msg: 'DENY TCP 198.51.100.22:44321 -> 10.0.1.5:3389 (brute-force threshold)' },
      { level: 'info', msg: 'NAT mapping 10.0.1.5:443 -> 203.0.113.10:443' },
      { level: 'warn', msg: 'VPN connection from 203.0.113.50 using expired certificate' },
      { level: 'info', msg: 'IPS signature 2024-5678 matched on flow TCP 10.0.1.45:443 -> 10.0.2.10:443' },
      { level: 'error', msg: 'Anomaly detected: 500+ SYNs/sec from 198.51.100.0/24' }
    ]
  },
  Workstation: {
    types: ['Security.evtx', 'System.evtx', 'Application.evtx', 'PowerShell-Operational.evtx'],
    samplePatterns: [
      { level: 'info', msg: 'Event 4624: An account was successfully logged on (admin@WORKSTATION-42)' },
      { level: 'warn', msg: 'Event 4648: A logon was attempted using explicit credentials' },
      { level: 'error', msg: 'Event 4688: A new process was created (cmd.exe /c net start)' },
      { level: 'info', msg: 'Event 4656: A handle to an object was requested (C:\secret.key)' },
      { level: 'warn', msg: 'Event 7036: Windows Defender real-time protection turned off' },
      { level: 'error', msg: 'Event 1001: Windows Error Reporting - svchost.exe crashed' },
      { level: 'info', msg: 'Event 6005: Event log service started' },
      { level: 'warn', msg: 'Event 5157: Windows Filtering Platform blocked connection to 185.220.101.22:443' }
    ]
  },
  Database: {
    types: ['mysql-slow.log', 'postgresql.log', 'mssql-error.log', 'audit-trail.log'],
    samplePatterns: [
      { level: 'info', msg: 'CONNECT db=app_db user=app_user host=10.0.1.10 port=5432' },
      { level: 'warn', msg: 'Slow query (2.3s): SELECT * FROM users WHERE email = ?' },
      { level: 'error', msg: 'Connection rejected from 203.0.113.50: max_connections reached' },
      { level: 'info', msg: 'QUERY: INSERT INTO audit_log (user_id, action) VALUES (42, \'login\')' },
      { level: 'warn', msg: 'Failed login for user \'sa\' from host 198.51.100.22' },
      { level: 'error', msg: 'Deadlock detected on transaction ID 84729, rolled back' }
    ]
  },
  'Network Device': {
    types: ['syslog', 'snmp-traps.log', 'config-change.log', 'interface.log'],
    samplePatterns: [
      { level: 'info', msg: 'Interface GigabitEthernet0/1 up (10.0.1.1/24)' },
      { level: 'warn', msg: 'Interface GigabitEthernet0/2 CRC errors: 1423 packets discarded' },
      { level: 'error', msg: 'BGP neighbor 10.0.255.1 state changed from ESTABLISHED to IDLE' },
      { level: 'info', msg: 'OSPF adjacency established with 10.0.255.2 (area 0)' },
      { level: 'warn', msg: 'CPU utilization at 87% for 5 minutes' },
      { level: 'info', msg: 'Configuration committed by admin from 10.0.1.10' }
    ]
  },
  Gateway: {
    types: ['gateway-access.log', 'vpn-connections.log', 'proxy.log'],
    samplePatterns: [
      { level: 'info', msg: 'VPN tunnel established to remote site 203.0.113.5 (AES-256)' },
      { level: 'warn', msg: 'VPN tunnel rekey failed, re-establishing' },
      { level: 'error', msg: 'Proxy connection to 185.220.101.22:443 blocked (category: Malware)' },
      { level: 'info', msg: 'Client 10.0.1.45 authenticated via certificate CN=alice.chen' },
      { level: 'warn', msg: 'TLS interception failed for 203.0.113.50:443 (unsupported cipher)' }
    ]
  }
};

app.post('/api/network-assets/:id/collect-logs', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const assets = readTable('network-assets');
  const asset = assets.find(a => a.id === parseInt(req.params.id));
  if (!asset) return res.status(404).json({ error: 'Asset not found' });

  const logSource = LOG_SOURCES[asset.type] || LOG_SOURCES.Server;
  const totalEvents = Math.floor(Math.random() * 5000 + 500);
  const suspiciousCount = Math.floor(Math.random() * totalEvents * 0.03 + 1);
  const warningCount = Math.floor(Math.random() * totalEvents * 0.08 + 2);
  const errorCount = Math.floor(Math.random() * totalEvents * 0.01 + 0);
  const timeRangeHours = Math.floor(Math.random() * 24 + 1);
  const collectedAt = new Date().toISOString();
  const logStart = new Date(Date.now() - timeRangeHours * 3600000).toISOString();
  const logEnd = collectedAt;

  const sampleLogs = [];
  const sampleCount = Math.min(50, totalEvents);
  for (let i = 0; i < sampleCount; i++) {
    const logType = logSource.types[Math.floor(Math.random() * logSource.types.length)];
    const pattern = logSource.samplePatterns[Math.floor(Math.random() * logSource.samplePatterns.length)];
    const timestamp = new Date(Date.now() - Math.floor(Math.random() * timeRangeHours * 3600000)).toISOString();
    const srcIp = `${Math.floor(Math.random() * 223 + 1)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
    sampleLogs.push({
      timestamp, logType, level: pattern.level,
      message: pattern.msg.replace(/\d+\.\d+\.\d+\.\d+/g, srcIp),
      srcIp
    });
  }
  sampleLogs.sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  const collection = {
    id: nextId(readTableSafe('asset-logs')),
    assetId: asset.id,
    assetName: asset.assetName,
    collectedAt,
    logSource: asset.type,
    logTypes: logSource.types,
    timeRange: { start: logStart, end: logEnd },
    summary: { totalEvents, warnings: warningCount, errors: errorCount, suspicious: suspiciousCount },
    samples: sampleLogs
  };

  const logs = readTableSafe('asset-logs');
  logs.push(collection);
  writeTable('asset-logs', logs);
  audit('logs_collected', req, { assetId: asset.id, assetName: asset.assetName, totalEvents });

  res.json(collection);
});

app.get('/api/asset-logs', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const logs = readTableSafe('asset-logs');
  const assetId = parseInt(req.query.assetId);
  let result = logs;
  if (assetId) result = logs.filter(l => l.assetId === assetId);
  res.json(result.reverse());
});

function readTableSafe(name) {
  const file = path.join(DATA_DIR, `${name}.json`);
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return []; }
}

app.post('/api/network-traffic/simulate', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const assets = readTable('network-assets');
  if (assets.length === 0) return res.status(400).json({ error: 'No assets found. Add an asset first.' });
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
  audit('traffic_simulated', req, { flowId: flow.id });
  broadcast('traffic-flow', flow);
  if (flow.status === 'suspicious' || flow.status === 'blocked') {
    logAutomation('realtime_traffic_alert', {
      message: `${flow.status.toUpperCase()} traffic: ${flow.srcIp}:${flow.srcPort} -> ${flow.destIp}:${flow.destPort} (${flow.protocol})`,
      srcIp: flow.srcIp, destIp: flow.destIp, protocol: flow.protocol, status: flow.status
    });
  }
  res.status(201).json(flow);
});

// ---- Framework/CSF ----
app.get('/api/framework/csf', optionalAuth, (req, res) => {
  const allPlaybooks = readTable('playbooks');
  const allPolicies = readTable('security-policies');
  const allStandards = readTable('security-standards');
  const csfData = CSF_FUNCTIONS.map(csf => {
    const incidents = readTable('incidents').filter(i => i.csfFunction === csf.id);
    const rules = readTable('detection-rules').filter(r => r.csfFunction === csf.id);
    const playbooks = allPlaybooks.filter(p => (p.csfFunctions && p.csfFunctions.includes(csf.id)) || p.csfFunction === csf.id);
    const policies = allPolicies.filter(p => p.csfFunction === csf.id);
    const standards = allStandards.filter(s => s.csfFunction === csf.id);
    return { ...csf, incidentCount: incidents.length, ruleCount: rules.length, playbookCount: playbooks.length, policyCount: policies.length, standardCount: standards.length };
  });
  res.json(csfData);
});

// ---- Auto Simulate ----
app.post('/api/network-traffic/auto-simulate', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const { interval = 5000 } = req.body || {};
  const timer = setInterval(() => {
    http.request({ method: 'POST', hostname: 'localhost', port: config.port, path: '/api/network-traffic/simulate', headers: { 'Content-Type': 'application/json', ...(req.headers.authorization ? { Authorization: req.headers.authorization } : {}) } }, r => { r.resume(); }).end();
  }, interval);
  req.on('close', () => clearInterval(timer));
  res.json({ status: 'simulation_started', interval });
});

// ---- Error handling ----
app.use(notFoundHandler);
app.use(errorHandler);

// ---- Start ----
seedAdminUser();

const tls = loadCerts();

if (tls) {
  https.createServer(tls, app).listen(config.https.port, config.host, () => {
    console.log(`NIDS Enterprise running at https://localhost:${config.https.port}`);
    console.log(`  Auth: POST /api/auth/login`);
    console.log(`  Default: admin:admin — CHANGE PASSWORD IMMEDIATELY`);
  });
}

app.listen(config.port, config.host, () => {
  console.log(`NIDS Enterprise running at http://localhost:${config.port}`);
  console.log(`  Auth: POST /api/auth/login`);
  console.log(`  Default: admin:admin — CHANGE PASSWORD IMMEDIATELY`);
});
