const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const multer = require('multer');

const config = require('./lib/config');
const { authenticate, optionalAuth, authorize, ROLES, seedAdminUser, loginRoute, changePasswordRoute, meRoute, listUsersRoute, createUserRoute, updateUserRoute, deleteUserRoute, csrfProtection } = require('./lib/auth');
const { validate, schemas } = require('./lib/validate');
const { audit, getAuditLog } = require('./lib/audit');
const { errorHandler, notFoundHandler, AppError, ValidationError, NotFoundError } = require('./lib/errors');
const { loadCerts } = require('./lib/tls');
const pcap = require('./lib/pcap');
const monitor = require('./lib/monitor');
const db = require('./lib/db');
const alerting = require('./lib/alerting');
const mitre = require('./lib/mitre');
const syslog = require('./lib/syslog');
const snort = require('./lib/snort');
const agent = require('./lib/agent');
const soar = require('./lib/soar');
const fim = require('./lib/fim');
const vulnscan = require('./lib/vulnscan');
const compliance = require('./lib/compliance');
const ml = require('./lib/ml');
const retention = require('./lib/retention');

const app = express();
const DATA_DIR = config.dataDir;

const pcapUpload = multer({
  dest: pcap.PCAP_DIR,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (['.pcap', '.pcapng', '.cap'].includes(ext)) return cb(null, true);
    cb(new Error('Only .pcap, .pcapng, .cap files allowed'));
  }
});

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

// Global rate limiting (apply to all routes, not just /api/)
app.use(rateLimit({ windowMs: config.rateLimitWindowMs, max: config.rateLimitMax * 5, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests' } }));
app.use('/api/', rateLimit({ windowMs: config.rateLimitWindowMs, max: config.rateLimitMax, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests' } }));
app.use('/api/auth/', rateLimit({ windowMs: config.rateLimitWindowMs, max: config.authRateLimitMax, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many auth attempts' } }));

// CSRF protection for state-changing requests (skip login, change-password, and unauthenticated requests)
app.use('/api/', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.path.startsWith('/auth/login') || req.path.startsWith('/auth/change-password')) return next();
  // Only enforce CSRF if the request has an auth cookie (authenticated session)
  if (!req.cookies?.[config.cookieName]) return next();
  const token = req.headers['x-csrf-token'] || req.body?._csrf;
  const expected = req.cookies?.['csrf-token'];
  if (!expected || !token || token !== expected) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
});

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
  return db.readTable(name);
}

function writeTable(name, data) {
  db.writeTable(name, data);
}

function nextId(data) {
  return db.nextId(data);
}

function readTablePaginated(name, query) {
  return db.readTablePaginated(name, query);
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

// ---- Network traffic list with Wireshark display filter support ----
app.get('/api/network-traffic', optionalAuth, (req, res) => {
  let data = readTable('network-traffic');
  const filter = req.query.displayFilter || '';
  if (filter) {
    try {
      data = data.filter(item => {
        try {
          const tokens = filter.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
          return evaluateTokens(tokens, item);
        } catch { return true; }
      });
    } catch {}
  }
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(config.maxPageSize, Math.max(1, parseInt(req.query.limit) || config.defaultPageSize));
  const totalFiltered = data.length;
  const offset = (page - 1) * limit;
  const items = data.slice(offset, offset + limit);
  res.json({ items, pagination: { page, limit, total: totalFiltered, totalFiltered, totalPages: Math.ceil(totalFiltered / limit) } });
});

// ---- Web Traffic Analytics ----
function isWebFlow(f) { return f.httpMethod || (f.protocol && (f.protocol === 'HTTP' || f.protocol === 'HTTPS')); }

app.get('/api/web-traffic/summary', optionalAuth, (req, res) => {
  const traffic = readTable('network-traffic').filter(isWebFlow);
  const methodDist = {}; const statusGroups = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
  const uriCount = {}; const hostCount = {};
  traffic.forEach(f => {
    if (f.httpMethod) methodDist[f.httpMethod] = (methodDist[f.httpMethod] || 0) + 1;
    if (f.httpStatus) statusGroups[Math.floor(f.httpStatus / 100) + 'xx'] = (statusGroups[Math.floor(f.httpStatus / 100) + 'xx'] || 0) + 1;
    if (f.httpUri) uriCount[f.httpUri] = (uriCount[f.httpUri] || 0) + 1;
    if (f.httpHost) hostCount[f.httpHost] = (hostCount[f.httpHost] || 0) + 1;
  });
  const topUris = Object.entries(uriCount).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([uri, count]) => ({ uri, count }));
  const topHosts = Object.entries(hostCount).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([host, count]) => ({ host, count }));
  const errorCount = (statusGroups['4xx'] || 0) + (statusGroups['5xx'] || 0);
  const total = traffic.length;
  res.json({
    totalRequests: total,
    methodDistribution: Object.entries(methodDist).map(([method, count]) => ({ method, count })),
    statusCodeGroups: statusGroups,
    topUris,
    topHosts,
    errorRate: total > 0 ? parseFloat((errorCount / total * 100).toFixed(1)) : 0,
    uniqueUris: Object.keys(uriCount).length,
    uniqueHosts: Object.keys(hostCount).length
  });
});

app.get('/api/web-traffic/requests', optionalAuth, (req, res) => {
  let data = readTable('network-traffic').filter(isWebFlow);
  const filter = req.query.displayFilter || '';
  if (filter) {
    try {
      data = data.filter(item => {
        try {
          const tokens = filter.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
          return evaluateTokens(tokens, item);
        } catch { return true; }
      });
    } catch {}
  }
  const method = req.query.method || ''; const status = req.query.status || '';
  const search = req.query.search || '';
  if (method) data = data.filter(f => f.httpMethod === method);
  if (status) data = data.filter(f => String(f.httpStatus).startsWith(status));
  if (search) data = data.filter(f => (f.httpUri || '').toLowerCase().includes(search) || (f.httpHost || '').toLowerCase().includes(search) || String(f.httpStatus).includes(search));
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(config.maxPageSize, Math.max(1, parseInt(req.query.limit) || config.defaultPageSize));
  const totalFiltered = data.length;
  const offset = (page - 1) * limit;
  const items = data.slice(offset, offset + limit);
  res.json({ items, pagination: { page, limit, total: totalFiltered, totalFiltered, totalPages: Math.ceil(totalFiltered / limit) } });
});

app.get('/api/web-traffic/top-uris', optionalAuth, (req, res) => {
  const traffic = readTable('network-traffic').filter(isWebFlow);
  const uriCount = {};
  traffic.forEach(f => { if (f.httpUri) uriCount[f.httpUri] = (uriCount[f.httpUri] || 0) + 1; });
  const top = Object.entries(uriCount).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([uri, count]) => ({ uri, count }));
  res.json(top);
});

app.get('/api/web-traffic/top-hosts', optionalAuth, (req, res) => {
  const traffic = readTable('network-traffic').filter(isWebFlow);
  const hostCount = {};
  traffic.forEach(f => { if (f.httpHost) hostCount[f.httpHost] = (hostCount[f.httpHost] || 0) + 1; });
  const top = Object.entries(hostCount).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([host, count]) => ({ host, count }));
  res.json(top);
});

app.get('/api/web-traffic/errors', optionalAuth, (req, res) => {
  const traffic = readTable('network-traffic').filter(isWebFlow);
  const errors = traffic.filter(f => f.httpStatus && f.httpStatus >= 400);
  const byUri = {}; const byCode = {};
  errors.forEach(f => {
    const uri = f.httpUri || '/unknown';
    if (!byUri[uri]) byUri[uri] = { uri, total: 0, '4xx': 0, '5xx': 0 };
    byUri[uri].total++;
    if (f.httpStatus >= 500) byUri[uri]['5xx']++; else byUri[uri]['4xx']++;
    const codeStr = String(f.httpStatus);
    byCode[codeStr] = (byCode[codeStr] || 0) + 1;
  });
  res.json({
    totalErrors: errors.length,
    errorRate: traffic.length > 0 ? parseFloat((errors.length / traffic.length * 100).toFixed(1)) : 0,
    byUri: Object.values(byUri).sort((a, b) => b.total - a.total).slice(0, 20),
    byCode: Object.entries(byCode).sort((a, b) => b[1] - a[1]).map(([code, count]) => ({ code: parseInt(code), count }))
  });
});

// ---- Generic CRUD with Auth + Validation + Audit + Pagination ----
const WRITABLE_TABLES = ['incidents', 'detection-rules', 'threat-intel', 'engineering-tasks', 'network-assets', 'qa-tests', 'playbooks', 'security-policies', 'security-standards'];
const READONLY_TABLES = ['network-traffic'];
const ALL_TABLES = [...WRITABLE_TABLES, ...READONLY_TABLES];

ALL_TABLES.forEach(table => {
  const route = `/api/${table}`;

  // LIST with pagination (custom handler for network-traffic with Wireshark filter support)
  if (table === 'network-traffic') {
    // Custom route is registered before this loop
  } else {
    app.get(route, optionalAuth, (req, res) => {
      const result = readTablePaginated(table, req.query);
      res.json(result);
    });
  }

  // CSV export
  app.get(`${route}/export`, authenticate, (req, res) => {
    const data = readTable(table);
    if (data.length === 0) return res.status(404).json({ error: 'No data to export' });
    const headers = Object.keys(data[0]);
    const csv = [headers.join(','), ...data.map(row => headers.map(h => {
      const val = row[h];
      if (val === null || val === undefined) return '';
      let str = String(val);
      if (['=', '+', '-', '@', '\t'].includes(str[0])) str = "'" + str;
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
    { id: 1, srcIp: '10.0.1.45', destIp: '185.220.101.22', srcPort: 49152, destPort: 443, protocol: 'HTTPS', bytes: 45000, packets: 120, duration: 5.2, timestamp: new Date(Date.now() - 1800000).toISOString(), status: 'blocked', application: 'Web', assetId: 1, ruleId: 1, country: 'RU', httpMethod: null, httpUri: null, httpStatus: null, httpHost: null, httpUserAgent: null, httpContentType: null },
    { id: 2, srcIp: '10.0.1.10', destIp: '10.0.1.5', srcPort: 52001, destPort: 80, protocol: 'HTTP', bytes: 2500, packets: 8, duration: 0.4, timestamp: new Date(Date.now() - 60000).toISOString(), status: 'allowed', application: 'Web', assetId: 1, ruleId: null, country: 'US', httpMethod: 'GET', httpUri: '/api/dashboard', httpStatus: 200, httpHost: 'app.internal.local', httpUserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125', httpContentType: 'application/json' },
    { id: 3, srcIp: '203.0.113.50', destIp: '10.0.1.5', srcPort: 33456, destPort: 80, protocol: 'HTTP', bytes: 420, packets: 3, duration: 0.1, timestamp: new Date(Date.now() - 120000).toISOString(), status: 'blocked', application: 'Web', assetId: 1, ruleId: 2, country: 'CN', httpMethod: 'POST', httpUri: '/api/auth/login', httpStatus: 401, httpHost: 'api.internal.local', httpUserAgent: 'python-requests/2.31', httpContentType: 'application/json' },
    { id: 4, srcIp: '10.0.1.20', destIp: '10.0.1.5', srcPort: 52002, destPort: 80, protocol: 'HTTP', bytes: 12000, packets: 35, duration: 2.1, timestamp: new Date(Date.now() - 300000).toISOString(), status: 'allowed', application: 'Web', assetId: 1, ruleId: null, country: 'US', httpMethod: 'GET', httpUri: '/api/incidents', httpStatus: 200, httpHost: 'app.internal.local', httpUserAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14) Safari/17', httpContentType: 'application/json' },
    { id: 5, srcIp: '10.0.1.45', destIp: '10.0.1.5', srcPort: 52003, destPort: 443, protocol: 'HTTPS', bytes: 89000, packets: 210, duration: 8.5, timestamp: new Date(Date.now() - 900000).toISOString(), status: 'allowed', application: 'Web', assetId: 1, ruleId: null, country: 'US', httpMethod: 'POST', httpUri: '/api/reports/generate', httpStatus: 200, httpHost: 'app.internal.local', httpUserAgent: 'Mozilla/5.0 (X11; Linux x86_64) Firefox/126', httpContentType: 'application/json' },
    { id: 6, srcIp: '198.51.100.33', destIp: '10.0.1.5', srcPort: 44001, destPort: 80, protocol: 'HTTP', bytes: 180, packets: 2, duration: 0.05, timestamp: new Date(Date.now() - 45000).toISOString(), status: 'blocked', application: 'Web', assetId: 1, ruleId: null, country: 'DE', httpMethod: 'GET', httpUri: '/admin/config.php', httpStatus: 404, httpHost: 'app.internal.local', httpUserAgent: 'curl/8.4', httpContentType: 'text/html' },
    { id: 7, srcIp: '10.0.1.10', destIp: '8.8.8.8', srcPort: 53, destPort: 53, protocol: 'DNS', bytes: 120, packets: 2, duration: 0.03, timestamp: new Date(Date.now() - 5000).toISOString(), status: 'allowed', application: 'DNS', assetId: 1, ruleId: null, country: 'US', httpMethod: null, httpUri: null, httpStatus: null, httpHost: null, httpUserAgent: null, httpContentType: null }
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

const HTTP_METHODS = ['GET', 'GET', 'GET', 'GET', 'POST', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'];
const HTTP_URIS = ['/api/users', '/api/incidents', '/api/dashboard', '/login', '/api/search', '/index.html', '/api/assets', '/api/reports', '/api/settings', '/api/auth/login', '/api/traffic', '/api/rules', '/api/threat-intel', '/api/tasks', '/css/styles.css', '/js/app.js', '/api/health', '/api/metrics'];
const HTTP_STATUSES = [200, 200, 200, 200, 200, 200, 200, 201, 301, 302, 304, 400, 401, 403, 404, 404, 404, 500, 502, 503];
const HTTP_HOSTS = ['app.internal.local', 'api.internal.local', 'dashboard.internal.local', 'login.internal.local', 'cdn.internal.local', 's3.internal.local'];
const HTTP_USER_AGENTS = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14) Safari/17', 'curl/8.4', 'python-requests/2.31', 'Mozilla/5.0 (X11; Linux x86_64) Firefox/126', 'Go-http-client/2.0'];
const HTTP_CONTENT_TYPES = ['application/json', 'text/html', 'text/css', 'application/javascript', 'image/png', 'application/octet-stream', 'text/plain', 'multipart/form-data'];

let sseClients = [];

app.get('/api/events', authenticate, (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  res.write('data: {"type":"connected"}\n\n');
  const id = Date.now();
  sseClients.push({ id, res, user: req.user });
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
  return db.readTableSafe(name);
}

function generateHttpFields(protocol) {
  if (protocol !== 'HTTP' && protocol !== 'HTTPS') {
    return { httpMethod: null, httpUri: null, httpStatus: null, httpHost: null, httpUserAgent: null, httpContentType: null };
  }
  const method = HTTP_METHODS[Math.floor(Math.random() * HTTP_METHODS.length)];
  const uri = HTTP_URIS[Math.floor(Math.random() * HTTP_URIS.length)];
  const statuses = method === 'POST' ? [200, 201, 400, 401, 500] : method === 'DELETE' ? [200, 204, 404, 500] : method === 'PUT' ? [200, 201, 400, 500] : [200, 200, 200, 200, 200, 200, 200, 201, 301, 302, 304, 400, 401, 403, 404, 404, 404, 500, 502, 503];
  return {
    httpMethod: method,
    httpUri: uri,
    httpStatus: statuses[Math.floor(Math.random() * statuses.length)],
    httpHost: HTTP_HOSTS[Math.floor(Math.random() * HTTP_HOSTS.length)],
    httpUserAgent: HTTP_USER_AGENTS[Math.floor(Math.random() * HTTP_USER_AGENTS.length)],
    httpContentType: HTTP_CONTENT_TYPES[Math.floor(Math.random() * HTTP_CONTENT_TYPES.length)]
  };
}

app.post('/api/network-traffic/simulate', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const assets = readTable('network-assets');
  if (assets.length === 0) return res.status(400).json({ error: 'No assets found. Add an asset first.' });
  const asset = assets[Math.floor(Math.random() * assets.length)];
  const isExternal = Math.random() > 0.5;
  const protocol = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
  const flow = {
    id: nextId(readTable('network-traffic')),
    srcIp: isExternal ? `${Math.floor(Math.random() * 223 + 1)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}` : asset.ipRange.split('/')[0],
    destIp: isExternal ? asset.ipRange.split('/')[0] : `${Math.floor(Math.random() * 223 + 1)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
    srcPort: Math.floor(Math.random() * 60000 + 1024),
    destPort: protocol === 'HTTP' ? 80 : protocol === 'HTTPS' ? 443 : [22, 53, 445, 3389, 25, 123, 8080, 8443][Math.floor(Math.random() * 8)],
    protocol,
    bytes: Math.floor(Math.random() * 10000000 + 500),
    packets: Math.floor(Math.random() * 8000 + 10),
    duration: parseFloat((Math.random() * 300 + 0.1).toFixed(1)),
    timestamp: new Date().toISOString(),
    status: STATUSES[Math.floor(Math.random() * STATUSES.length)],
    application: APPS[Math.floor(Math.random() * APPS.length)],
    assetId: asset.id,
    ruleId: Math.random() > 0.7 ? Math.floor(Math.random() * 10 + 1) : null,
    country: COUNTRIES[Math.floor(Math.random() * COUNTRIES.length)],
    ...generateHttpFields(protocol)
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

// ---- PCAP Capture & Analysis ----
pcap.ensurePcapDir();

app.post('/api/pcap/upload', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  pcapUpload.single('pcap')(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    try {
      const ext = path.extname(req.file.originalname);
      const newName = `capture-${Date.now()}${ext}`;
      const newPath = path.join(pcap.PCAP_DIR, newName);
      fs.renameSync(req.file.path, newPath);
      const stats = fs.statSync(newPath);
      let meta = { packets: null, duration: null, protocols: [] };
      if (pcap.isTsharkAvailable()) {
        try {
          const count = await pcap.tsharkRaw(['-r', newPath, '-T', 'fields', '-e', 'frame.number']);
          meta.packets = count.split('\n').filter(l => l.trim()).length;
          const phs = await pcap.tsharkRaw(['-r', newPath, '-z', 'io,phs']);
          const protoMatch = phs.match(/([A-Z]+)\s+[\d.]+%/g);
          if (protoMatch) meta.protocols = protoMatch.map(m => m.split(/\s+/)[0]);
        } catch {}
      }
      const record = pcap.createCaptureRecord(newName, req.file.originalname, stats.size, meta);
      audit('pcap_upload', req, { id: record.id, originalName: req.file.originalname, size: stats.size, packets: meta.packets });
      res.status(201).json(record);
    } catch (e) { next(e); }
  });
});

app.get('/api/pcap/captures', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const captures = pcap.readMeta().reverse();
  res.json({ items: captures, total: captures.length });
});

app.get('/api/pcap/captures/:id', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const record = await pcap.getCaptureMetadata(req.params.id);
    res.json(record);
  } catch (e) { next(new NotFoundError('Capture')); }
});

app.delete('/api/pcap/captures/:id', authenticate, authorize('admin'), async (req, res, next) => {
  try {
    const { record, filePath } = await pcap.getPcapFile(req.params.id);
    fs.unlinkSync(filePath);
    const meta = pcap.readMeta();
    pcap.writeMeta(meta.filter(m => m.id !== parseInt(req.params.id)));
    audit('pcap_delete', req, { id: parseInt(req.params.id), originalName: record.originalName });
    res.status(204).send();
  } catch (e) { next(new NotFoundError('Capture')); }
});

app.get('/api/pcap/captures/:id/analysis/protocols', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const data = await pcap.getProtocolHierarchy(req.params.id);
    res.json(data);
  } catch (e) { next(e); }
});

app.get('/api/pcap/captures/:id/analysis/endpoints', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const type = req.query.type || 'ip';
    const data = await pcap.getEndpoints(req.params.id, type);
    res.json(data);
  } catch (e) { next(e); }
});

app.get('/api/pcap/captures/:id/analysis/conversations', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const type = req.query.type || 'ip';
    const data = await pcap.getConversations(req.params.id, type);
    res.json(data);
  } catch (e) { next(e); }
});

app.get('/api/pcap/captures/:id/packets', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const filter = req.query.filter || '';
    const limit = Math.min(500, parseInt(req.query.limit) || 200);
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    const data = await pcap.getPackets(req.params.id, filter, limit, offset);
    res.json(data);
  } catch (e) { next(e); }
});

app.get('/api/pcap/captures/:id/export', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const { record, filePath } = await pcap.getPcapFile(req.params.id);
    res.download(filePath, record.originalName);
  } catch (e) { next(new NotFoundError('Capture')); }
});

app.get('/api/pcap/captures/:id/analysis/http', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const data = await pcap.getHttpAnalysis(req.params.id);
    res.json(data);
  } catch (e) { next(e); }
});

// ---- Web Traffic Export ----
app.get('/api/web-traffic/export', authenticate, (req, res) => {
  const data = readTable('network-traffic').filter(f => f.httpMethod);
  if (data.length === 0) return res.status(404).json({ error: 'No web traffic data' });
  const headers = ['timestamp','srcIp','destIp','srcPort','destPort','protocol','httpMethod','httpUri','httpStatus','httpHost','httpUserAgent','httpContentType','bytes','duration','status'];
  const csv = [headers.join(','), ...data.map(row => headers.map(h => {
    const val = row[h];
    if (val === null || val === undefined) return '';
    let str = String(val);
    if (['=', '+', '-', '@', '\t'].includes(str[0])) str = "'" + str;
    return str.includes(',') || str.includes('"') || str.includes('\n') ? `"${str.replace(/"/g, '""')}"` : str;
  }).join(','))].join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="web-traffic-${new Date().toISOString().split('T')[0]}.csv"`);
  res.send(csv);
});

// ---- Live Capture ----
app.get('/api/capture/interfaces', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    if (!pcap.isTsharkAvailable()) return res.json({ available: false, interfaces: [] });
    const interfaces = await pcap.listInterfaces();
    res.json({ available: true, interfaces });
  } catch (e) { next(e); }
});

app.post('/api/capture/start', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const { interface: iface, duration = 30, filter = '' } = req.body || {};
    if (!iface) return res.status(400).json({ error: 'interface is required' });
    const captureId = await pcap.startLiveCapture(iface, parseInt(duration), filter);
    audit('capture_start', req, { interface: iface, duration, filter });
    res.status(201).json({ captureId, interface: iface, duration, filter, startedAt: new Date().toISOString() });
  } catch (e) { next(e); }
});

app.post('/api/capture/stop', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const { captureId } = req.body || {};
    if (!captureId) return res.status(400).json({ error: 'captureId is required' });
    pcap.stopLiveCapture(captureId);
    audit('capture_stop', req, { captureId });
    res.json({ status: 'stopped', captureId });
  } catch (e) { next(e); }
});

app.get('/api/capture/active', authenticate, authorize('admin', 'analyst'), (req, res) => {
  res.json(pcap.getActiveCaptures());
});

// ---- Display Filter Validation & Filtering ----
app.post('/api/pcap/validate-filter', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const { filter } = req.body || {};
    const result = await pcap.validateDisplayFilter(filter);
    res.json(result);
  } catch (e) { next(e); }
});



function evaluateTokens(tokens, item) {
  let result = true;
  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i];
    if (token === '(') {
      const subTokens = [];
      let depth = 1;
      i++;
      while (i < tokens.length && depth > 0) {
        if (tokens[i] === '(') depth++;
        else if (tokens[i] === ')') { depth--; if (depth === 0) break; }
        subTokens.push(tokens[i]);
        i++;
      }
      const subResult = evaluateTokens(subTokens, item);
      if (i < tokens.length - 1 && (tokens[i + 1] === '&&' || tokens[i + 1] === 'and')) { result = result && subResult; i += 2; }
      else if (i < tokens.length - 1 && (tokens[i + 1] === '||' || tokens[i + 1] === 'or')) { result = result || subResult; i += 2; }
      else result = result && subResult;
    } else if (token === '!' || token === 'not') {
      i++;
      const negResult = evaluateTokens([tokens[i]], item);
      result = result && !negResult;
      i++;
    } else if (token === '&&' || token === 'and' || token === '||' || token === 'or') {
      i++;
    } else {
      const exprResult = evaluateSingleExpr(token, item);
      if (i < tokens.length - 1 && (tokens[i + 1] === '&&' || tokens[i + 1] === 'and')) { result = result && exprResult; i += 2; }
      else if (i < tokens.length - 1 && (tokens[i + 1] === '||' || tokens[i + 1] === 'or')) { result = result || exprResult; i += 2; }
      else { result = result && exprResult; i++; }
    }
  }
  return result;
}

function safeRegexTest(pattern, str, timeoutMs = 1000) {
  return new Promise((resolve) => {
    let result = false;
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; resolve(false); }, timeoutMs);
    try {
      const re = new RegExp(pattern, 'i');
      const testStr = String(str);
      const run = () => { if (!timedOut) { result = re.test(testStr); clearTimeout(timer); resolve(result); } };
      if (typeof setImmediate === 'function') setImmediate(run);
      else run();
    } catch { clearTimeout(timer); resolve(false); }
  });
}

function evaluateSingleExpr(token, item) {
  const match = token.match(/^([\w.]+)\s*([!=<>]+|contains|matches)\s*(.+)$/i);
  if (!match) {
    if (token.startsWith('!')) return !evaluateSingleExpr(token.slice(1), item);
    return false;
  }
  const [, field, operator, valueRaw] = match;
  const value = valueRaw.replace(/^"|"$/g, '').toLowerCase();
  const fieldValue = getNidsFieldValue(field, item);
  if (fieldValue === null || fieldValue === undefined) return false;
  const strVal = String(fieldValue).toLowerCase();
  switch (operator) {
    case '==': return strVal === value;
    case '!=': return strVal !== value;
    case '>': return parseFloat(strVal) > parseFloat(value);
    case '<': return parseFloat(strVal) < parseFloat(value);
    case '>=': return parseFloat(strVal) >= parseFloat(value);
    case '<=': return parseFloat(strVal) <= parseFloat(value);
    case 'contains': return strVal.includes(value);
    case 'matches':
      try {
        const re = new RegExp(value, 'i');
        const timeoutId = setTimeout(() => { throw new Error('Regex timeout'); }, 1000);
        const result = re.test(strVal);
        clearTimeout(timeoutId);
        return result;
      } catch { return false; }
    default: return true;
  }
}

function getNidsFieldValue(field, item) {
  const map = {
    'ip.src': 'srcIp', 'ip.dst': 'destIp', 'ip.addr': null,
    'tcp.srcport': 'srcPort', 'tcp.dstport': 'destPort',
    'udp.srcport': 'srcPort', 'udp.dstport': 'destPort',
    'frame.len': 'bytes', 'frame.protocols': 'protocol', 'ip.proto': 'protocol',
    'http.method': 'httpMethod', 'http.request.method': 'httpMethod',
    'http.uri': 'httpUri', 'http.request.uri': 'httpUri',
    'http.status': 'httpStatus', 'http.response.code': 'httpStatus',
    'http.host': 'httpHost', 'http.user_agent': 'httpUserAgent',
    'http.content_type': 'httpContentType'
  };
  if (field === 'ip.addr') return `${item.srcIp} ${item.destIp}`;
  if (field === 'tcp.port') return `${item.srcPort} ${item.destPort}`;
  const mapped = map[field];
  if (mapped && item[mapped] !== undefined) return item[mapped];
  if (item[field] !== undefined) return item[field];
  return null;
}

// ---- TShark status ----
app.get('/api/pcap/status', authenticate, (req, res) => {
  res.json({
    tsharkAvailable: pcap.isTsharkAvailable(),
    captureCount: pcap.readMeta().length
  });
});

// ---- Real Host Monitoring ----
app.get('/api/monitor/connections', authenticate, authorize('admin', 'analyst'), (req, res) => {
  try {
    const connections = monitor.getConnections();
    res.json(Array.isArray(connections) ? connections : []);
  } catch (err) {
    res.json([]);
  }
});

app.get('/api/monitor/ports', authenticate, authorize('admin', 'analyst'), (req, res) => {
  try {
    const ports = monitor.getOpenPorts();
    res.json(Array.isArray(ports) ? ports : []);
  } catch (err) {
    res.json([]);
  }
});

app.get('/api/monitor/process/:pid', authenticate, authorize('admin', 'analyst'), (req, res) => {
  try {
    const detail = monitor.getProcessDetail(req.params.pid);
    res.json(detail || { error: 'Process not found' });
  } catch (err) {
    res.json({ error: err.message });
  }
});

app.get('/api/monitor/interfaces', authenticate, authorize('admin', 'analyst'), (req, res) => {
  try {
    const ifaces = monitor.getTrafficStats();
    res.json(Array.isArray(ifaces) ? ifaces : []);
  } catch (err) {
    res.json([]);
  }
});

app.get('/api/monitor/system', authenticate, authorize('admin', 'analyst'), (req, res) => {
  try {
    const info = monitor.getSystemInfo();
    res.json(info || {});
  } catch (err) {
    res.json({ error: err.message });
  }
});

app.get('/api/monitor/bandwidth', authenticate, authorize('admin', 'analyst'), (req, res) => {
  try {
    const bw = monitor.getBandwidthUsage();
    res.json(Array.isArray(bw) ? bw : []);
  } catch (err) {
    res.json([]);
  }
});

app.get('/api/monitor/arp', authenticate, authorize('admin', 'analyst'), (req, res) => {
  try {
    const arp = monitor.getArpTable();
    res.json(Array.isArray(arp) ? arp : []);
  } catch (err) {
    res.json([]);
  }
});

app.get('/api/monitor/dns-cache', authenticate, authorize('admin', 'analyst'), (req, res) => {
  try {
    const cache = monitor.getDnsCache();
    res.json(Array.isArray(cache) ? cache : []);
  } catch (err) {
    res.json([]);
  }
});

app.get('/api/monitor/routing-table', authenticate, authorize('admin', 'analyst'), (req, res) => {
  try {
    const routes = monitor.getRoutingTable();
    res.json(Array.isArray(routes) ? routes : []);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/monitor/scan', authenticate, authorize('admin', 'analyst'), (req, res) => {
  try {
    const { subnet } = req.body || {};
    if (!subnet) return res.status(400).json({ error: 'subnet is required (e.g. 192.168.1.0/24)' });
    const base = subnet.split('/')[0].split('.').slice(0, 3).join('.') + '.0';
    const devices = monitor.scanNetwork(base);
    res.json(Array.isArray(devices) ? devices : []);
  } catch (err) {
    res.json({ error: err.message });
  }
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

// ---- Change Password ----
app.post('/api/auth/change-password', authenticate, (req, res, next) => {
  try { changePasswordRoute(req, res); } catch (err) { next(err); }
});

// ---- Logout ----
app.post('/api/auth/logout', authenticate, (req, res) => {
  res.clearCookie(config.cookieName, { path: '/' });
  res.clearCookie('csrf-token', { path: '/' });
  res.json({ status: 'ok', message: 'Logged out' });
});

// ---- MITRE ATT&CK Framework ----
app.get('/api/mitre/tactics', optionalAuth, (req, res) => {
  res.json(mitre.getTactics());
});

app.get('/api/mitre/techniques', optionalAuth, (req, res) => {
  const { tactic, platform, search: searchQuery } = req.query;
  let techniques = mitre.getTechniques();
  if (tactic) techniques = techniques.filter(t => t.tacticId === tactic);
  if (platform) techniques = mitre.getTechniquesByPlatform(platform);
  if (searchQuery) techniques = mitre.search(searchQuery);
  res.json(techniques);
});

app.get('/api/mitre/techniques/:id', optionalAuth, (req, res) => {
  const technique = mitre.getTechniqueById(req.params.id);
  if (!technique) return res.status(404).json({ error: 'Technique not found' });
  res.json(technique);
});

app.get('/api/mitre/tactics/:id', optionalAuth, (req, res) => {
  const tactic = mitre.getTacticById(req.params.id);
  if (!tactic) return res.status(404).json({ error: 'Tactic not found' });
  const techniques = mitre.getTechniquesByTactic(req.params.id);
  res.json({ ...tactic, techniques });
});

app.post('/api/mitre/map-attack-type', authenticate, (req, res) => {
  const { attackType } = req.body || {};
  if (!attackType) return res.status(400).json({ error: 'attackType required' });
  const techniques = mitre.mapAttackTypeToTechniques(attackType);
  const detections = mitre.getRecommendedDetections(techniques.map(t => t.id));
  res.json({ attackType, mappedTechniques: techniques, recommendedDetections: detections });
});

// ---- Syslog Collection ----
let syslogServerRunning = false;
app.post('/api/syslog/start', authenticate, authorize('admin'), (req, res) => {
  if (syslogServerRunning) return res.json({ status: 'already_running' });
  const { udpPort = 514, tcpPort = 601, udp = true, tcp = false } = req.body || {};
  try {
    syslog.startSyslogServer({ udp, tcp, udpPort, tcpPort });
    syslogServerRunning = true;
    audit('syslog_start', req, { udp, tcp, udpPort, tcpPort });
    res.json({ status: 'started', udp, tcp, udpPort, tcpPort });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/syslog/stop', authenticate, authorize('admin'), (req, res) => {
  syslog.stopSyslogServer();
  syslogServerRunning = false;
  audit('syslog_stop', req, {});
  res.json({ status: 'stopped' });
});

app.get('/api/syslog/logs', authenticate, (req, res) => {
  const limit = Math.min(500, parseInt(req.query.limit) || 100);
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  res.json(syslog.getCollectedLogs(limit, offset));
});

app.get('/api/syslog/stats', authenticate, (req, res) => {
  res.json(syslog.getLogStats());
});

app.post('/api/syslog/clear', authenticate, authorize('admin'), (req, res) => {
  syslog.clearLogs();
  res.json({ status: 'cleared' });
});

app.get('/api/syslog/status', authenticate, (req, res) => {
  res.json({ running: syslogServerRunning });
});

// Windows Events
app.get('/api/syslog/windows-events', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const { logName = 'Security', maxEvents = 100, eventIds } = req.query;
    const events = await syslog.getWindowsEvents({ logName, maxEvents: parseInt(maxEvents), eventIds: eventIds ? eventIds.split(',').map(Number) : [] });
    res.json(Array.isArray(events) ? events : []);
  } catch (err) { res.json([]); }
});

app.get('/api/syslog/windows-logs', authenticate, authorize('admin'), (req, res) => {
  try {
    const logs = syslog.getEventLogs();
    res.json(Array.isArray(logs) ? logs : []);
  } catch (err) { res.json([]); }
});

// ---- Snort/Suricata Integration ----
app.post('/api/snort/parse', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const { rule } = req.body || {};
  if (!rule) return res.status(400).json({ error: 'rule string required' });
  try {
    const parsed = snort.parseRule(rule);
    res.json(parsed);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/snort/validate', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const { rule } = req.body || {};
  if (!rule) return res.status(400).json({ error: 'rule string required' });
  const result = snort.validateRule(rule);
  res.json(result);
});

app.post('/api/snort/convert', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const { rule } = req.body || {};
  if (!rule) return res.status(400).json({ error: 'rule string required' });
  try {
    const parsed = snort.parseRule(rule);
    const nidsRule = snort.convertToNidsRule(parsed);
    res.json({ snortRule: parsed, nidsRule });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/snort/sample-rules', optionalAuth, (req, res) => {
  res.json(snort.exportSampleRules ? snort.exportSampleRules() : snort.parseRules([]));
});

app.post('/api/snort/correlate', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const { flowId } = req.body || {};
  if (!flowId) return res.status(400).json({ error: 'flowId required' });
  const traffic = readTable('network-traffic');
  const flow = traffic.find(f => f.id === parseInt(flowId));
  if (!flow) return res.status(404).json({ error: 'Flow not found' });
  const rules = readTable('detection-rules');
  const correlation = snort.correlateAlert(flow, rules);
  res.json(correlation);
});

app.get('/api/snort/correlation-stats', authenticate, (req, res) => {
  res.json(snort.getCorrelationStats());
});

// ---- Remote Agent Monitoring ----
app.get('/api/agents', authenticate, (req, res) => {
  res.json(agent.getRegisteredAgents());
});

app.post('/api/agents/register', authenticate, authorize('admin'), (req, res) => {
  const { type, host, port, username, authType } = req.body || {};
  if (!type || !host) return res.status(400).json({ error: 'type and host required' });
  const result = agent.registerAgent({ type, host, port: port || 22, username: username || 'root', authType: authType || 'password', ...req.body });
  audit('agent_registered', req, { host, type });
  res.status(201).json(result);
});

app.delete('/api/agents/:id', authenticate, authorize('admin'), (req, res) => {
  agent.removeAgent(req.params.id);
  res.status(204).send();
});

app.post('/api/agents/collect', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const results = await agent.collectFromAllAgents();
    res.json(results);
  } catch (err) { next(err); }
});

app.post('/api/agents/discover', authenticate, authorize('admin'), (req, res) => {
  const { subnet } = req.body || {};
  if (!subnet) return res.status(400).json({ error: 'subnet required' });
  const discovered = agent.discoverAgents(subnet);
  res.json(discovered);
});

// Agent HTTP server
app.post('/api/agents/server/start', authenticate, authorize('admin'), (req, res) => {
  const { port = 9100 } = req.body || {};
  try {
    agent.startAgentServer(port);
    res.json({ status: 'started', port });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/agents/server/stop', authenticate, authorize('admin'), (req, res) => {
  agent.stopAgentServer();
  res.json({ status: 'stopped' });
});

// ---- SOAR Playbook Engine ----
app.get('/api/soar/playbooks/builtin', optionalAuth, (req, res) => {
  res.json(soar.getBuiltinPlaybooks());
});

app.get('/api/soar/playbooks/builtin/:name', optionalAuth, (req, res) => {
  const pb = soar.getBuiltinPlaybook(req.params.name);
  if (!pb) return res.status(404).json({ error: 'Playbook not found' });
  res.json(pb);
});

app.post('/api/soar/execute', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  const { playbookId, context = {} } = req.body || {};
  if (!playbookId) return res.status(400).json({ error: 'playbookId required' });

  let playbook;
  const storedPlaybooks = readTableSafe('playbooks');
  playbook = storedPlaybooks.find(p => p.id === parseInt(playbookId) || p.id === playbookId);
  if (!playbook) playbook = soar.getBuiltinPlaybook(playbookId);
  if (!playbook) return res.status(404).json({ error: 'Playbook not found' });

  try {
    const executionId = await soar.startPlaybook(playbook, context);
    audit('soar_execution_started', req, { playbookId: playbook.id || playbook.name, executionId });
    res.status(201).json({ executionId, status: 'started', playbook: playbook.name });
  } catch (err) { next(err); }
});

app.post('/api/soar/stop/:executionId', authenticate, authorize('admin'), (req, res) => {
  soar.stopPlaybook(req.params.executionId);
  res.json({ status: 'stopped' });
});

app.get('/api/soar/executions', authenticate, (req, res) => {
  const { status } = req.query;
  const filters = {};
  if (status) filters.status = status;
  res.json(soar.listExecutions(filters));
});

app.get('/api/soar/executions/:executionId', authenticate, (req, res) => {
  const exec = soar.getPlaybookStatus(req.params.executionId);
  if (!exec) return res.status(404).json({ error: 'Execution not found' });
  res.json(exec);
});

app.delete('/api/soar/executions', authenticate, authorize('admin'), (req, res) => {
  soar.clearExecutions();
  res.status(204).send();
});

// ---- File Integrity Monitoring ----
app.get('/api/fim/baseline', authenticate, (req, res) => {
  res.json(fim.getBaseline());
});

app.post('/api/fim/baseline', authenticate, authorize('admin'), (req, res) => {
  const { paths } = req.body || {};
  if (!paths || !Array.isArray(paths) || paths.length === 0) return res.status(400).json({ error: 'paths array required' });
  try {
    const baseline = fim.createBaseline(paths);
    audit('fim_baseline_created', req, { fileCount: baseline.length });
    res.status(201).json({ fileCount: baseline.length, baseline });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/fim/baseline/add', authenticate, authorize('admin'), (req, res) => {
  const { filePath } = req.body || {};
  if (!filePath) return res.status(400).json({ error: 'filePath required' });
  try {
    const entry = fim.addToBaseline(filePath);
    res.status(201).json(entry);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/fim/baseline', authenticate, authorize('admin'), (req, res) => {
  const { filePath } = req.body || {};
  if (filePath) fim.removeFromBaseline(filePath);
  else fim.clearBaseline();
  res.status(204).send();
});

app.post('/api/fim/scan', authenticate, authorize('admin', 'analyst'), (req, res) => {
  try {
    const result = fim.runScan();
    audit('fim_scan', req, { changed: result.changed.length, added: result.added.length, removed: result.removed.length });
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/fim/scans', authenticate, (req, res) => {
  const limit = Math.min(100, parseInt(req.query.limit) || 10);
  res.json(fim.getScanHistory(limit));
});

app.get('/api/fim/last-scan', authenticate, (req, res) => {
  res.json(fim.getLastScan() || { status: 'no_scans' });
});

app.post('/api/fim/watch/start', authenticate, authorize('admin'), (req, res) => {
  const { interval = 60 } = req.body || {};
  fim.startWatcher(interval * 1000);
  res.json({ status: 'watching', interval });
});

app.post('/api/fim/watch/stop', authenticate, authorize('admin'), (req, res) => {
  fim.stopWatcher();
  res.json({ status: 'stopped' });
});

app.get('/api/fim/report', authenticate, (req, res) => {
  res.json(fim.getFIMReport ? fim.getFIMReport() : {});
});

app.get('/api/fim/config', authenticate, (req, res) => {
  res.json(fim.getConfig ? fim.getConfig() : {});
});

app.put('/api/fim/config', authenticate, authorize('admin'), (req, res) => {
  if (fim.saveConfig) fim.saveConfig(req.body);
  res.json({ status: 'ok' });
});

// ---- Vulnerability Scanning ----
app.post('/api/vulnscan/scan', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const { targets } = req.body || {};
  if (!targets || !Array.isArray(targets) || targets.length === 0) return res.status(400).json({ error: 'targets array required' });
  const scanId = vulnscan.startScan(targets);
  audit('vulnscan_started', req, { targets, scanId });
  res.status(201).json({ scanId, targets, status: 'running' });
});

app.get('/api/vulnscan/scans', authenticate, (req, res) => {
  res.json(vulnscan.getScanHistory());
});

app.get('/api/vulnscan/scan/:scanId', authenticate, (req, res) => {
  const scan = vulnscan.getScanStatus(req.params.scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json(scan);
});

app.get('/api/vulnscan/scan/:scanId/results', authenticate, (req, res) => {
  const results = vulnscan.getScanResults(req.params.scanId);
  if (!results) return res.status(404).json({ error: 'Scan not found or not completed' });
  res.json(results);
});

app.post('/api/vulnscan/scan/:scanId/cancel', authenticate, authorize('admin'), (req, res) => {
  vulnscan.cancelScan(req.params.scanId);
  res.json({ status: 'cancelled' });
});

app.post('/api/vulnscan/assess-asset', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const { assetId } = req.body || {};
  if (!assetId) return res.status(400).json({ error: 'assetId required' });
  const assets = readTable('network-assets');
  const asset = assets.find(a => a.id === parseInt(assetId));
  if (!asset) return res.status(404).json({ error: 'Asset not found' });
  const assessment = vulnscan.assessAsset(asset);
  res.json(assessment);
});

app.get('/api/vulnscan/vulnerabilities', optionalAuth, (req, res) => {
  const { severity, search } = req.query;
  let vulns = vulnscan.vulnerabilityDatabase || [];
  if (severity) vulns = vulns.filter(v => v.severity === severity);
  if (search) vulns = vulns.filter(v => v.description.toLowerCase().includes(search.toLowerCase()) || v.id.toLowerCase().includes(search.toLowerCase()));
  res.json(vulns);
});

app.get('/api/vulnscan/report', authenticate, (req, res) => {
  res.json(vulnscan.getVulnerabilityReport ? vulnscan.getVulnerabilityReport({}) : {});
});

// ---- Compliance Reporting ----
app.get('/api/compliance/frameworks', optionalAuth, (req, res) => {
  res.json([
    { id: 'pci-dss', name: 'PCI DSS v4.0', controls: compliance.pciDssData ? compliance.pciDssData.length : 0 },
    { id: 'hipaa', name: 'HIPAA Security Rule', controls: compliance.hipaaData ? compliance.hipaaData.length : 0 },
    { id: 'gdpr', name: 'GDPR', controls: compliance.gdprData ? compliance.gdprData.length : 0 }
  ]);
});

app.get('/api/compliance/:framework', optionalAuth, (req, res) => {
  const { framework } = req.params;
  const valid = ['pci-dss', 'hipaa', 'gdpr'];
  if (!valid.includes(framework)) return res.status(400).json({ error: `Framework must be one of: ${valid.join(', ')}` });
  const status = compliance.getComplianceStatus(framework);
  res.json(status);
});

app.get('/api/compliance/:framework/controls', optionalAuth, (req, res) => {
  const { framework } = req.params;
  const data = { 'pci-dss': compliance.pciDssData, 'hipaa': compliance.hipaaData, 'gdpr': compliance.gdprData }[framework];
  res.json(data || []);
});

app.get('/api/compliance/:framework/report', authenticate, (req, res) => {
  const { framework } = req.params;
  const report = compliance.generateReport(framework, { format: 'json' });
  res.json(report);
});

app.get('/api/compliance/dashboard', authenticate, (req, res) => {
  const dashboard = {};
  for (const fw of ['pci-dss', 'hipaa', 'gdpr']) {
    dashboard[fw] = compliance.getComplianceStatus(fw);
  }
  res.json(dashboard);
});

app.get('/api/compliance/evidence/:framework/:controlId', authenticate, (req, res) => {
  const evidence = compliance.collectEvidence(req.params.framework, req.params.controlId);
  res.json(evidence);
});

app.get('/api/compliance/recommendations', authenticate, (req, res) => {
  const frameworks = req.query.frameworks ? req.query.frameworks.split(',') : ['pci-dss', 'hipaa', 'gdpr'];
  const recommendations = [];
  for (const fw of frameworks) {
    const status = compliance.getComplianceStatus(fw);
    if (status.recommendations) recommendations.push(...status.recommendations.map(r => ({ ...r, framework: fw })));
  }
  res.json(recommendations);
});

// ---- Anomaly/ML Detection ----
app.post('/api/ml/detect-anomalies', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const { data, field, method = 'zscore', threshold = 3 } = req.body || {};
  if (!data || !field) return res.status(400).json({ error: 'data and field required' });
  try {
    const result = ml.detectAnomalies(data, field, { method, threshold });
    res.json(result);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/ml/traffic-baseline', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const traffic = readTable('network-traffic');
  const baseline = ml.buildTrafficBaseline(traffic);
  ml.saveModel('traffic-baseline', baseline);
  res.json({ status: 'baseline_built', recordCount: traffic.length, timestamp: baseline.lastUpdated });
});

app.post('/api/ml/detect-traffic-anomalies', authenticate, authorize('admin', 'analyst'), (req, res) => {
  let baseline;
  try { baseline = ml.loadModel('traffic-baseline'); } catch { baseline = null; }
  if (!baseline) return res.status(400).json({ error: 'No traffic baseline. Build one first via POST /api/ml/traffic-baseline' });
  const traffic = readTable('network-traffic');
  const anomalies = ml.detectTrafficAnomalies(traffic, baseline);
  res.json(anomalies);
});

app.post('/api/ml/threshold-rule', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const { name, field, operator, value, window, cooldown } = req.body || {};
  if (!name || !field || !operator || value === undefined) return res.status(400).json({ error: 'name, field, operator, value required' });
  const rule = ml.createThresholdRule(name, { field, operator, value, window: window || 300, cooldown: cooldown || 600 });
  res.status(201).json(rule);
});

app.get('/api/ml/threshold-rules', authenticate, (req, res) => {
  res.json(ml.getActiveThresholds());
});

app.get('/api/ml/models', authenticate, (req, res) => {
  res.json(ml.listModels());
});

app.delete('/api/ml/models/:name', authenticate, authorize('admin'), (req, res) => {
  ml.deleteModel(req.params.name);
  res.status(204).send();
});

// ---- Data Retention ----
app.get('/api/retention/policies', authenticate, (req, res) => {
  res.json(retention.getPolicies());
});

app.post('/api/retention/policies', authenticate, authorize('admin'), (req, res) => {
  const policy = retention.savePolicy(req.body);
  res.status(201).json(policy);
});

app.delete('/api/retention/policies/:id', authenticate, authorize('admin'), (req, res) => {
  retention.deletePolicy(req.params.id);
  res.status(204).send();
});

app.post('/api/retention/run', authenticate, authorize('admin'), (req, res) => {
  const result = retention.runOnce();
  audit('retention_run', req, { purged: result.purged, archived: result.archived });
  res.json(result);
});

app.get('/api/retention/report', authenticate, (req, res) => {
  res.json(retention.getRetentionReport());
});

app.get('/api/retention/archives', authenticate, (req, res) => {
  res.json(retention.getArchives ? retention.getArchives() : []);
});

app.post('/api/retention/archives/:id/restore', authenticate, authorize('admin'), (req, res) => {
  const result = retention.restoreArchive(req.params.id);
  res.json(result || { status: 'restored' });
});

app.delete('/api/retention/archives/:id', authenticate, authorize('admin'), (req, res) => {
  retention.deleteArchive(req.params.id);
  res.status(204).send();
});

app.get('/api/retention/holds', authenticate, (req, res) => {
  res.json(retention.getLegalHolds());
});

app.post('/api/retention/holds', authenticate, authorize('admin'), (req, res) => {
  const hold = retention.addLegalHold(req.body);
  res.status(201).json(hold);
});

app.delete('/api/retention/holds/:id', authenticate, authorize('admin'), (req, res) => {
  retention.removeLegalHold(req.params.id);
  res.status(204).send();
});

app.get('/api/retention/storage-forecast', authenticate, (req, res) => {
  const days = parseInt(req.query.days) || 90;
  res.json(retention.getStorageForecast(days));
});

// ---- Alerting Configuration ----
app.get('/api/alerting/config', authenticate, (req, res) => {
  res.json(alerting.getConfig());
});

app.put('/api/alerting/config', authenticate, authorize('admin'), (req, res) => {
  alerting.saveConfig(req.body);
  res.json({ status: 'ok' });
});

app.post('/api/alerting/test', authenticate, authorize('admin'), async (req, res) => {
  const { type = 'email' } = req.body || {};
  const config = alerting.getConfig();
  let result;
  if (type === 'email' && config.email.enabled) {
    result = await alerting.sendEmail({ to: config.email.to || 'test@example.com', subject: 'NIDS Alert Test', html: '<h1>Test Alert</h1><p>This is a test notification from NIDS Enterprise.</p>' });
  } else if (type === 'slack' && config.slack.enabled) {
    result = await alerting.sendSlack({ webhookUrl: config.slack.webhookUrl, text: 'NIDS Test Alert - This is a test notification.' });
  } else if (type === 'webhook' && config.webhook.enabled) {
    result = await alerting.sendWebhook({ url: config.webhook.url, method: config.webhook.method || 'POST', body: { test: true, message: 'NIDS Test Alert' } });
  }
  res.json(result || { success: false, error: `${type} not configured or disabled` });
});

// ---- Database Stats ----
app.get('/api/db/stats', authenticate, authorize('admin'), (req, res) => {
  res.json(db.getStats());
});

// Integrate alerting into automations
const originalRunAutomations = runAutomations;
runAutomations = function(event, item, allData, oldItem) {
  originalRunAutomations(event, item, allData, oldItem);
  try {
    alerting.notify(event, { item, timestamp: new Date().toISOString(), user: 'system' });
  } catch (err) {
    console.error('[Alerting] Failed to notify:', err.message);
  }
};

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
    console.log(`  CSRF: Include X-CSRF-Token header (get from csrf-token cookie on login)`);
  });
}

app.listen(config.port, config.host, () => {
  console.log(`NIDS Enterprise running at http://localhost:${config.port}`);
  console.log(`  Auth: POST /api/auth/login`);
  console.log(`  CSRF: Include X-CSRF-Token header (get from csrf-token cookie on login)`);
});
