import { NextRequest, NextResponse } from 'next/server';
import * as cookie from 'cookie';
import fs from 'fs';
import path from 'path';

export const dynamic = 'force-dynamic';

const config = require('../../../lib/config');
const jwt = require('jsonwebtoken');
const db = require('../../../lib/db');
const { authenticate: authMiddleware, optionalAuth, loginRoute, meRoute, listUsersRoute, createUserRoute, updateUserRoute, deleteUserRoute, seedAdminUser } = require('../../../lib/auth');
const { audit, getAuditLog } = require('../../../lib/audit');
const { AppError, NotFoundError, AuthError, ForbiddenError } = require('../../../lib/errors');
const pcap = require('../../../lib/pcap');
const monitor = require('../../../lib/monitor');
const alerting = require('../../../lib/alerting');
const mitre = require('../../../lib/mitre');
const syslog = require('../../../lib/syslog');
const snort = require('../../../lib/snort');
const agent = require('../../../lib/agent');
const soar = require('../../../lib/soar');
const fim = require('../../../lib/fim');
const vulnscan = require('../../../lib/vulnscan');
const compliance = require('../../../lib/compliance');
const ml = require('../../../lib/ml');
const retention = require('../../../lib/retention');

seedAdminUser();

const DATA_DIR = config.dataDir;

function readTable(name) { return db.readTable(name); }
function writeTable(name, data) { db.writeTable(name, data); }
function nextId(data) { return db.nextId(data); }
function readTablePaginated(name, query) { return db.readTablePaginated(name, query); }
function readTableSafe(name) { return db.readTableSafe(name); }

function getToken(req) {
  const cookies = cookie.parse(req.headers.get('cookie') || '');
  const authHeader = req.headers.get('authorization') || '';
  let token;
  if (authHeader.startsWith('Bearer ')) token = authHeader.slice(7);
  else if (cookies[config.cookieName]) token = cookies[config.cookieName];
  return token;
}

function getUser(token) {
  if (!token) return null;
  try { return jwt.verify(token, config.jwtSecret); } catch { return null; }
}

function errorResponse(status, message) {
  return NextResponse.json({ error: message }, { status });
}

function authenticate(req) {
  const token = getToken(req);
  const user = getUser(token);
  if (!user) throw new AuthError();
  return user;
}

function optionalAuthRequest(req) {
  const token = getToken(req);
  return getUser(token);
}

function authorize(user, ...roles) {
  if (!user) throw new AuthError();
  if (roles.length > 0 && !roles.includes(user.role)) throw new ForbiddenError();
}

const WRITABLE_TABLES = ['incidents', 'detection-rules', 'threat-intel', 'engineering-tasks', 'network-assets', 'qa-tests', 'playbooks', 'security-policies', 'security-standards'];
const READONLY_TABLES = ['network-traffic'];
const ALL_TABLES = [...WRITABLE_TABLES, ...READONLY_TABLES];

const CSF_FUNCTIONS = [
  { id: 'GV', name: 'Govern', desc: 'Establish organizational cybersecurity governance' },
  { id: 'ID', name: 'Identify', desc: 'Understand and manage cybersecurity risks' },
  { id: 'PR', name: 'Protect', desc: 'Implement safeguards to protect assets' },
  { id: 'DE', name: 'Detect', desc: 'Detect cybersecurity anomalies and events' },
  { id: 'RS', name: 'Respond', desc: 'Respond to cybersecurity incidents' },
  { id: 'RC', name: 'Recover', desc: 'Recover from cybersecurity incidents' },
];

function logAutomation(action, details) {
  const logFile = path.join(DATA_DIR, 'automations-log.json');
  let log = [];
  try { const raw = fs.readFileSync(logFile, 'utf8'); log = JSON.parse(raw); } catch { log = []; }
  log.push({ id: log.length + 1, action, details, timestamp: new Date().toISOString() });
  fs.writeFileSync(logFile, JSON.stringify(log, null, 2), 'utf8');
}

function ipInRange(ip, range) {
  if (!range.includes('-')) return false;
  const [start, end] = range.split('-');
  const ipNum = ip.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0);
  const startNum = start.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0);
  const endNum = end.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0);
  return ipNum >= startNum && ipNum <= endNum;
}

function runAutomations(event, item, allData, oldItem) {
  if (event === 'incident.created' || event === 'incident.updated') {
    if (item.severity === 'Critical' && item.status !== 'Resolved' && item.status !== 'Closed') {
      logAutomation('critical_severity_alert', { incidentId: item.id, title: item.title, message: `CRITICAL: Incident #${item.id} "${item.title}" requires immediate attention.`, severity: item.severity, attackType: item.attackType, sourceIp: item.sourceIp });
    }
    if (item.status === 'Resolved' && item.cvssScore != null) {
      logAutomation('incident_resolved_cvss_scored', { incidentId: item.id, title: item.title, cvssScore: item.cvssScore, message: `Incident #${item.id} resolved with CVSS score ${item.cvssScore}.` });
    }
    try {
      const playbooks = readTable('playbooks');
      const matching = playbooks.filter(p => p.status === 'Active' && p.triggerOnAttackTypes && p.triggerOnAttackTypes.includes(item.attackType));
      if (matching.length > 0) {
        logAutomation('playbook_suggested', { incidentId: item.id, attackType: item.attackType, suggestedPlaybooks: matching.map(p => ({ id: p.id, name: p.name })), message: `Incident #${item.id} matches ${matching.length} active playbook(s)` });
      }
    } catch {}
    try {
      const assets = readTable('network-assets');
      const matchingAsset = assets.find(a => item.sourceIp && a.ipRange && (item.sourceIp.startsWith(a.ipRange.split('/')[0].replace('.0', '')) || item.sourceIp === a.ipRange.split('/')[0] || (a.ipRange.includes('-') && ipInRange(item.sourceIp, a.ipRange))));
      if (matchingAsset) {
        const openIncidents = allData.filter(i => i.sourceIp && matchingAsset.ipRange && (i.sourceIp.startsWith(matchingAsset.ipRange.split('/')[0].replace('.0', '')) || i.sourceIp === matchingAsset.ipRange.split('/')[0] || (matchingAsset.ipRange.includes('-') && ipInRange(i.sourceIp, matchingAsset.ipRange))) && i.status !== 'Resolved' && i.status !== 'Closed').length;
        const assetIdx = assets.findIndex(a => a.id === matchingAsset.id);
        if (assetIdx !== -1) {
          assets[assetIdx].openIncidentCount = openIncidents;
          assets[assetIdx].lastIncidentDate = item.detectedAt || new Date().toISOString();
          writeTable('network-assets', assets);
        }
      }
    } catch {}
  }
  if (event === 'task.updated' && item.status === 'Done' && item.ruleId) {
    try {
      const rules = readTable('detection-rules');
      const ruleIdx = rules.findIndex(r => r.id === item.ruleId);
      if (ruleIdx !== -1 && rules[ruleIdx].status === 'In Development') {
        rules[ruleIdx].status = 'Active';
        rules[ruleIdx].lastUpdated = new Date().toISOString().split('T')[0];
        writeTable('detection-rules', rules);
      }
    } catch {}
  }
}

function evaluateSingleExpr(token, item) {
  const match = token.match(/^([\w.]+)\s*([!=<>]+|contains|matches)\s*(.+)$/i);
  if (!match) { if (token.startsWith('!')) return !evaluateSingleExpr(token.slice(1), item); return false; }
  const [, field, operator, valueRaw] = match;
  const value = valueRaw.replace(/^"|"$/g, '').toLowerCase();
  const map = { 'ip.src': 'srcIp', 'ip.dst': 'destIp', 'tcp.srcport': 'srcPort', 'tcp.dstport': 'destPort', 'udp.srcport': 'srcPort', 'udp.dstport': 'destPort', 'frame.len': 'bytes', 'frame.protocols': 'protocol', 'ip.proto': 'protocol', 'http.method': 'httpMethod', 'http.request.method': 'httpMethod', 'http.uri': 'httpUri', 'http.request.uri': 'httpUri', 'http.status': 'httpStatus', 'http.response.code': 'httpStatus', 'http.host': 'httpHost', 'http.user_agent': 'httpUserAgent', 'http.content_type': 'httpContentType' };
  let fieldValue;
  if (field === 'ip.addr') fieldValue = `${item.srcIp} ${item.destIp}`;
  else if (field === 'tcp.port') fieldValue = `${item.srcPort} ${item.destPort}`;
  else { const mapped = map[field]; fieldValue = mapped ? item[mapped] : item[field]; }
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
    case 'matches': try { return new RegExp(value, 'i').test(strVal); } catch { return false; }
    default: return true;
  }
}

function evaluateTokens(tokens, item) {
  let result = true, i = 0;
  while (i < tokens.length) {
    const token = tokens[i];
    if (token === '(') {
      const subTokens = []; let depth = 1; i++;
      while (i < tokens.length && depth > 0) {
        if (tokens[i] === '(') depth++;
        else if (tokens[i] === ')') { depth--; if (depth === 0) break; }
        subTokens.push(tokens[i]); i++;
      }
      const subResult = evaluateTokens(subTokens, item);
      if (i < tokens.length - 1 && (tokens[i + 1] === '&&' || tokens[i + 1] === 'and')) { result = result && subResult; i += 2; }
      else if (i < tokens.length - 1 && (tokens[i + 1] === '||' || tokens[i + 1] === 'or')) { result = result || subResult; i += 2; }
      else { result = result && subResult; }
    } else if (token === '!' || token === 'not') {
      i++; result = result && !evaluateTokens([tokens[i]], item); i++;
    } else if (token === '&&' || token === 'and' || token === '||' || token === 'or') { i++; }
    else {
      const exprResult = evaluateSingleExpr(token, item);
      if (i < tokens.length - 1 && (tokens[i + 1] === '&&' || tokens[i + 1] === 'and')) { result = result && exprResult; i += 2; }
      else if (i < tokens.length - 1 && (tokens[i + 1] === '||' || tokens[i + 1] === 'or')) { result = result || exprResult; i += 2; }
      else { result = result && exprResult; i++; }
    }
  }
  return result;
}

function isWebFlow(f) { return f.httpMethod || (f.protocol && (f.protocol === 'HTTP' || f.protocol === 'HTTPS')); }

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
    { id: 1, assetName: 'Core Web Server', ipRange: '10.0.1.0/24', type: 'Server', riskLevel: 'Critical', monitoringStatus: 'Online', owner: 'Platform Engineering', openIncidentCount: 1, lastIncidentDate: new Date().toISOString(), lastScanned: new Date(Date.now() - 86400000).toISOString(), description: 'Primary web server hosting customer-facing application and API endpoints.', risks: [{ risk: 'Web application vulnerability exploit leading to data breach', likelihood: 'Medium', severity: 'Critical', priority: 'Critical' }] },
    { id: 2, assetName: 'Corporate Firewall', ipRange: '10.0.0.1', type: 'Firewall', riskLevel: 'High', monitoringStatus: 'Online', owner: 'Network Team', openIncidentCount: 0, lastIncidentDate: null, lastScanned: new Date(Date.now() - 172800000).toISOString(), description: 'Perimeter firewall.', risks: [{ risk: 'Firewall rule misconfiguration exposing internal services', likelihood: 'Medium', severity: 'High', priority: 'High' }] }
  ],
  'qa-tests': [
    { id: 1, testName: 'C2 Rule QA Validation', ruleId: 1, status: 'pending', testCases: ['Generate test C2 traffic', 'Verify alert fires', 'Check false positive rate'], testedBy: 'Carol Nguyen', notes: 'Awaiting test environment', createdAt: new Date(Date.now() - 86400000).toISOString() }
  ],
  'network-traffic': [
    { id: 1, srcIp: '10.0.1.45', destIp: '185.220.101.22', srcPort: 49152, destPort: 443, protocol: 'HTTPS', bytes: 45000, packets: 120, duration: 5.2, timestamp: new Date(Date.now() - 1800000).toISOString(), status: 'blocked', application: 'Web', assetId: 1, ruleId: 1, country: 'RU', httpMethod: null, httpUri: null, httpStatus: null, httpHost: null, httpUserAgent: null, httpContentType: null },
    { id: 2, srcIp: '10.0.1.10', destIp: '10.0.1.5', srcPort: 52001, destPort: 80, protocol: 'HTTP', bytes: 2500, packets: 8, duration: 0.4, timestamp: new Date(Date.now() - 60000).toISOString(), status: 'allowed', application: 'Web', assetId: 1, ruleId: null, country: 'US' },
    { id: 3, srcIp: '203.0.113.50', destIp: '10.0.1.5', srcPort: 33456, destPort: 80, protocol: 'HTTP', bytes: 420, packets: 3, duration: 0.1, timestamp: new Date(Date.now() - 120000).toISOString(), status: 'blocked', application: 'Web', assetId: 1, ruleId: 2, country: 'CN' },
    { id: 4, srcIp: '10.0.1.20', destIp: '10.0.1.5', srcPort: 52002, destPort: 80, protocol: 'HTTP', bytes: 12000, packets: 35, duration: 2.1, timestamp: new Date(Date.now() - 300000).toISOString(), status: 'allowed', application: 'Web', assetId: 1, ruleId: null, country: 'US' },
    { id: 5, srcIp: '10.0.1.45', destIp: '10.0.1.5', srcPort: 52003, destPort: 443, protocol: 'HTTPS', bytes: 89000, packets: 210, duration: 8.5, timestamp: new Date(Date.now() - 900000).toISOString(), status: 'allowed', application: 'Web', assetId: 1, ruleId: null, country: 'US' },
    { id: 6, srcIp: '198.51.100.33', destIp: '10.0.1.5', srcPort: 44001, destPort: 80, protocol: 'HTTP', bytes: 180, packets: 2, duration: 0.05, timestamp: new Date(Date.now() - 45000).toISOString(), status: 'blocked', application: 'Web', assetId: 1, ruleId: null, country: 'DE' },
    { id: 7, srcIp: '10.0.1.10', destIp: '8.8.8.8', srcPort: 53, destPort: 53, protocol: 'DNS', bytes: 120, packets: 2, duration: 0.03, timestamp: new Date(Date.now() - 5000).toISOString(), status: 'allowed', application: 'DNS', assetId: 1, ruleId: null, country: 'US' }
  ],
  playbooks: [
    { id: 1, name: 'C2 Containment', category: 'Incident Response', severity: 'Critical', status: 'Active', createdBy: 'Alice Chen', description: 'Isolate and investigate C2 communication', triggerOnAttackTypes: ['C2 Communication'], steps: [{ order: 1, action: 'Isolate affected host from network', assignee: 'SOC Tier 1', duration: '5 min' }, { order: 2, action: 'Collect network flow logs', assignee: 'SOC Tier 2', duration: '15 min' }, { order: 3, action: 'Analyze C2 payload and update IOCs', assignee: 'Threat Intel', duration: '30 min' }], runCount: 3, lastRun: new Date(Date.now() - 3600000).toISOString(), createdAt: new Date(Date.now() - 604800000).toISOString() }
  ],
  'security-policies': [
    { id: 1, name: 'Incident Response Policy', category: 'Incident Response', status: 'Active', version: '2.1', csfFunction: 'RS', description: 'All security incidents must be classified, tracked, and resolved within defined SLAs.', createdBy: 'Alice Chen', lastReviewed: '2026-06-01', reviewInterval: 'Quarterly' },
    { id: 2, name: 'Access Control Policy', category: 'Access Control', status: 'Active', version: '3.0', csfFunction: 'PR', description: 'Network access must follow least-privilege principles.', createdBy: 'Carol Nguyen', lastReviewed: '2026-05-15', reviewInterval: 'Semi-Annual' },
    { id: 3, name: 'Logging and Monitoring Policy', category: 'Monitoring', status: 'Active', version: '1.5', csfFunction: 'DE', description: 'All network traffic, system events, and access logs must be collected.', createdBy: 'Bob Martinez', lastReviewed: '2026-04-20', reviewInterval: 'Annual' }
  ],
  'security-standards': [
    { id: 1, name: 'C2 Detection Standard', category: 'Detection', status: 'Active', version: '1.0', csfFunction: 'DE', description: 'All C2 beaconing detection rules must threshold on 5+ connections.', createdBy: 'Bob Martinez', lastReviewed: '2026-06-10', framework: 'NIST SP 800-61' },
    { id: 2, name: 'Incident Severity Classification', category: 'Incident Response', status: 'Active', version: '2.0', csfFunction: 'RS', description: 'Incidents are classified by CVSS score.', createdBy: 'Alice Chen', lastReviewed: '2026-05-01', framework: 'NIST SP 800-61' },
    { id: 3, name: 'Asset Risk Classification Standard', category: 'Asset Management', status: 'Active', version: '1.2', csfFunction: 'ID', description: 'Network assets are classified as Critical, High, Medium, or Low.', createdBy: 'Carol Nguyen', lastReviewed: '2026-03-20', framework: 'NIST SP 800-53' }
  ]
};

export async function GET(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return handleRequest('GET', req, path);
}

export async function POST(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return handleRequest('POST', req, path);
}

export async function PUT(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return handleRequest('PUT', req, path);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return handleRequest('DELETE', req, path);
}

async function handleRequest(method: string, req: NextRequest, pathSegments: string[]) {
  try {
    const url = new URL(req.url);
    const query = Object.fromEntries(url.searchParams.entries());
    const pathStr = '/' + (pathSegments || []).join('/');
    const user = optionalAuthRequest(req);

    const body = method !== 'GET' && method !== 'DELETE' ? await req.json().catch(() => ({})) : {};

    // ---- Auth Routes ----
    if (pathStr === '/auth/login' && method === 'POST') {
      const { username, password } = body;
      return handleLogin(username, password);
    }
    if (pathStr === '/auth/me' && method === 'GET') {
      const u = authenticate(req); return handleResult(await meRoute(u));
    }
    if (pathStr === '/auth/users' && method === 'GET') {
      const u = authenticate(req); authorize(u, 'admin'); return handleResult(listUsersRoute(u));
    }
    if (pathStr === '/auth/users' && method === 'POST') {
      const u = authenticate(req); authorize(u, 'admin'); return handleResult(createUserRoute(u, body));
    }
    if (pathStr.match(/^\/auth\/users\/\d+$/) && method === 'PUT') {
      const u = authenticate(req); authorize(u, 'admin'); const id = pathStr.split('/')[3];
      return handleResult(updateUserRoute(u, id, body));
    }
    if (pathStr.match(/^\/auth\/users\/\d+$/) && method === 'DELETE') {
      const u = authenticate(req); authorize(u, 'admin'); const id = pathStr.split('/')[3];
      return handleResult(deleteUserRoute(u, id));
    }
    if (pathStr === '/auth/logout' && method === 'POST') {
      return handleLogout();
    }

    // ---- Audit Log ----
    if (pathStr === '/audit/log' && method === 'GET') {
      const u = authenticate(req); authorize(u, 'admin');
      const limit = Math.min(500, parseInt(query.limit) || 100);
      const offset = Math.max(0, parseInt(query.offset) || 0);
      return NextResponse.json(getAuditLog(limit, offset));
    }

    // ---- Stats ----
    if (pathStr === '/stats' && method === 'GET') {
      const incidents = readTable('incidents');
      const rules = readTable('detection-rules');
      const tasks = readTable('engineering-tasks');
      const assets = readTable('network-assets');
      const traffic = readTable('network-traffic');
      const policies = readTable('security-policies');
      const standards = readTable('security-standards');
      const playbooks = readTable('playbooks');
      const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
      incidents.forEach(i => { severityCounts[i.severity] = (severityCounts[i.severity] || 0) + 1; });
      const statusCounts = { New: 0, Investigating: 0, Resolved: 0, Closed: 0 };
      incidents.forEach(i => { statusCounts[i.status] = (statusCounts[i.status] || 0) + 1; });
      const ruleStatusCounts = { Active: 0, 'In Development': 0, Deprecated: 0 };
      rules.forEach(r => { ruleStatusCounts[r.status] = (ruleStatusCounts[r.status] || 0) + 1; });
      const taskStatusCounts = { 'To Do': 0, 'In Progress': 0, Done: 0 };
      tasks.forEach(t => { taskStatusCounts[t.status] = (taskStatusCounts[t.status] || 0) + 1; });
      const assetRiskCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
      assets.forEach(a => { assetRiskCounts[a.riskLevel] = (assetRiskCounts[a.riskLevel] || 0) + 1; });
      const attackTypeCounts = {};
      incidents.forEach(i => { attackTypeCounts[i.attackType] = (attackTypeCounts[i.attackType] || 0) + 1; });
      const csfIncidentCounts = {}; const csfRuleCounts = {};
      CSF_FUNCTIONS.forEach(csf => { csfIncidentCounts[csf.id] = 0; csfRuleCounts[csf.id] = 0; });
      incidents.forEach(i => { if (i.csfFunction) csfIncidentCounts[i.csfFunction] = (csfIncidentCounts[i.csfFunction] || 0) + 1; });
      rules.forEach(r => { if (r.csfFunction) csfRuleCounts[r.csfFunction] = (csfRuleCounts[r.csfFunction] || 0) + 1; });
      return NextResponse.json({
        totalIncidents: incidents.length, openIncidents: incidents.filter(i => i.status !== 'Resolved' && i.status !== 'Closed').length,
        severityCounts, statusCounts, ruleStatusCounts, taskStatusCounts, assetRiskCounts, attackTypeCounts,
        activeRules: rules.filter(r => r.status === 'Active').length, openTasks: tasks.filter(t => t.status !== 'Done').length,
        criticalAssets: assets.filter(a => a.riskLevel === 'Critical').length,
        totalTrafficFlows: traffic.length, suspiciousTrafficFlows: traffic.filter(t => t.status === 'suspicious').length,
        blockedTrafficFlows: traffic.filter(t => t.status === 'blocked').length,
        csfIncidentCounts, csfRuleCounts, totalPolicies: policies.length, totalStandards: standards.length, totalPlaybooks: playbooks.length
      });
    }

    // ---- Customer Report ----
    if (pathStr === '/customer-report' && method === 'GET') {
      const incidents = readTable('incidents');
      return NextResponse.json(incidents.filter(i => i.status === 'Resolved' && i.cvssScore != null));
    }

    // ---- Settings / Profile ----
    if (pathStr === '/setup/settings' && method === 'GET') {
      return handleResult(readJsonFile(path.join(DATA_DIR, 'system-settings.json')) || { dashboardRefresh: 30, monitoringRefresh: 10, autoSimulate: 'off', maxTrafficDisplay: 100 });
    }
    if (pathStr === '/setup/settings' && method === 'PUT') {
      authenticate(req); writeJsonFile(path.join(DATA_DIR, 'system-settings.json'), body); return NextResponse.json({ status: 'ok' });
    }
    if (pathStr === '/setup/profile' && method === 'GET') {
      return handleResult(readJsonFile(path.join(DATA_DIR, 'operator-profile.json')) || { operatorName: '', operatorRole: 'SOC Analyst', operatorTeam: '' });
    }
    if (pathStr === '/setup/profile' && method === 'PUT') {
      authenticate(req); writeJsonFile(path.join(DATA_DIR, 'operator-profile.json'), body); return NextResponse.json({ status: 'ok' });
    }
    if (pathStr === '/setup/seed' && method === 'POST') {
      const u = authenticate(req); authorize(u, 'admin');
      let count = 0, tableCount = 0;
      Object.keys(SEED_DATA).forEach(table => {
        const existing = readTable(table);
        if (existing.length > 0) return;
        writeTable(table, SEED_DATA[table].map(item => ({ ...item })));
        count += SEED_DATA[table].length; tableCount++;
      });
      return NextResponse.json({ status: 'ok', message: `Loaded ${count} seed records across ${tableCount} tables` });
    }
    if (pathStr === '/setup/reset' && method === 'POST') {
      const u = authenticate(req); authorize(u, 'admin');
      WRITABLE_TABLES.forEach(table => writeTable(table, []));
      try { fs.unlinkSync(path.join(DATA_DIR, 'system-settings.json')); } catch {}
      try { fs.unlinkSync(path.join(DATA_DIR, 'operator-profile.json')); } catch {}
      try { fs.unlinkSync(path.join(DATA_DIR, 'automations-log.json')); } catch {}
      return NextResponse.json({ status: 'ok', message: 'All data reset successfully' });
    }

    // ---- Network Traffic ----
    if (pathStr === '/network-traffic/stats' && method === 'GET') {
      const traffic = readTable('network-traffic');
      const totalBytes = traffic.reduce((sum, t) => sum + t.bytes, 0);
      return NextResponse.json({
        totalFlows: traffic.length, suspiciousCount: traffic.filter(t => t.status === 'suspicious').length,
        blockedCount: traffic.filter(t => t.status === 'blocked').length, allowedCount: traffic.filter(t => t.status === 'allowed').length,
        totalBytes, uniqueProtocols: Array.from(new Set(traffic.map(t => t.protocol))).length
      });
    }
    if (pathStr === '/network-traffic' && method === 'GET') {
      let data = readTable('network-traffic');
      const filter = query.displayFilter || '';
      if (filter) {
        try {
          const tokens = filter.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
          data = data.filter(item => evaluateTokens(tokens, item));
        } catch {}
      }
      const page = Math.max(1, parseInt(query.page) || 1);
      const limit = Math.min(config.maxPageSize, Math.max(1, parseInt(query.limit) || config.defaultPageSize));
      const totalFiltered = data.length;
      const offset = (page - 1) * limit;
      return NextResponse.json({ items: data.slice(offset, offset + limit), pagination: { page, limit, total: totalFiltered, totalFiltered, totalPages: Math.ceil(totalFiltered / limit) } });
    }
    if (pathStr === '/network-traffic/simulate' && method === 'POST') {
      const u = authenticate(req); authorize(u, 'admin', 'analyst');
      const assets = readTable('network-assets');
      if (assets.length === 0) return errorResponse(400, 'No assets found. Add an asset first.');
      const asset = assets[Math.floor(Math.random() * assets.length)];
      const PROTOCOLS = ['HTTPS', 'HTTP', 'DNS', 'SSH', 'SMB', 'RDP', 'TCP', 'SMTP', 'NTP', 'MODBUS'];
      const APPS = ['Web', 'DNS', 'Remote Access', 'File Sharing', 'Email', 'Infrastructure', 'SCADA', 'P2P'];
      const STATUSES = ['allowed', 'allowed', 'allowed', 'blocked', 'suspicious'];
      const COUNTRIES = ['US', 'US', 'US', 'CN', 'RU', 'DE', 'FR', 'GB', 'NL', 'BR'];
      const isExternal = Math.random() > 0.5;
      const protocol = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
      const flow = {
        id: nextId(readTable('network-traffic')),
        srcIp: isExternal ? `${Math.floor(Math.random() * 223 + 1)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}` : asset.ipRange.split('/')[0],
        destIp: isExternal ? asset.ipRange.split('/')[0] : `${Math.floor(Math.random() * 223 + 1)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
        srcPort: Math.floor(Math.random() * 60000 + 1024),
        destPort: protocol === 'HTTP' ? 80 : protocol === 'HTTPS' ? 443 : [22, 53, 445, 3389, 25, 123, 8080, 8443][Math.floor(Math.random() * 8)],
        protocol, bytes: Math.floor(Math.random() * 10000000 + 500), packets: Math.floor(Math.random() * 8000 + 10),
        duration: parseFloat((Math.random() * 300 + 0.1).toFixed(1)), timestamp: new Date().toISOString(),
        status: STATUSES[Math.floor(Math.random() * STATUSES.length)], application: APPS[Math.floor(Math.random() * APPS.length)],
        assetId: asset.id, ruleId: Math.random() > 0.7 ? Math.floor(Math.random() * 10 + 1) : null,
        country: COUNTRIES[Math.floor(Math.random() * COUNTRIES.length)]
      };
      const traffic = readTable('network-traffic');
      traffic.push(flow); writeTable('network-traffic', traffic);
      audit({ user: { id: u.id, username: u.username, role: u.role }, ip: req.headers.get('x-forwarded-for') || '127.0.0.1', method: 'POST', path: '/api/network-traffic/simulate' }, 'traffic_simulated', { flowId: flow.id });
      return NextResponse.json(flow, { status: 201 });
    }
    if (pathStr === '/network-traffic/export' && method === 'GET') {
      const u = authenticate(req);
      return handleCsvExport('network-traffic', f => f.httpMethod, 'web-traffic');
    }
    if (pathStr === '/network-traffic/auto-simulate' && method === 'POST') {
      return NextResponse.json({ status: 'simulation_started', interval: body.interval || 5000 });
    }

    // ---- Web Traffic ----
    if (pathStr === '/web-traffic/summary' && method === 'GET') {
      const traffic = readTable('network-traffic').filter(isWebFlow);
      const methodDist = {}; const statusGroups = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
      const uriCount = {}; const hostCount = {};
      traffic.forEach(f => {
        if (f.httpMethod) methodDist[f.httpMethod] = (methodDist[f.httpMethod] || 0) + 1;
        if (f.httpStatus) statusGroups[Math.floor(f.httpStatus / 100) + 'xx'] = (statusGroups[Math.floor(f.httpStatus / 100) + 'xx'] || 0) + 1;
        if (f.httpUri) uriCount[f.httpUri] = (uriCount[f.httpUri] || 0) + 1;
        if (f.httpHost) hostCount[f.httpHost] = (hostCount[f.httpHost] || 0) + 1;
      });
      return NextResponse.json({
        totalRequests: traffic.length,
        methodDistribution: Object.entries(methodDist).map(([method, count]) => ({ method, count })),
        statusCodeGroups: statusGroups,
        topUris: Object.entries(uriCount).sort((a, b) => (b[1] as number) - (a[1] as number)).slice(0, 10).map(([uri, count]) => ({ uri, count: count as number })),
        topHosts: Object.entries(hostCount).sort((a, b) => (b[1] as number) - (a[1] as number)).slice(0, 10).map(([host, count]) => ({ host, count: count as number })),
        errorRate: traffic.length > 0 ? parseFloat((((statusGroups['4xx'] || 0) + (statusGroups['5xx'] || 0)) / traffic.length * 100).toFixed(1)) : 0,
        uniqueUris: Object.keys(uriCount).length, uniqueHosts: Object.keys(hostCount).length
      });
    }
    if (pathStr === '/web-traffic/requests' && method === 'GET') {
      let data = readTable('network-traffic').filter(isWebFlow);
      const filter = query.displayFilter || '';
      if (filter) { try { const tokens = filter.match(/(?:[^\s"]+|"[^"]*")+/g) || []; data = data.filter(item => evaluateTokens(tokens, item)); } catch {} }
      const method = query.method || ''; const status = query.status || ''; const search = query.search || '';
      if (method) data = data.filter(f => f.httpMethod === method);
      if (status) data = data.filter(f => String(f.httpStatus).startsWith(status));
      if (search) data = data.filter(f => (f.httpUri || '').toLowerCase().includes(search) || (f.httpHost || '').toLowerCase().includes(search) || String(f.httpStatus).includes(search));
      const page = Math.max(1, parseInt(query.page) || 1);
      const limit = Math.min(config.maxPageSize, Math.max(1, parseInt(query.limit) || config.defaultPageSize));
      const totalFiltered = data.length;
      return NextResponse.json({ items: data.slice((page - 1) * limit, (page - 1) * limit + limit), pagination: { page, limit, total: totalFiltered, totalFiltered, totalPages: Math.ceil(totalFiltered / limit) } });
    }
    if (pathStr === '/web-traffic/top-uris' && method === 'GET') {
      const traffic = readTable('network-traffic').filter(isWebFlow);
      const uriCount = {};
      traffic.forEach(f => { if (f.httpUri) uriCount[f.httpUri] = (uriCount[f.httpUri] || 0) + 1; });
      return NextResponse.json(Object.entries(uriCount).sort((a, b) => (b[1] as number) - (a[1] as number)).slice(0, 20).map(([uri, count]) => ({ uri, count: count as number })));
    }
    if (pathStr === '/web-traffic/top-hosts' && method === 'GET') {
      const traffic = readTable('network-traffic').filter(isWebFlow);
      const hostCount = {};
      traffic.forEach(f => { if (f.httpHost) hostCount[f.httpHost] = (hostCount[f.httpHost] || 0) + 1; });
      return NextResponse.json(Object.entries(hostCount).sort((a, b) => (b[1] as number) - (a[1] as number)).slice(0, 20).map(([host, count]) => ({ host, count: count as number })));
    }
    if (pathStr === '/web-traffic/errors' && method === 'GET') {
      const traffic = readTable('network-traffic').filter(isWebFlow);
      const errors = traffic.filter(f => f.httpStatus && f.httpStatus >= 400);
      const byUri: Record<string, { uri: string; total: number; '4xx': number; '5xx': number }> = {}; const byCode: Record<string, number> = {};
      errors.forEach(f => {
        const uri = f.httpUri || '/unknown';
        if (!byUri[uri]) byUri[uri] = { uri, total: 0, '4xx': 0, '5xx': 0 };
        byUri[uri].total++;
        if (f.httpStatus >= 500) byUri[uri]['5xx']++; else byUri[uri]['4xx']++;
        byCode[String(f.httpStatus)] = (byCode[String(f.httpStatus)] || 0) + 1;
      });
      return NextResponse.json({
        totalErrors: errors.length, errorRate: traffic.length > 0 ? parseFloat((errors.length / traffic.length * 100).toFixed(1)) : 0,
        byUri: Object.values(byUri).sort((a, b) => b.total - a.total).slice(0, 20),
        byCode: Object.entries(byCode).sort((a, b) => (b[1] as number) - (a[1] as number)).map(([code, count]) => ({ code: parseInt(code), count: count as number }))
      });
    }
    if (pathStr === '/web-traffic/export' && method === 'GET') {
      return handleWebCsvExport();
    }

    // ---- Automations Log ----
    if (pathStr === '/automations/log' && method === 'GET') {
      const logFile = path.join(DATA_DIR, 'automations-log.json');
      try {
        const raw = fs.readFileSync(logFile, 'utf8');
        const data = JSON.parse(raw);
        const page = Math.max(1, parseInt(query.page) || 1);
        const limit = Math.min(200, Math.max(1, parseInt(query.limit) || 50));
        const offset = (page - 1) * limit;
        return NextResponse.json({ items: data.reverse().slice(offset, offset + limit), pagination: { page, limit, total: data.length, totalPages: Math.ceil(data.length / limit) } });
      } catch { return NextResponse.json({ items: [], pagination: { page: 1, limit: 50, total: 0, totalPages: 0 } }); }
    }

    // ---- Automation Triggers ----
    if (pathStr === '/automations/trigger/severity-critical' && method === 'POST') {
      const u = authenticate(req); authorize(u, 'admin', 'analyst');
      const incidents = readTable('incidents');
      const critical = incidents.filter(i => i.severity === 'Critical' && i.status !== 'Resolved' && i.status !== 'Closed');
      if (critical.length === 0) return NextResponse.json({ triggered: false, message: 'No critical open incidents found' });
      critical.forEach(i => logAutomation('manual_critical_severity_alert', { incidentId: i.id, title: i.title, message: `CRITICAL ALERT: Incident #${i.id} "${i.title}"` }));
      return NextResponse.json({ triggered: true, count: critical.length, incidents: critical.map(i => i.id) });
    }
    if (pathStr === '/automations/trigger/resolved-asset-update' && method === 'POST') {
      const u = authenticate(req); authorize(u, 'admin', 'analyst');
      const incidents = readTable('incidents');
      const assets = readTable('network-assets');
      let updatedCount = 0;
      incidents.filter(i => i.status === 'Resolved').forEach(inc => {
        const matchingAsset = assets.find(a => inc.sourceIp && a.ipRange && (inc.sourceIp.startsWith(a.ipRange.split('/')[0].replace('.0', '')) || inc.sourceIp === a.ipRange.split('/')[0]));
        if (matchingAsset) { logAutomation('resolved_asset_link', { incidentId: inc.id, assetId: matchingAsset.id, assetName: matchingAsset.assetName, message: `Resolved incident #${inc.id} linked to asset.` }); updatedCount++; }
      });
      return NextResponse.json({ triggered: true, updatedCount, message: `${updatedCount} resolved incidents linked to assets` });
    }

    // ---- Framework ----
    if (pathStr === '/framework/csf' && method === 'GET') {
      const allPlaybooks = readTable('playbooks');
      const allPolicies = readTable('security-policies');
      const allStandards = readTable('security-standards');
      return NextResponse.json(CSF_FUNCTIONS.map(csf => {
        const incidents = readTable('incidents').filter(i => i.csfFunction === csf.id);
        const rules = readTable('detection-rules').filter(r => r.csfFunction === csf.id);
        const playbooks = allPlaybooks.filter(p => (p.csfFunctions && p.csfFunctions.includes(csf.id)) || p.csfFunction === csf.id);
        const policies = allPolicies.filter(p => p.csfFunction === csf.id);
        const standards = allStandards.filter(s => s.csfFunction === csf.id);
        return { ...csf, incidentCount: incidents.length, ruleCount: rules.length, playbookCount: playbooks.length, policyCount: policies.length, standardCount: standards.length };
      }));
    }

    // ---- Asset Logs ----
    if (pathStr === '/asset-logs' && method === 'GET') {
      const u = authenticate(req); authorize(u, 'admin', 'analyst');
      const logs = readTableSafe('asset-logs');
      const assetId = parseInt(query.assetId);
      return NextResponse.json((assetId ? logs.filter(l => l.assetId === assetId) : logs).reverse());
    }

    // ---- Generic CRUD ----
    const tableMatch = pathStr.match(/^\/(\w[\w-]*)$/);
    const tableIdMatch = pathStr.match(/^\/(\w[\w-]*)\/(\d+)$/);
    const tableExportMatch = pathStr.match(/^\/(\w[\w-]*)\/export$/);

    if (tableExportMatch) {
      const table = tableExportMatch[1];
      if (ALL_TABLES.includes(table)) {
        return handleTableExport(table);
      }
    }

    if (tableIdMatch) {
      const table = tableIdMatch[1];
      const id = parseInt(tableIdMatch[2]);
      if (ALL_TABLES.includes(table)) {
        if (method === 'GET') {
          const data = readTable(table);
          const item = data.find(d => d.id === id);
          if (!item) return errorResponse(404, 'Not found');
          return NextResponse.json(item);
        }
        if (method === 'PUT' && WRITABLE_TABLES.includes(table)) {
          const u = authenticate(req); authorize(u, 'admin', 'analyst');
          const data = readTable(table);
          const idx = data.findIndex(d => d.id === id);
          if (idx === -1) return errorResponse(404, 'Not found');
          const oldItem = { ...data[idx] };
          data[idx] = { ...data[idx], ...body, id: data[idx].id };
          writeTable(table, data);
          audit({ user: { id: u.id, username: u.username, role: u.role }, method: 'PUT', path: `/api/${table}/${id}` }, 'update', { table, id, changes: Object.keys(body) });
          if (table === 'incidents') runAutomations('incident.updated', data[idx], data, oldItem);
          if (table === 'engineering-tasks') runAutomations('task.updated', data[idx], data, oldItem);
          try { alerting.notify(`incident.updated`, { item: data[idx], timestamp: new Date().toISOString(), user: 'system' }); } catch {}
          return NextResponse.json(data[idx]);
        }
        if (method === 'DELETE' && WRITABLE_TABLES.includes(table)) {
          const u = authenticate(req); authorize(u, 'admin');
          const data = readTable(table);
          const idx = data.findIndex(d => d.id === id);
          if (idx === -1) return errorResponse(404, 'Not found');
          data.splice(idx, 1);
          writeTable(table, data);
          audit({ user: { id: u.id, username: u.username, role: u.role }, method: 'DELETE', path: `/api/${table}/${id}` }, 'delete', { table, id });
          return new NextResponse(null, { status: 204 });
        }
      }
    }

    if (tableMatch) {
      const table = tableMatch[1];
      if (ALL_TABLES.includes(table)) {
        if (method === 'GET') {
          const result = readTablePaginated(table, query);
          return NextResponse.json(result);
        }
        if (method === 'POST' && WRITABLE_TABLES.includes(table)) {
          const u = authenticate(req); authorize(u, 'admin', 'analyst');
          const data = readTable(table);
          const item = { id: nextId(data), ...body };
          data.push(item);
          writeTable(table, data);
          audit({ user: { id: u.id, username: u.username, role: u.role }, method: 'POST', path: `/api/${table}` }, 'create', { table, id: item.id });
          if (table === 'incidents') runAutomations('incident.created', item, data, null);
          if (table === 'engineering-tasks') runAutomations('task.created', item, data, null);
          try { alerting.notify(`incident.created`, { item, timestamp: new Date().toISOString(), user: 'system' }); } catch {}
          return NextResponse.json(item, { status: 201 });
        }
      }
    }

    // ---- Network Assets Scans ----
    if (pathStr === '/network-assets/scan' && method === 'POST') {
      const u = authenticate(req); authorize(u, 'admin', 'analyst');
      const { ipRange } = body;
      if (!ipRange) return errorResponse(400, 'ipRange is required');
      const baseIp = ipRange.split('/')[0].split('-')[0];
      const reachable = Math.random() > 0.2;
      const ports = reachable ? [22, 80, 443, 3389, 8080].filter(() => Math.random() > 0.4) : [];
      const result = {
        ip: baseIp, reachable, pingMs: reachable ? Math.floor(Math.random() * 150 + 5) : null,
        openPorts: ports.map(port => ({ port, service: { 22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3389: 'RDP', 8080: 'HTTP-Alt' }[port] || 'Unknown', state: 'open' })),
        osHints: reachable ? ['Linux', 'Windows', 'Network Device'][Math.floor(Math.random() * 3)] : null,
        macAddress: reachable ? Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':') : null,
        hostname: reachable ? `host-${baseIp.replace(/\./g, '-')}.internal.local` : null,
        scanDuration: parseFloat((Math.random() * 2 + 0.3).toFixed(1)), scannedAt: new Date().toISOString()
      };
      logAutomation('asset_scan', { ipRange, reachable: result.reachable, openPortCount: result.openPorts.length });
      return NextResponse.json(result);
    }

    // ---- Network Assets Log Collection ----
    if (pathStr.match(/^\/network-assets\/\d+\/collect-logs$/) && method === 'POST') {
      const u = authenticate(req); authorize(u, 'admin', 'analyst');
      const assetId = parseInt(pathStr.split('/')[3]);
      const assets = readTable('network-assets');
      const asset = assets.find(a => a.id === assetId);
      if (!asset) return errorResponse(404, 'Asset not found');
      const collection = { id: nextId(readTableSafe('asset-logs')), assetId: asset.id, assetName: asset.assetName, collectedAt: new Date().toISOString(), logSource: asset.type, samples: [] };
      const logs = readTableSafe('asset-logs'); logs.push(collection); writeTable('asset-logs', logs);
      return NextResponse.json(collection);
    }

    // ---- Events (SSE placeholder) ----
    if (pathStr === '/events' && method === 'GET') {
      return NextResponse.json({ type: 'connected', note: 'SSE not available in serverless mode' });
    }

    // ---- PCAP ----
    if (pathStr === '/pcap/captures' && method === 'GET') {
      const u = authenticate(req); authorize(u, 'admin', 'analyst');
      const captures = pcap.readMeta().reverse();
      return NextResponse.json({ items: captures, total: captures.length });
    }
    if (pathStr === '/pcap/status' && method === 'GET') {
      return NextResponse.json({ tsharkAvailable: pcap.isTsharkAvailable(), tsharkPath: pcap.findTshark(), captureDir: pcap.PCAP_DIR, captureCount: pcap.readMeta().length });
    }
    if (pathStr === '/pcap/validate-filter' && method === 'POST') {
      try {
        const result = await pcap.validateDisplayFilter(body.filter);
        return NextResponse.json(result);
      } catch (e) { return NextResponse.json({ valid: false, error: e.message }); }
    }

    // ---- Monitor ----
    if (pathStr.startsWith('/monitor/')) {
      const subPath = pathStr.slice(9);
      try {
        if (subPath === 'connections' && method === 'GET') return NextResponse.json(monitor.getConnections() || []);
        if (subPath === 'ports' && method === 'GET') return NextResponse.json(monitor.getOpenPorts() || []);
        if (subPath === 'interfaces' && method === 'GET') return NextResponse.json(monitor.getTrafficStats() || []);
        if (subPath === 'system' && method === 'GET') return NextResponse.json(monitor.getSystemInfo() || {});
        if (subPath === 'bandwidth' && method === 'GET') return NextResponse.json(monitor.getBandwidthUsage() || []);
        if (subPath === 'arp' && method === 'GET') return NextResponse.json(monitor.getArpTable() || []);
        if (subPath === 'dns-cache' && method === 'GET') return NextResponse.json(monitor.getDnsCache() || []);
        if (subPath === 'routing-table' && method === 'GET') return NextResponse.json(monitor.getRoutingTable() || []);
        if (subPath === 'scan' && method === 'POST') {
          const { subnet } = body;
          if (!subnet) return errorResponse(400, 'subnet is required');
          return NextResponse.json(monitor.scanNetwork(subnet.split('/')[0].split('.').slice(0, 3).join('.') + '.0') || []);
        }
        const procMatch = subPath.match(/^process\/(\d+)$/);
        if (procMatch && method === 'GET') return NextResponse.json(monitor.getProcessDetail(procMatch[1]) || { error: 'Process not found' });
      } catch (err) { return NextResponse.json([]); }
    }

    // ---- MITRE ----
    if (pathStr === '/mitre/tactics' && method === 'GET') return NextResponse.json(mitre.getTactics());
    if (pathStr === '/mitre/techniques' && method === 'GET') {
      let techniques = mitre.getTechniques();
      if (query.tactic) techniques = techniques.filter(t => t.tacticId === query.tactic);
      if (query.platform) techniques = mitre.getTechniquesByPlatform(query.platform);
      if (query.search) techniques = mitre.search(query.search);
      return NextResponse.json(techniques);
    }
    const mitreTechId = pathStr.match(/^\/mitre\/techniques\/(.+)$/);
    if (mitreTechId && method === 'GET') {
      const technique = mitre.getTechniqueById(mitreTechId[1]);
      if (!technique) return errorResponse(404, 'Technique not found');
      return NextResponse.json(technique);
    }
    const mitreTacticId = pathStr.match(/^\/mitre\/tactics\/(.+)$/);
    if (mitreTacticId && method === 'GET') {
      const tactic = mitre.getTacticById(mitreTacticId[1]);
      if (!tactic) return errorResponse(404, 'Tactic not found');
      const techniques = mitre.getTechniquesByTactic(mitreTacticId[1]);
      return NextResponse.json({ ...tactic, techniques });
    }
    if (pathStr === '/mitre/map-attack-type' && method === 'POST') {
      const { attackType } = body;
      if (!attackType) return errorResponse(400, 'attackType required');
      const techniques = mitre.mapAttackTypeToTechniques(attackType);
      return NextResponse.json({ attackType, mappedTechniques: techniques, recommendedDetections: mitre.getRecommendedDetections(techniques.map(t => t.id)) });
    }

    // ---- Syslog ----
    let syslogServerRunning = false;
    if (pathStr === '/syslog/status' && method === 'GET') return NextResponse.json({ running: syslogServerRunning });
    if (pathStr === '/syslog/start' && method === 'POST') {
      if (syslogServerRunning) return NextResponse.json({ status: 'already_running' });
      const { udpPort = 514, tcpPort = 601, udp = true, tcp = false } = body;
      try { syslog.startSyslogServer({ udp, tcp, udpPort, tcpPort }); syslogServerRunning = true; return NextResponse.json({ status: 'started', udp, tcp, udpPort, tcpPort }); }
      catch (err) { return errorResponse(500, err.message); }
    }
    if (pathStr === '/syslog/stop' && method === 'POST') { syslog.stopSyslogServer(); syslogServerRunning = false; return NextResponse.json({ status: 'stopped' }); }
    if (pathStr === '/syslog/logs' && method === 'GET') {
      const limit = Math.min(500, parseInt(query.limit) || 100); const offset = Math.max(0, parseInt(query.offset) || 0);
      return NextResponse.json(syslog.getCollectedLogs(limit, offset));
    }
    if (pathStr === '/syslog/stats' && method === 'GET') return NextResponse.json(syslog.getLogStats());
    if (pathStr === '/syslog/clear' && method === 'POST') { syslog.clearLogs(); return NextResponse.json({ status: 'cleared' }); }
    if (pathStr === '/syslog/windows-events' && method === 'GET') {
      try { const events = await syslog.getWindowsEvents({ logName: query.logName || 'Security', maxEvents: parseInt(query.maxEvents) || 100, eventIds: query.eventIds ? query.eventIds.split(',').map(Number) : [] }); return NextResponse.json(events || []); }
      catch { return NextResponse.json([]); }
    }
    if (pathStr === '/syslog/windows-logs' && method === 'GET') return NextResponse.json(syslog.getEventLogs() || []);

    // ---- Snort ----
    if (pathStr === '/snort/sample-rules' && method === 'GET') return NextResponse.json(snort.exportSampleRules ? snort.exportSampleRules() : snort.parseRules([]));
    if (pathStr === '/snort/parse' && method === 'POST') { try { return NextResponse.json(snort.parseRule(body.rule)); } catch (err) { return errorResponse(400, err.message); } }
    if (pathStr === '/snort/validate' && method === 'POST') return NextResponse.json(snort.validateRule(body.rule));
    if (pathStr === '/snort/convert' && method === 'POST') { try { const parsed = snort.parseRule(body.rule); return NextResponse.json({ snortRule: parsed, nidsRule: snort.convertToNidsRule(parsed) }); } catch (err) { return errorResponse(400, err.message); } }
    if (pathStr === '/snort/correlate' && method === 'POST') {
      const { flowId } = body; if (!flowId) return errorResponse(400, 'flowId required');
      const traffic = readTable('network-traffic'); const flow = traffic.find(f => f.id === parseInt(flowId));
      if (!flow) return errorResponse(404, 'Flow not found');
      return NextResponse.json(snort.correlateAlert(flow, readTable('detection-rules')));
    }
    if (pathStr === '/snort/correlation-stats' && method === 'GET') return NextResponse.json(snort.getCorrelationStats());

    // ---- Agents ----
    if (pathStr === '/agents' && method === 'GET') return NextResponse.json(agent.getRegisteredAgents());
    if (pathStr === '/agents/register' && method === 'POST') {
      const { type, host, port, username, authType } = body;
      if (!type || !host) return errorResponse(400, 'type and host required');
      return NextResponse.json(agent.registerAgent({ type, host, port: port || 22, username: username || 'root', authType: authType || 'password', ...body }), { status: 201 });
    }
    if (pathStr.match(/^\/agents\/\d+$/) && method === 'DELETE') { agent.removeAgent(pathStr.split('/')[2]); return new NextResponse(null, { status: 204 }); }
    if (pathStr === '/agents/collect' && method === 'POST') { const results = await agent.collectFromAllAgents(); return NextResponse.json(results); }
    if (pathStr === '/agents/discover' && method === 'POST') { const { subnet } = body; if (!subnet) return errorResponse(400, 'subnet required'); return NextResponse.json(agent.discoverAgents(subnet)); }
    if (pathStr === '/agents/server/start' && method === 'POST') { const { port = 9100 } = body; agent.startAgentServer(port); return NextResponse.json({ status: 'started', port }); }
    if (pathStr === '/agents/server/stop' && method === 'POST') { agent.stopAgentServer(); return NextResponse.json({ status: 'stopped' }); }

    // ---- SOAR ----
    if (pathStr === '/soar/playbooks/builtin' && method === 'GET') return NextResponse.json(soar.getBuiltinPlaybooks());
    if (pathStr.match(/^\/soar\/playbooks\/builtin\/(.+)$/) && method === 'GET') {
      const pb = soar.getBuiltinPlaybook(pathStr.split('/').pop());
      if (!pb) return errorResponse(404, 'Playbook not found');
      return NextResponse.json(pb);
    }
    if (pathStr === '/soar/execute' && method === 'POST') {
      const { playbookId, context = {} } = body; if (!playbookId) return errorResponse(400, 'playbookId required');
      let playbook = readTableSafe('playbooks').find(p => p.id === parseInt(playbookId) || p.id === playbookId);
      if (!playbook) playbook = soar.getBuiltinPlaybook(playbookId);
      if (!playbook) return errorResponse(404, 'Playbook not found');
      const executionId = await soar.startPlaybook(playbook, context);
      return NextResponse.json({ executionId, status: 'started', playbook: playbook.name }, { status: 201 });
    }
    if (pathStr.match(/^\/soar\/stop\/(.+)$/) && method === 'POST') { soar.stopPlaybook(pathStr.split('/').pop()); return NextResponse.json({ status: 'stopped' }); }
    if (pathStr === '/soar/executions' && method === 'GET') { const { status } = query; return NextResponse.json(soar.listExecutions(status ? { status } : {})); }
    if (pathStr.match(/^\/soar\/executions\/(.+)$/) && method === 'GET') {
      const exec = soar.getPlaybookStatus(pathStr.split('/').pop());
      if (!exec) return errorResponse(404, 'Execution not found');
      return NextResponse.json(exec);
    }
    if (pathStr === '/soar/executions' && method === 'DELETE') { soar.clearExecutions(); return new NextResponse(null, { status: 204 }); }

    // ---- FIM ----
    if (pathStr === '/fim/baseline' && method === 'GET') return NextResponse.json(fim.getBaseline());
    if (pathStr === '/fim/baseline' && method === 'POST') {
      const { paths } = body; if (!paths || !Array.isArray(paths) || paths.length === 0) return errorResponse(400, 'paths array required');
      try { const baseline = fim.createBaseline(paths); return NextResponse.json({ fileCount: baseline.length, baseline }, { status: 201 }); }
      catch (err) { return errorResponse(400, err.message); }
    }
    if (pathStr === '/fim/baseline/add' && method === 'POST') { try { return NextResponse.json(fim.addToBaseline(body.filePath), { status: 201 }); } catch (err) { return errorResponse(400, err.message); } }
    if (pathStr === '/fim/baseline' && method === 'DELETE') { if (body.filePath) fim.removeFromBaseline(body.filePath); else fim.clearBaseline(); return new NextResponse(null, { status: 204 }); }
    if (pathStr === '/fim/scan' && method === 'POST') { try { return NextResponse.json(fim.runScan()); } catch (err) { return errorResponse(500, err.message); } }
    if (pathStr === '/fim/scans' && method === 'GET') return NextResponse.json(fim.getScanHistory(Math.min(100, parseInt(query.limit) || 10)));
    if (pathStr === '/fim/last-scan' && method === 'GET') return NextResponse.json(fim.getLastScan() || { status: 'no_scans' });
    if (pathStr === '/fim/watch/start' && method === 'POST') { fim.startWatcher((body.interval || 60) * 1000); return NextResponse.json({ status: 'watching', interval: body.interval || 60 }); }
    if (pathStr === '/fim/watch/stop' && method === 'POST') { fim.stopWatcher(); return NextResponse.json({ status: 'stopped' }); }
    if (pathStr === '/fim/report' && method === 'GET') return NextResponse.json(fim.getFIMReport ? fim.getFIMReport() : {});
    if (pathStr === '/fim/config' && method === 'GET') return NextResponse.json(fim.getConfig ? fim.getConfig() : {});
    if (pathStr === '/fim/config' && method === 'PUT') { if (fim.saveConfig) fim.saveConfig(body); return NextResponse.json({ status: 'ok' }); }

    // ---- VulnScan ----
    if (pathStr === '/vulnscan/scan' && method === 'POST') {
      const { targets } = body; if (!targets || !Array.isArray(targets) || targets.length === 0) return errorResponse(400, 'targets array required');
      const scanId = vulnscan.startScan(targets); return NextResponse.json({ scanId, targets, status: 'running' }, { status: 201 });
    }
    if (pathStr === '/vulnscan/scans' && method === 'GET') return NextResponse.json(vulnscan.getScanHistory());
    if (pathStr.match(/^\/vulnscan\/scan\/([^/]+)$/) && method === 'GET') {
      const scan = vulnscan.getScanStatus(pathStr.split('/').pop());
      if (!scan) return errorResponse(404, 'Scan not found');
      return NextResponse.json(scan);
    }
    if (pathStr.match(/^\/vulnscan\/scan\/([^/]+)\/results$/) && method === 'GET') {
      const results = vulnscan.getScanResults(pathStr.split('/')[2]);
      if (!results) return errorResponse(404, 'Scan not found or not completed');
      return NextResponse.json(results);
    }
    if (pathStr.match(/^\/vulnscan\/scan\/([^/]+)\/cancel$/) && method === 'POST') { vulnscan.cancelScan(pathStr.split('/')[2]); return NextResponse.json({ status: 'cancelled' }); }
    if (pathStr === '/vulnscan/assess-asset' && method === 'POST') {
      const { assetId } = body; if (!assetId) return errorResponse(400, 'assetId required');
      const assets = readTable('network-assets'); const asset = assets.find(a => a.id === parseInt(assetId));
      if (!asset) return errorResponse(404, 'Asset not found');
      return NextResponse.json(vulnscan.assessAsset(asset));
    }
    if (pathStr === '/vulnscan/vulnerabilities' && method === 'GET') {
      let vulns = vulnscan.vulnerabilityDatabase || [];
      if (query.severity) vulns = vulns.filter(v => v.severity === query.severity);
      if (query.search) vulns = vulns.filter(v => v.description.toLowerCase().includes(query.search.toLowerCase()) || v.id.toLowerCase().includes(query.search.toLowerCase()));
      return NextResponse.json(vulns);
    }
    if (pathStr === '/vulnscan/report' && method === 'GET') return NextResponse.json(vulnscan.getVulnerabilityReport ? vulnscan.getVulnerabilityReport({}) : {});

    // ---- Compliance ----
    if (pathStr === '/compliance/frameworks' && method === 'GET') {
      return NextResponse.json([
        { id: 'pci-dss', name: 'PCI DSS v4.0', controls: compliance.pciDssData ? compliance.pciDssData.length : 0 },
        { id: 'hipaa', name: 'HIPAA Security Rule', controls: compliance.hipaaData ? compliance.hipaaData.length : 0 },
        { id: 'gdpr', name: 'GDPR', controls: compliance.gdprData ? compliance.gdprData.length : 0 }
      ]);
    }
    if (pathStr === '/compliance/dashboard' && method === 'GET') {
      const dashboard = {};
      for (const fw of ['pci-dss', 'hipaa', 'gdpr']) dashboard[fw] = compliance.getComplianceStatus(fw);
      return NextResponse.json(dashboard);
    }
    if (pathStr === '/compliance/recommendations' && method === 'GET') {
      const frameworks = query.frameworks ? query.frameworks.split(',') : ['pci-dss', 'hipaa', 'gdpr'];
      const recommendations = [];
      for (const fw of frameworks) { const status = compliance.getComplianceStatus(fw); if (status.recommendations) recommendations.push(...status.recommendations.map(r => ({ ...r, framework: fw }))); }
      return NextResponse.json(recommendations);
    }
    const complianceFw = pathStr.match(/^\/compliance\/(pci-dss|hipaa|gdpr)$/);
    if (complianceFw && method === 'GET') return NextResponse.json(compliance.getComplianceStatus(complianceFw[1]));
    const complianceCtrl = pathStr.match(/^\/compliance\/(pci-dss|hipaa|gdpr)\/controls$/);
    if (complianceCtrl && method === 'GET') return NextResponse.json({ 'pci-dss': compliance.pciDssData, 'hipaa': compliance.hipaaData, 'gdpr': compliance.gdprData }[complianceCtrl[1]] || []);
    const complianceReport = pathStr.match(/^\/compliance\/(pci-dss|hipaa|gdpr)\/report$/);
    if (complianceReport && method === 'GET') return NextResponse.json(compliance.generateReport(complianceReport[1], { format: 'json' }));

    // ---- ML ----
    if (pathStr === '/ml/detect-anomalies' && method === 'POST') {
      const { data, field, method: mlMethod = 'zscore', threshold = 3 } = body;
      if (!data || !field) return errorResponse(400, 'data and field required');
      try { return NextResponse.json(ml.detectAnomalies(data, field, { method: mlMethod, threshold })); } catch (err) { return errorResponse(400, err.message); }
    }
    if (pathStr === '/ml/traffic-baseline' && method === 'POST') {
      const traffic = readTable('network-traffic');
      const baseline = ml.buildTrafficBaseline(traffic); ml.saveModel('traffic-baseline', baseline);
      return NextResponse.json({ status: 'baseline_built', recordCount: traffic.length, timestamp: baseline.lastUpdated });
    }
    if (pathStr === '/ml/detect-traffic-anomalies' && method === 'POST') {
      let baseline;
      try { baseline = ml.loadModel('traffic-baseline'); } catch { baseline = null; }
      if (!baseline) return errorResponse(400, 'No traffic baseline. Build one first.');
      return NextResponse.json(ml.detectTrafficAnomalies(readTable('network-traffic'), baseline));
    }
    if (pathStr === '/ml/threshold-rule' && method === 'POST') {
      const { name, field, operator, value, window, cooldown } = body;
      if (!name || !field || !operator || value === undefined) return errorResponse(400, 'name, field, operator, value required');
      return NextResponse.json(ml.createThresholdRule(name, { field, operator, value, window: window || 300, cooldown: cooldown || 600 }), { status: 201 });
    }
    if (pathStr === '/ml/threshold-rules' && method === 'GET') return NextResponse.json(ml.getActiveThresholds());
    if (pathStr === '/ml/models' && method === 'GET') return NextResponse.json(ml.listModels());
    if (pathStr.match(/^\/ml\/models\/(.+)$/) && method === 'DELETE') { ml.deleteModel(pathStr.split('/').pop()); return new NextResponse(null, { status: 204 }); }

    // ---- Retention ----
    if (pathStr === '/retention/policies' && method === 'GET') return NextResponse.json(retention.getPolicies());
    if (pathStr === '/retention/policies' && method === 'POST') return NextResponse.json(retention.savePolicy(body), { status: 201 });
    if (pathStr.match(/^\/retention\/policies\/(\d+)$/) && method === 'DELETE') { retention.deletePolicy(pathStr.split('/').pop()); return new NextResponse(null, { status: 204 }); }
    if (pathStr === '/retention/run' && method === 'POST') return NextResponse.json(retention.runOnce());
    if (pathStr === '/retention/report' && method === 'GET') return NextResponse.json(retention.getRetentionReport());
    if (pathStr === '/retention/archives' && method === 'GET') return NextResponse.json(retention.getArchives ? retention.getArchives() : []);
    if (pathStr.match(/^\/retention\/archives\/(\d+)\/restore$/) && method === 'POST') return NextResponse.json(retention.restoreArchive(pathStr.split('/')[2]) || { status: 'restored' });
    if (pathStr.match(/^\/retention\/archives\/(\d+)$/) && method === 'DELETE') { retention.deleteArchive(pathStr.split('/').pop()); return new NextResponse(null, { status: 204 }); }
    if (pathStr === '/retention/holds' && method === 'GET') return NextResponse.json(retention.getLegalHolds());
    if (pathStr === '/retention/holds' && method === 'POST') return NextResponse.json(retention.addLegalHold(body), { status: 201 });
    if (pathStr.match(/^\/retention\/holds\/(\d+)$/) && method === 'DELETE') { retention.removeLegalHold(pathStr.split('/').pop()); return new NextResponse(null, { status: 204 }); }
    if (pathStr === '/retention/storage-forecast' && method === 'GET') return NextResponse.json(retention.getStorageForecast(parseInt(query.days) || 90));

    // ---- Alerting ----
    if (pathStr === '/alerting/config' && method === 'GET') return NextResponse.json(alerting.getConfig());
    if (pathStr === '/alerting/config' && method === 'PUT') { alerting.saveConfig(body); return NextResponse.json({ status: 'ok' }); }
    if (pathStr === '/alerting/test' && method === 'POST') {
      const { type = 'email' } = body;
      const cfg = alerting.getConfig();
      let result;
      if (type === 'email' && cfg.email.enabled) result = await alerting.sendEmail({ to: cfg.email.to || 'test@example.com', subject: 'NIDS Alert Test', html: '<h1>Test Alert</h1>' });
      else if (type === 'slack' && cfg.slack.enabled) result = await alerting.sendSlack({ webhookUrl: cfg.slack.webhookUrl, text: 'NIDS Test Alert' });
      else if (type === 'webhook' && cfg.webhook.enabled) result = await alerting.sendWebhook({ url: cfg.webhook.url, method: cfg.webhook.method || 'POST', body: { test: true } });
      return NextResponse.json(result || { success: false, error: `${type} not configured or disabled` });
    }

    // ---- DB Stats ----
    if (pathStr === '/db/stats' && method === 'GET') return NextResponse.json(db.getStats());

    // ---- PCAP-specific routes that need more handling ---
    if (pathStr.match(/^\/pcap\/captures\/(\d+)\/analysis\/protocols$/) && method === 'GET') {
      try { return NextResponse.json(await pcap.getProtocolHierarchy(pathStr.split('/')[2])); } catch (e) { return NextResponse.json({ error: e.message }, { status: 500 }); }
    }
    if (pathStr.match(/^\/pcap\/captures\/(\d+)\/analysis\/endpoints$/) && method === 'GET') {
      try { return NextResponse.json(await pcap.getEndpoints(pathStr.split('/')[2], query.type || 'ip')); } catch (e) { return NextResponse.json({ error: e.message }, { status: 500 }); }
    }
    if (pathStr.match(/^\/pcap\/captures\/(\d+)\/analysis\/conversations$/) && method === 'GET') {
      try { return NextResponse.json(await pcap.getConversations(pathStr.split('/')[2], query.type || 'ip')); } catch (e) { return NextResponse.json({ error: e.message }, { status: 500 }); }
    }
    if (pathStr.match(/^\/pcap\/captures\/(\d+)\/analysis\/http$/) && method === 'GET') {
      try { return NextResponse.json(await pcap.getHttpAnalysis(pathStr.split('/')[2])); } catch (e) { return NextResponse.json({ error: e.message }, { status: 500 }); }
    }
    if (pathStr.match(/^\/pcap\/captures\/(\d+)\/packets$/) && method === 'GET') {
      try {
        const filter = query.filter || ''; const limit = Math.min(500, parseInt(query.limit) || 200); const offset = Math.max(0, parseInt(query.offset) || 0);
        return NextResponse.json(await pcap.getPackets(pathStr.split('/')[2], filter, limit, offset));
      } catch (e) { return NextResponse.json({ error: e.message }, { status: 500 }); }
    }
    if (pathStr.match(/^\/pcap\/captures\/(\d+)\/export$/) && method === 'GET') {
      try {
        const { filePath } = await pcap.getPcapFile(pathStr.split('/')[2]);
        const file = fs.readFileSync(filePath);
        return new NextResponse(file, { headers: { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${path.basename(filePath)}"` } });
      } catch (e) { return errorResponse(404, e.message); }
    }
    if (pathStr.match(/^\/pcap\/captures\/(\d+)$/) && method === 'GET') {
      try { return NextResponse.json(await pcap.getCaptureMetadata(pathStr.split('/')[2])); } catch (e) { return errorResponse(404, e.message); }
    }
    if (pathStr.match(/^\/pcap\/captures\/(\d+)$/) && method === 'DELETE') {
      try {
        const id = parseInt(pathStr.split('/')[2]);
        const { record, filePath: pcapFile } = await pcap.getPcapFile(id);
        fs.unlinkSync(pcapFile);
        const meta = pcap.readMeta();
        pcap.writeMeta(meta.filter(m => m.id !== id));
        return new NextResponse(null, { status: 204 });
      } catch (e) { return errorResponse(404, e.message); }
    }

    // ---- Capture ----
    if (pathStr === '/capture/interfaces' && method === 'GET') {
      if (!pcap.isTsharkAvailable()) return NextResponse.json({ available: false, interfaces: [] });
      return NextResponse.json({ available: true, interfaces: await pcap.listInterfaces() });
    }
    if (pathStr === '/capture/start' && method === 'POST') {
      const { interface: iface, duration = 30, filter: capFilter = '' } = body;
      if (!iface) return errorResponse(400, 'interface is required');
      const captureId = await pcap.startLiveCapture(iface, parseInt(duration), capFilter);
      return NextResponse.json({ captureId, interface: iface, duration, filter: capFilter, startedAt: new Date().toISOString() }, { status: 201 });
    }
    if (pathStr === '/capture/stop' && method === 'POST') {
      const { captureId } = body; if (!captureId) return errorResponse(400, 'captureId is required');
      pcap.stopLiveCapture(captureId); return NextResponse.json({ status: 'stopped', captureId });
    }
    if (pathStr === '/capture/active' && method === 'GET') return NextResponse.json(pcap.getActiveCaptures());

    // ---- PCAP Upload ----
    if (pathStr === '/pcap/upload' && method === 'POST') {
      try {
        const formData = await req.formData();
        const file = formData.get('pcap') as File;
        if (!file) return errorResponse(400, 'No file uploaded');
        const ext = path.extname(file.name).toLowerCase();
        if (!['.pcap', '.pcapng', '.cap'].includes(ext)) return errorResponse(400, 'Only .pcap, .pcapng, .cap files allowed');
        const buffer = Buffer.from(await file.arrayBuffer());
        const newName = `capture-${Date.now()}${ext}`;
        const newPath = path.join(pcap.PCAP_DIR, newName);
        fs.writeFileSync(newPath, buffer);
        const stats = fs.statSync(newPath);
        let meta = { packets: null, duration: null, protocols: [] };
        if (pcap.isTsharkAvailable()) {
          try {
            const count = await pcap.tsharkRaw(['-r', newPath, '-T', 'fields', '-e', 'frame.number']);
            meta.packets = count.split('\n').filter(l => l.trim()).length;
          } catch {}
        }
        const record = pcap.createCaptureRecord(newName, file.name, stats.size, meta);
        return NextResponse.json(record, { status: 201 });
      } catch (e) { return errorResponse(500, e.message); }
    }

    return errorResponse(404, `Route ${method} ${pathStr} not found`);
  } catch (err) {
    if (err.isOperational) return NextResponse.json({ error: err.message }, { status: err.statusCode });
    console.error('[FATAL]', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

function handleResult(data) {
  if (data && data.statusCode) return NextResponse.json({ error: data.message }, { status: data.statusCode });
  return NextResponse.json(data);
}

function handleLogin(username, password) {
  const { loginRoute: login } = require('../../../lib/auth');
  const jwt = require('jsonwebtoken');
  const bcrypt = require('bcryptjs');
  const fs = require('fs');
  const path = require('path');
  const USERS_FILE = path.join(DATA_DIR, 'users.json');
  let users;
  try { users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { users = []; }
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
  }
  user.lastLogin = new Date().toISOString();
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, config.jwtSecret, { expiresIn: config.jwtExpiresIn });
  const res = NextResponse.json({ token, user: { id: user.id, username: user.username, role: user.role, displayName: user.displayName, email: user.email } });
  res.headers.append('Set-Cookie', cookie.serialize(config.cookieName, token, { httpOnly: true, sameSite: 'lax', maxAge: config.cookieMaxAge, path: '/' }));
  return res;
}

function handleLogout() {
  const res = NextResponse.json({ status: 'ok', message: 'Logged out' });
  res.headers.append('Set-Cookie', cookie.serialize(config.cookieName, '', { httpOnly: true, sameSite: 'lax', maxAge: 0, path: '/' }));
  return res;
}

function readJsonFile(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; } }
function writeJsonFile(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8'); }

function handleTableExport(table) {
  const data = readTable(table);
  if (data.length === 0) return errorResponse(404, 'No data to export');
  const headers = Object.keys(data[0]);
  const csv = [headers.join(','), ...data.map(row => headers.map(h => {
    const val = row[h];
    if (val === null || val === undefined) return '';
    const str = String(val);
    return str.includes(',') || str.includes('"') || str.includes('\n') ? `"${str.replace(/"/g, '""')}"` : str;
  }).join(','))].join('\n');
  return new NextResponse(csv, { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="${table}-${new Date().toISOString().split('T')[0]}.csv"` } });
}

function handleCsvExport(table, filterFn, prefix) {
  const data = readTable(table).filter(filterFn);
  if (data.length === 0) return errorResponse(404, 'No data to export');
  const headers = ['timestamp','srcIp','destIp','srcPort','destPort','protocol','httpMethod','httpUri','httpStatus','httpHost','httpUserAgent','httpContentType','bytes','duration','status'];
  const csv = [headers.join(','), ...data.map(row => headers.map(h => {
    const val = row[h];
    if (val === null || val === undefined) return '';
    const str = String(val);
    return str.includes(',') || str.includes('"') || str.includes('\n') ? `"${str.replace(/"/g, '""')}"` : str;
  }).join(','))].join('\n');
  return new NextResponse(csv, { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="${prefix}-${new Date().toISOString().split('T')[0]}.csv"` } });
}

function handleWebCsvExport() {
  const data = readTable('network-traffic').filter(isWebFlow);
  if (data.length === 0) return errorResponse(404, 'No web traffic data');
  const headers = ['timestamp','srcIp','destIp','srcPort','destPort','protocol','httpMethod','httpUri','httpStatus','httpHost','httpUserAgent','httpContentType','bytes','duration','status'];
  const csv = [headers.join(','), ...data.map(row => headers.map(h => {
    const val = row[h]; if (val === null || val === undefined) return '';
    const str = String(val);
    return str.includes(',') || str.includes('"') || str.includes('\n') ? `"${str.replace(/"/g, '""')}"` : str;
  }).join(','))].join('\n');
  return new NextResponse(csv, { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="web-traffic-${new Date().toISOString().split('T')[0]}.csv"` } });
}

// Stub alerting.notify
try { alerting.notify = alerting.notify || function() {}; } catch {}
