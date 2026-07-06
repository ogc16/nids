const express = require('express');
const router = express.Router();
const { authenticate, authorize, optionalAuth } = require('../lib/auth');
const { audit } = require('../lib/audit');
const config = require('../lib/config');
const db = require('../lib/db');
const sse = require('./sse');

function readTable(name) { return db.readTable(name); }

function isWebFlow(f) { return f.httpMethod || (f.protocol && (f.protocol === 'HTTP' || f.protocol === 'HTTPS')); }

router.get('/network-traffic/stats', optionalAuth, (req, res) => {
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

router.get('/network-traffic', optionalAuth, (req, res) => {
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

router.get('/web-traffic/summary', optionalAuth, (req, res) => {
  const traffic = readTable('network-traffic').filter(isWebFlow);
  const methodDist = {}; const statusGroups = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
  const uriCount = {}; const hostCount = {};
  traffic.forEach(f => {
    if (f.httpMethod) methodDist[f.httpMethod] = (methodDist[f.httpMethod] || 0) + 1;
    if (f.httpStatus) statusGroups[Math.floor(f.httpStatus / 100) + 'xx'] = (statusGroups[Math.floor(f.httpStatus / 100) + 'xx'] || 0) + 1;
    if (f.httpUri) uriCount[f.httpUri] = (uriCount[f.httpUri] || 0) + 1;
    if (f.httpHost) hostCount[f.httpHost] = (hostCount[f.httpHost] || 0) + 1;
  });
  res.json({
    totalRequests: traffic.length,
    methodDistribution: Object.entries(methodDist).map(([method, count]) => ({ method, count })),
    statusCodeGroups: statusGroups,
    topUris: Object.entries(uriCount).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([uri, count]) => ({ uri, count })),
    topHosts: Object.entries(hostCount).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([host, count]) => ({ host, count })),
    errorRate: traffic.length > 0 ? parseFloat((((statusGroups['4xx'] || 0) + (statusGroups['5xx'] || 0)) / traffic.length * 100).toFixed(1)) : 0,
    uniqueUris: Object.keys(uriCount).length,
    uniqueHosts: Object.keys(hostCount).length
  });
});

router.get('/web-traffic/requests', optionalAuth, (req, res) => {
  let data = readTable('network-traffic').filter(isWebFlow);
  const filter = req.query.displayFilter || '';
  if (filter) {
    try {
      data = data.filter(item => {
        try { const tokens = filter.match(/(?:[^\s"]+|"[^"]*")+/g) || []; return evaluateTokens(tokens, item); } catch { return true; }
      });
    } catch {}
  }
  const method = req.query.method || ''; const status = req.query.status || ''; const search = req.query.search || '';
  if (method) data = data.filter(f => f.httpMethod === method);
  if (status) data = data.filter(f => String(f.httpStatus).startsWith(status));
  if (search) data = data.filter(f => (f.httpUri || '').toLowerCase().includes(search) || (f.httpHost || '').toLowerCase().includes(search) || String(f.httpStatus).includes(search));
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(config.maxPageSize, Math.max(1, parseInt(req.query.limit) || config.defaultPageSize));
  const totalFiltered = data.length;
  const items = data.slice((page - 1) * limit, (page - 1) * limit + limit);
  res.json({ items, pagination: { page, limit, total: totalFiltered, totalFiltered, totalPages: Math.ceil(totalFiltered / limit) } });
});

router.get('/web-traffic/top-uris', optionalAuth, (req, res) => {
  const traffic = readTable('network-traffic').filter(isWebFlow);
  const uriCount = {};
  traffic.forEach(f => { if (f.httpUri) uriCount[f.httpUri] = (uriCount[f.httpUri] || 0) + 1; });
  const top = Object.entries(uriCount).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([uri, count]) => ({ uri, count }));
  res.json(top);
});

router.get('/web-traffic/top-hosts', optionalAuth, (req, res) => {
  const traffic = readTable('network-traffic').filter(isWebFlow);
  const hostCount = {};
  traffic.forEach(f => { if (f.httpHost) hostCount[f.httpHost] = (hostCount[f.httpHost] || 0) + 1; });
  const top = Object.entries(hostCount).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([host, count]) => ({ host, count }));
  res.json(top);
});

router.get('/web-traffic/errors', optionalAuth, (req, res) => {
  const traffic = readTable('network-traffic').filter(isWebFlow);
  const errors = traffic.filter(f => f.httpStatus && f.httpStatus >= 400);
  const byUri = {}; const byCode = {};
  errors.forEach(f => {
    const uri = f.httpUri || '/unknown';
    if (!byUri[uri]) byUri[uri] = { uri, total: 0, '4xx': 0, '5xx': 0 };
    byUri[uri].total++;
    if (f.httpStatus >= 500) byUri[uri]['5xx']++; else byUri[uri]['4xx']++;
    byCode[String(f.httpStatus)] = (byCode[String(f.httpStatus)] || 0) + 1;
  });
  res.json({
    totalErrors: errors.length,
    errorRate: traffic.length > 0 ? parseFloat((errors.length / traffic.length * 100).toFixed(1)) : 0,
    byUri: Object.values(byUri).sort((a, b) => b.total - a.total).slice(0, 20),
    byCode: Object.entries(byCode).sort((a, b) => b[1] - a[1]).map(([code, count]) => ({ code: parseInt(code), count }))
  });
});

router.get('/web-traffic/export', authenticate, (req, res) => {
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

router.post('/network-traffic/simulate', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const assets = readTable('network-assets');
  if (assets.length === 0) return res.status(400).json({ error: 'No assets found. Add an asset first.' });
  const asset = assets[Math.floor(Math.random() * assets.length)];
  const isExternal = Math.random() > 0.5;
  const protocol = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
  const flow = {
    id: db.nextId(readTable('network-traffic')),
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
  db.writeTable('network-traffic', traffic);
  audit('traffic_simulated', req, { flowId: flow.id });
  sse.broadcast('traffic-flow', flow);
  if (flow.status === 'suspicious' || flow.status === 'blocked') {
    const automations = require('./automations');
    if (automations && automations.logAutomation) automations.logAutomation('realtime_traffic_alert', {
      message: `${flow.status.toUpperCase()} traffic: ${flow.srcIp}:${flow.srcPort} -> ${flow.destIp}:${flow.destPort} (${flow.protocol})`,
      srcIp: flow.srcIp, destIp: flow.destIp, protocol: flow.protocol, status: flow.status
    });
  }
  res.status(201).json(flow);
});

router.post('/network-traffic/auto-simulate', authenticate, authorize('admin', 'analyst'), (req, res) => {
  const http = require('http');
  const { interval = 5000 } = req.body || {};
  const timer = setInterval(() => {
    http.request({ method: 'POST', hostname: 'localhost', port: config.port, path: '/api/network-traffic/simulate', headers: { 'Content-Type': 'application/json', ...(req.headers.authorization ? { Authorization: req.headers.authorization } : {}) } }, r => { r.resume(); }).end();
  }, interval);
  req.on('close', () => clearInterval(timer));
  res.json({ status: 'simulation_started', interval });
});

function evaluateTokens(tokens, item) {
  let result = true; let i = 0;
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
      else result = result && subResult;
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
      try { const re = new RegExp(value, 'i'); return re.test(strVal); } catch { return false; }
    default: return true;
  }
}

function getNidsFieldValue(field, item) {
  const map = {
    'ip.src': 'srcIp', 'ip.dst': 'destIp',
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

module.exports = router;
