const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { execSync } = require('child_process');
const crypto = require('crypto');
const config = require('./config');
const { ValidationError } = require('./errors');

const EXECUTIONS_FILE = path.join(config.dataDir, 'soar-executions.json');

const actionHandlers = {};
const executions = {};
const abortControllers = {};

function uuid() {
  return crypto.randomUUID();
}

function interpolate(str, context) {
  if (typeof str !== 'string') return str;
  return str.replace(/\{\{\s*([^}\s]+(?:\.[^}\s]+)*)\s*\}\}/g, (_, key) => {
    const val = key.split('.').reduce((o, k) => (o != null ? o[k] : undefined), context);
    return val != null ? val : `{{${key}}}`;
  });
}

function deepInterpolate(obj, context) {
  if (typeof obj === 'string') return interpolate(obj, context);
  if (Array.isArray(obj)) return obj.map(item => deepInterpolate(item, context));
  if (obj && typeof obj === 'object') {
    const result = {};
    for (const [k, v] of Object.entries(obj)) result[k] = deepInterpolate(v, context);
    return result;
  }
  return obj;
}

function readExecutions() {
  try {
    if (fs.existsSync(EXECUTIONS_FILE)) {
      return JSON.parse(fs.readFileSync(EXECUTIONS_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('[SOAR] Error reading executions:', err.message);
  }
  return {};
}

function writeExecutions(data) {
  try {
    const dir = path.dirname(EXECUTIONS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(EXECUTIONS_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error('[SOAR] Error writing executions:', err.message);
  }
}

async function saveExecution(execution) {
  const all = readExecutions();
  all[execution.id] = execution;
  writeExecutions(all);
}

function loadExecution(executionId) {
  const all = readExecutions();
  return all[executionId] || null;
}

async function handleApiRequest(params, context) {
  const { url, method = 'GET', headers = {}, body, timeout = 30000 } = params;
  if (!url) return { success: false, error: 'URL is required for api_request' };
  const parsed = new URL(url);
  const isHttps = parsed.protocol === 'https:';
  const lib = isHttps ? https : http;
  const payload = body ? JSON.stringify(body) : null;
  const options = {
    hostname: parsed.hostname,
    port: parsed.port || (isHttps ? 443 : 80),
    path: parsed.pathname + parsed.search,
    method: method.toUpperCase(),
    headers: { 'Content-Type': 'application/json', ...headers },
    timeout
  };
  if (payload) options.headers['Content-Length'] = Buffer.byteLength(payload);
  return new Promise((resolve) => {
    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let parsedBody;
        try { parsedBody = JSON.parse(data); } catch { parsedBody = data; }
        resolve({
          success: res.statusCode >= 200 && res.statusCode < 300,
          statusCode: res.statusCode,
          headers: res.headers,
          data: parsedBody
        });
      });
    });
    req.on('error', (err) => resolve({ success: false, error: err.message }));
    req.on('timeout', () => { req.destroy(); resolve({ success: false, error: 'Request timed out' }); });
    if (payload) req.write(payload);
    req.end();
  });
}

async function handleCreateIncident(params, context) {
  try {
    const db = require('./db');
    const incidents = db.readTable('incidents');
    const newId = db.nextId(incidents);
    const incident = {
      id: newId,
      title: params.title || 'SOAR Incident',
      description: params.description || '',
      severity: params.severity || 'medium',
      status: 'open',
      source: 'soar',
      playbookId: context.playbookId || '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      ...params
    };
    delete incident.id;
    incidents.push(incident);
    db.writeTable('incidents', incidents);
    return { success: true, incident: { ...incident, id: newId } };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleUpdateIncident(params, context) {
  try {
    const db = require('./db');
    const incidents = db.readTable('incidents');
    const idx = incidents.findIndex(i => i.id === parseInt(params.id) || i.id === params.id);
    if (idx === -1) return { success: false, error: `Incident ${params.id} not found` };
    const updates = { ...params };
    delete updates.id;
    updates.updatedAt = new Date().toISOString();
    Object.assign(incidents[idx], updates);
    db.writeTable('incidents', incidents);
    return { success: true, incident: incidents[idx] };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleSendAlert(params, context) {
  try {
    const alerting = require('./alerting');
    const result = await alerting.notify(params.event || 'soar_alert', params.data || {});
    return { success: true, results: result };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleBlockIp(params, context) {
  try {
    const db = require('./db');
    const intel = db.readTable('threat-intel');
    const entry = {
      id: db.nextId(intel),
      type: 'ip',
      value: params.ip,
      source: 'soar',
      confidence: params.confidence || 'high',
      action: 'block',
      description: params.description || `Blocked by SOAR playbook ${context.playbookId || 'unknown'}`,
      expiresAt: params.expiresAt || null,
      createdAt: new Date().toISOString()
    };
    intel.push(entry);
    db.writeTable('threat-intel', intel);
    return { success: true, ioc: entry };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleUnblockIp(params, context) {
  try {
    const db = require('./db');
    const intel = db.readTable('threat-intel');
    const filtered = intel.filter(i => !(i.type === 'ip' && i.value === params.ip && i.action === 'block'));
    db.writeTable('threat-intel', filtered);
    return { success: true, message: `IP ${params.ip} unblocked` };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleAddIoc(params, context) {
  try {
    const db = require('./db');
    const intel = db.readTable('threat-intel');
    const entry = {
      id: db.nextId(intel),
      type: params.type || 'unknown',
      value: params.value,
      source: params.source || 'soar',
      confidence: params.confidence || 'medium',
      action: params.action || 'monitor',
      description: params.description || '',
      tags: params.tags || [],
      expiresAt: params.expiresAt || null,
      createdAt: new Date().toISOString()
    };
    intel.push(entry);
    db.writeTable('threat-intel', intel);
    return { success: true, ioc: entry };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleQuarantineAsset(params, context) {
  try {
    const db = require('./db');
    const assets = db.readTable('network-assets');
    const idx = assets.findIndex(a => a.ip === params.ip || a.mac === params.mac || a.id === parseInt(params.id) || a.id === params.id);
    if (idx === -1) return { success: false, error: `Asset ${params.ip || params.mac || params.id} not found` };
    assets[idx].status = 'quarantined';
    assets[idx].quarantinedAt = new Date().toISOString();
    assets[idx].quarantineReason = params.reason || 'SOAR playbook action';
    assets[idx].updatedAt = new Date().toISOString();
    db.writeTable('network-assets', assets);
    return { success: true, asset: assets[idx] };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleRunCommand(params, context) {
  try {
    const { command, timeout = 30000, shell = true } = params;
    if (!command) return { success: false, error: 'Command is required' };
    const stdout = execSync(command, { encoding: 'utf8', timeout, shell, maxBuffer: 10 * 1024 * 1024 });
    return { success: true, stdout: stdout.trim(), stderr: '' };
  } catch (err) {
    return {
      success: false,
      error: err.message,
      stdout: err.stdout ? err.stdout.toString().trim() : '',
      stderr: err.stderr ? err.stderr.toString().trim() : ''
    };
  }
}

function sleep(seconds) {
  return new Promise(resolve => setTimeout(resolve, seconds * 1000));
}

async function handleWait(params, context) {
  const seconds = parseFloat(params.seconds) || 1;
  await sleep(seconds);
  return { success: true, waited: seconds };
}

async function handleCondition(params, context) {
  const { field, operator, value, then, otherwise } = params;
  let actual = field.split('.').reduce((o, k) => (o != null ? o[k] : undefined), context);
  let match = false;
  switch (operator) {
    case 'eq': match = actual === value; break;
    case 'neq': match = actual !== value; break;
    case 'gt': match = actual > value; break;
    case 'gte': match = actual >= value; break;
    case 'lt': match = actual < value; break;
    case 'lte': match = actual <= value; break;
    case 'contains': match = String(actual).includes(String(value)); break;
    case 'startsWith': match = String(actual).startsWith(String(value)); break;
    case 'endsWith': match = String(actual).endsWith(String(value)); break;
    case 'regex': match = new RegExp(value).test(String(actual)); break;
    case 'in': match = Array.isArray(value) && value.includes(actual); break;
    case 'notIn': match = Array.isArray(value) && !value.includes(actual); break;
    case 'exists': match = actual != null; break;
    case 'notExists': match = actual == null; break;
    default: match = false;
  }
  return { success: true, condition: true, result: match ? 'then' : 'otherwise', branch: match ? then : otherwise, matched: match };
}

async function handleLoop(params, context) {
  const { items, itemKey = 'item', indexKey = 'index', steps } = params;
  const list = typeof items === 'string' ? (context[items] || []) : items;
  if (!Array.isArray(list)) return { success: false, error: 'Items must be an array' };
  const results = [];
  for (let i = 0; i < list.length; i++) {
    const loopCtx = { ...context, [itemKey]: list[i], [indexKey]: i };
    const stepResults = [];
    for (const step of (steps || [])) {
      const result = await executeStep(step, loopCtx);
      stepResults.push({ step: step.name, result });
      if (!result.success && step.onFailure === 'break') break;
    }
    results.push({ index: i, item: list[i], steps: stepResults });
  }
  return { success: true, iterations: results };
}

async function executeStep(step, context) {
  const startTime = Date.now();
  const timeout = (step.timeout || 30) * 1000;
  const retryCount = step.retryCount || 0;
  const stepContext = { ...context, stepName: step.name, stepOrder: step.order };

  const params = deepInterpolate(step.params || {}, stepContext);

  const handler = actionHandlers[step.action];
  if (!handler) return { success: false, error: `Unknown action: ${step.action}` };

  let lastError = null;
  for (let attempt = 0; attempt <= retryCount; attempt++) {
    if (attempt > 0) {
      const delay = Math.min(1000 * Math.pow(2, attempt - 1), 30000);
      await sleep(delay / 1000);
    }
    try {
      const result = await Promise.race([
        handler(params, stepContext),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Step timed out')), timeout))
      ]);
      if (context.results) context.results[step.name] = result;
      return { ...result, step: step.name, attempt, duration: Date.now() - startTime };
    } catch (err) {
      lastError = { success: false, error: err.message, step: step.name, attempt, duration: Date.now() - startTime };
    }
  }
  return lastError;
}

async function executePlaybook(playbook, context) {
  if (!playbook || !playbook.steps || !Array.isArray(playbook.steps)) {
    return { success: false, error: 'Invalid playbook: no steps defined' };
  }

  const steps = [...playbook.steps].sort((a, b) => a.order - b.order);
  const stepMap = {};
  for (const step of steps) stepMap[step.name] = step;

  const ctx = {
    playbookId: playbook.id,
    playbookName: playbook.name,
    trigger: playbook.trigger || {},
    results: {},
    ...context
  };

  let i = 0;
  while (i < steps.length) {
    const step = steps[i];
    const result = await executeStep(step, ctx);
    ctx.results[step.name] = result;
    ctx.lastResult = result;

    if (!result.success && step.onFailure) {
      const nextName = step.onFailure;
      const nextStep = stepMap[nextName];
      if (nextStep) {
        i = steps.findIndex(s => s.name === nextName);
        continue;
      }
    }
    if (result.success && step.onSuccess) {
      const nextName = step.onSuccess;
      const nextStep = stepMap[nextName];
      if (nextStep) {
        i = steps.findIndex(s => s.name === nextName);
        continue;
      }
    }
    i++;
  }

  return { success: true, results: ctx.results, context: ctx };
}

function registerAction(name, handler) {
  if (typeof handler !== 'function') throw new ValidationError('Handler must be a function');
  actionHandlers[name] = handler;
}

function registerBuiltinActions() {
  registerAction('api_request', handleApiRequest);
  registerAction('create_incident', handleCreateIncident);
  registerAction('update_incident', handleUpdateIncident);
  registerAction('send_alert', handleSendAlert);
  registerAction('block_ip', handleBlockIp);
  registerAction('unblock_ip', handleUnblockIp);
  registerAction('add_ioc', handleAddIoc);
  registerAction('quarantine_asset', handleQuarantineAsset);
  registerAction('run_command', handleRunCommand);
  registerAction('wait', handleWait);
  registerAction('condition', handleCondition);
  registerAction('loop', handleLoop);
}

registerBuiltinActions();

const BUILTIN_PLAYBOOKS = {
  quarantineHost: {
    id: 'builtin-quarantine-host',
    name: 'Quarantine Host',
    description: 'Isolate a host based on incident severity',
    trigger: { eventType: 'incident.created', conditions: [{ field: 'severity', operator: 'in', value: ['high', 'critical'] }] },
    steps: [
      { order: 1, name: 'validate_incident', action: 'condition', params: { field: 'incident.severity', operator: 'in', value: ['high', 'critical'], then: 'quarantine_asset_step', otherwise: 'skip' }, onFailure: 'skip', retryCount: 0, timeout: 10 },
      { order: 2, name: 'quarantine_asset_step', action: 'quarantine_asset', params: { ip: '{{ incident.source_ip }}', reason: 'Automated quarantine for {{ incident.severity }} severity incident: {{ incident.title }}' }, onSuccess: 'update_incident_status', onFailure: 'notify_failure', retryCount: 1, timeout: 30 },
      { order: 3, name: 'update_incident_status', action: 'update_incident', params: { id: '{{ incident.id }}', status: 'quarantined', description: 'Host quarantined via SOAR playbook' }, retryCount: 0, timeout: 15 },
      { order: 4, name: 'notify_failure', action: 'send_alert', params: { event: 'soar.playbook.failure', data: { playbook: 'Quarantine Host', incident: '{{ incident.id }}', error: '{{ lastResult.error }}' } }, retryCount: 0, timeout: 15 },
      { order: 5, name: 'skip', action: 'wait', params: { seconds: 0 }, retryCount: 0, timeout: 5 }
    ],
    enabled: true
  },
  c2Containment: {
    id: 'builtin-c2-containment',
    name: 'C2 Containment',
    description: 'Automated C2 incident response - block IPs and update threat intel',
    trigger: { eventType: 'alert.c2_detected', conditions: [{ field: 'confidence', operator: 'gte', value: 70 }] },
    steps: [
      { order: 1, name: 'block_c2_ip', action: 'block_ip', params: { ip: '{{ alert.source_ip }}', confidence: 'high', description: 'C2 communication detected - automated block' }, onSuccess: 'add_c2_ioc', onFailure: 'notify_failure', retryCount: 1, timeout: 20 },
      { order: 2, name: 'add_c2_ioc', action: 'add_ioc', params: { type: 'ip', value: '{{ alert.source_ip }}', source: 'soar-c2', confidence: 'high', action: 'block', tags: ['c2', 'automated'], description: 'C2 indicator from SOAR playbook' }, onSuccess: 'update_incident', onFailure: 'update_incident', retryCount: 0, timeout: 15 },
      { order: 3, name: 'update_incident', action: 'update_incident', params: { id: '{{ incident.id }}', status: 'in_progress', description: 'C2 containment initiated - IP blocked and IOC added' }, retryCount: 0, timeout: 15 },
      { order: 4, name: 'notify_failure', action: 'send_alert', params: { event: 'soar.playbook.failure', data: { playbook: 'C2 Containment', alert: '{{ alert.id }}', error: '{{ lastResult.error }}' } }, retryCount: 0, timeout: 15 }
    ],
    enabled: true
  },
  bruteForceResponse: {
    id: 'builtin-brute-force-response',
    name: 'Brute Force Response',
    description: 'Block IP and notify on brute force detection',
    trigger: { eventType: 'alert.brute_force', conditions: [{ field: 'attempts', operator: 'gte', value: 5 }] },
    steps: [
      { order: 1, name: 'block_attacker_ip', action: 'block_ip', params: { ip: '{{ alert.source_ip }}', confidence: 'high', description: 'Brute force attempt blocked - {{ alert.attempts }} failed logins' }, onSuccess: 'add_ioc', onFailure: 'notify_soc', retryCount: 1, timeout: 20 },
      { order: 2, name: 'add_ioc', action: 'add_ioc', params: { type: 'ip', value: '{{ alert.source_ip }}', source: 'soar-bf', confidence: 'high', action: 'block', tags: ['brute-force', 'automated'] }, onSuccess: 'notify_soc', onFailure: 'notify_soc', retryCount: 0, timeout: 15 },
      { order: 3, name: 'notify_soc', action: 'send_alert', params: { event: 'soar.brute_force.blocked', data: { ip: '{{ alert.source_ip }}', username: '{{ alert.username }}', attempts: '{{ alert.attempts }}', playbook: 'Brute Force Response' } }, retryCount: 0, timeout: 15 }
    ],
    enabled: true
  },
  malwareResponse: {
    id: 'builtin-malware-response',
    name: 'Malware Response',
    description: 'Quarantine affected host and scan for malware indicators',
    trigger: { eventType: 'alert.malware_detected', conditions: [{ field: 'malware.severity', operator: 'gte', value: 'medium' }] },
    steps: [
      { order: 1, name: 'quarantine_host', action: 'quarantine_asset', params: { ip: '{{ alert.host_ip }}', reason: 'Malware detected: {{ alert.malware.name }} ({{ alert.malware.severity }})' }, onSuccess: 'collect_iocs', onFailure: 'escalate', retryCount: 1, timeout: 30 },
      { order: 2, name: 'collect_iocs', action: 'add_ioc', params: { type: '{{ alert.malware.ioc_type }}', value: '{{ alert.malware.ioc_value }}', source: 'soar-malware', confidence: 'high', action: 'block', tags: ['malware', '{{ alert.malware.name }}'] }, onSuccess: 'update_incident', onFailure: 'update_incident', retryCount: 0, timeout: 15 },
      { order: 3, name: 'update_incident', action: 'update_incident', params: { id: '{{ incident.id }}', status: 'contained', description: 'Host quarantined, IOCs added for {{ alert.malware.name }}' }, retryCount: 0, timeout: 15 },
      { order: 4, name: 'escalate', action: 'send_alert', params: { event: 'soar.playbook.escalated', data: { playbook: 'Malware Response', host: '{{ alert.host_ip }}', incident: '{{ incident.id }}', error: '{{ lastResult.error }}', severity: 'high' } }, retryCount: 0, timeout: 15 }
    ],
    enabled: true
  },
  phishingResponse: {
    id: 'builtin-phishing-response',
    name: 'Phishing Response',
    description: 'Collect email artifacts and block sender on phishing detection',
    trigger: { eventType: 'alert.phishing', conditions: [{ field: 'phishing.confidence', operator: 'gte', value: 60 }] },
    steps: [
      { order: 1, name: 'block_sender', action: 'add_ioc', params: { type: 'email', value: '{{ alert.phishing.sender }}', source: 'soar-phishing', confidence: '{{ alert.phishing.confidence }}', action: 'block', tags: ['phishing', 'sender'], description: 'Phishing sender: {{ alert.phishing.subject }}' }, onSuccess: 'extract_indicators', onFailure: 'notify_soc', retryCount: 1, timeout: 20 },
      { order: 2, name: 'extract_indicators', action: 'loop', params: { items: '{{ alert.phishing.urls }}', itemKey: 'url', steps: [{ name: 'block_url', action: 'add_ioc', params: { type: 'url', value: '{{ url }}', source: 'soar-phishing', confidence: 'medium', action: 'block', tags: ['phishing', 'url'] }, retryCount: 0, timeout: 10 }] }, onSuccess: 'update_incident', onFailure: 'notify_soc', retryCount: 0, timeout: 60 },
      { order: 3, name: 'update_incident', action: 'update_incident', params: { id: '{{ incident.id }}', status: 'in_progress', description: 'Phishing response initiated - sender blocked, URLs extracted' }, retryCount: 0, timeout: 15 },
      { order: 4, name: 'notify_soc', action: 'send_alert', params: { event: 'soar.phishing.response', data: { sender: '{{ alert.phishing.sender }}', subject: '{{ alert.phishing.subject }}', recipients: '{{ alert.phishing.recipients }}', playbook: 'Phishing Response', status: '{{ lastResult.success ? "success" : "partial" }}' } }, retryCount: 0, timeout: 15 }
    ],
    enabled: true
  }
};

function getBuiltinPlaybooks() {
  return BUILTIN_PLAYBOOKS;
}

function getBuiltinPlaybook(name) {
  return BUILTIN_PLAYBOOKS[name] || null;
}

async function startPlaybook(playbookId, context) {
  const executionId = uuid();
  const execution = {
    id: executionId,
    playbookId,
    status: 'running',
    startedAt: new Date().toISOString(),
    completedAt: null,
    context: context || {},
    results: null,
    error: null
  };
  executions[executionId] = execution;
  await saveExecution(execution);

  const playbook = BUILTIN_PLAYBOOKS[playbookId] || null;

  if (!playbook) {
    execution.status = 'failed';
    execution.error = `Playbook "${playbookId}" not found`;
    execution.completedAt = new Date().toISOString();
    executions[executionId] = execution;
    await saveExecution(execution);
    return executionId;
  }

  abortControllers[executionId] = new AbortController();

  executePlaybookAsync(executionId, playbook, context).catch(() => {});

  return executionId;
}

async function executePlaybookAsync(executionId, playbook, context) {
  const execRecord = executions[executionId];
  try {
    const result = await executePlaybook(playbook, { ...context, _executionId: executionId });
    if (abortControllers[executionId] && abortControllers[executionId].signal.aborted) {
      execRecord.status = 'stopped';
      execRecord.error = 'Playbook execution stopped by user';
    } else {
      execRecord.status = result.success ? 'completed' : 'failed';
      execRecord.results = result.results || result;
      if (!result.success) execRecord.error = result.error || 'Playbook execution failed';
    }
  } catch (err) {
    execRecord.status = 'failed';
    execRecord.error = err.message;
    execRecord.results = null;
  }
  execRecord.completedAt = new Date().toISOString();
  executions[executionId] = execRecord;
  await saveExecution(execRecord);
  delete abortControllers[executionId];
}

function stopPlaybook(executionId) {
  if (abortControllers[executionId]) {
    abortControllers[executionId].abort();
    return true;
  }
  const exec = executions[executionId] || loadExecution(executionId);
  if (exec && exec.status === 'running') {
    exec.status = 'stopped';
    exec.completedAt = new Date().toISOString();
    exec.error = 'Playbook execution stopped by user';
    executions[executionId] = exec;
    saveExecution(exec);
    return true;
  }
  return false;
}

function getPlaybookStatus(executionId) {
  const exec = executions[executionId] || loadExecution(executionId);
  if (!exec) return null;
  return {
    id: exec.id,
    playbookId: exec.playbookId,
    status: exec.status,
    startedAt: exec.startedAt,
    completedAt: exec.completedAt,
    error: exec.error
  };
}

function listExecutions(filters = {}) {
  const all = readExecutions();
  let list = Object.values(all);
  for (const exec of Object.values(executions)) {
    const idx = list.findIndex(e => e.id === exec.id);
    if (idx >= 0) list[idx] = exec;
    else list.push(exec);
  }
  if (filters.status) list = list.filter(e => e.status === filters.status);
  if (filters.playbookId) list = list.filter(e => e.playbookId === filters.playbookId);
  if (filters.limit) list = list.slice(0, filters.limit);
  list.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
  return list;
}

function clearExecutions() {
  const all = readExecutions();
  const running = {};
  for (const [id, exec] of Object.entries(executions)) {
    if (exec.status === 'running') running[id] = exec;
  }
  writeExecutions(running);
  for (const id of Object.keys(executions)) {
    if (executions[id].status !== 'running') delete executions[id];
  }
}

module.exports = {
  executePlaybook,
  executeStep,
  startPlaybook,
  stopPlaybook,
  getPlaybookStatus,
  listExecutions,
  clearExecutions,
  registerAction,
  getBuiltinPlaybooks,
  getBuiltinPlaybook,
  saveExecution,
  loadExecution
};
