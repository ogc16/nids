'use strict';

const dgram = require('dgram');
const net = require('net');
const { execSync } = require('child_process');

const FACILITIES = {
  0: 'kern', 1: 'user', 2: 'mail', 3: 'daemon', 4: 'auth',
  5: 'syslog', 6: 'lpr', 7: 'news', 8: 'uucp', 9: 'cron',
  10: 'authpriv', 11: 'ftp', 16: 'local0', 17: 'local1',
  18: 'local2', 19: 'local3', 20: 'local4', 21: 'local5',
  22: 'local6', 23: 'local7'
};

const SEVERITIES = {
  0: 'emergency', 1: 'alert', 2: 'critical', 3: 'error',
  4: 'warning', 5: 'notice', 6: 'informational', 7: 'debug'
};

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

const MAX_BUFFER = 10000;
const collectedLogs = [];
const parsedMessages = [];

let udpServer = null;
let tcpServer = null;

function parsePriority(raw) {
  const match = raw.match(/^<(\d+)>/);
  if (!match) return null;
  const pri = parseInt(match[1], 10);
  return { pri, facility: pri >> 3, severity: pri & 7, rest: raw.slice(match[0].length) };
}

function parseRfc3164Timestamp(str) {
  const d = new Date();
  const parts = str.split(' ');
  if (parts.length < 3) return new Date();
  const month = MONTHS.indexOf(parts[0]);
  if (month === -1) return new Date();
  const day = parseInt(parts[1], 10);
  const timeParts = parts[2].split(':');
  if (timeParts.length !== 3) return new Date();
  d.setMonth(month);
  d.setDate(day);
  d.setHours(parseInt(timeParts[0], 10));
  d.setMinutes(parseInt(timeParts[1], 10));
  d.setSeconds(parseInt(timeParts[2], 10));
  d.setFullYear(new Date().getFullYear());
  return d;
}

function parseRfc5424Timestamp(str) {
  const parsed = new Date(str);
  return isNaN(parsed.getTime()) ? new Date() : parsed;
}

function parseRfc3164(parsed, raw) {
  const rest = parsed.rest.trim();
  const tsMatch = rest.match(/^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+/);
  if (!tsMatch) return null;
  const ts = tsMatch[1];
  let after = rest.slice(tsMatch[0].length).trim();

  const hostname = after.includes(' ') ? after.slice(0, after.indexOf(' ')) : after;
  after = after.includes(' ') ? after.slice(after.indexOf(' ') + 1).trim() : '';

  let appName = null;
  let msgId = null;
  let message = after;

  const tagMatch = after.match(/^([\w.-]+?)(?:\[(\d+)\])?:\s*(.*)/);
  if (tagMatch) {
    appName = tagMatch[1];
    msgId = tagMatch[2] || null;
    message = tagMatch[3] || '';
  }

  return {
    timestamp: parseRfc3164Timestamp(ts),
    facility: parsed.facility,
    facilityName: FACILITIES[parsed.facility] || 'unknown',
    severity: parsed.severity,
    severityName: SEVERITIES[parsed.severity] || 'unknown',
    hostname,
    appName,
    msgId,
    message,
    raw
  };
}

function parseRfc5424(parsed, raw) {
  const rest = parsed.rest.trim();
  const re = /^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)/;
  const m = rest.match(re);
  if (!m) return null;

  const sdRaw = m[7];
  let structuredData = null;
  let message = '';

  if (sdRaw.startsWith('[')) {
    const sdEnd = sdRaw.indexOf(']');
    if (sdEnd !== -1) {
      const sdContent = sdRaw.slice(1, sdEnd).trim();
      structuredData = {};
      if (sdContent) {
        sdContent.split(' ').forEach(part => {
          const eq = part.indexOf('=');
          if (eq !== -1) structuredData[part.slice(0, eq)] = part.slice(eq + 1).replace(/"/g, '');
        });
      }
      message = sdRaw.slice(sdEnd + 1).trim();
    }
  } else {
    const bom = sdRaw.charCodeAt(0) === 0xFEFF ? sdRaw.slice(1) : sdRaw;
    const msgIdx = bom.indexOf(' ');
    message = msgIdx !== -1 ? bom.slice(msgIdx + 1) : bom;
  }

  const msgIdVal = m[6] === '-' ? null : m[6];

  return {
    timestamp: parseRfc5424Timestamp(m[2]),
    facility: parsed.facility,
    facilityName: FACILITIES[parsed.facility] || 'unknown',
    severity: parsed.severity,
    severityName: SEVERITIES[parsed.severity] || 'unknown',
    hostname: m[3] === '-' ? null : m[3],
    appName: m[4] === '-' ? null : m[4],
    msgId: msgIdVal,
    structuredData,
    message: message || '',
    raw
  };
}

function parseSyslogMessage(raw) {
  const parsed = parsePriority(raw);
  if (!parsed) return null;

  const rfc5424 = parseRfc5424(parsed, raw);
  if (rfc5424) return rfc5424;

  const rfc3164 = parseRfc3164(parsed, raw);
  if (rfc3164) return rfc3164;

  return {
    facility: parsed.facility,
    facilityName: FACILITIES[parsed.facility] || 'unknown',
    severity: parsed.severity,
    severityName: SEVERITIES[parsed.severity] || 'unknown',
    hostname: null,
    appName: null,
    msgId: null,
    message: parsed.rest.trim(),
    timestamp: new Date(),
    raw
  };
}

function addToBuffer(entry) {
  const normalized = normalizeLogEntry(entry);
  collectedLogs.push(normalized);
  if (collectedLogs.length > MAX_BUFFER) {
    collectedLogs.shift();
  }
  return normalized;
}

function normalizeLogEntry(entry) {
  const normalized = {
    timestamp: entry.timestamp || new Date(),
    source: entry.source || 'unknown',
    type: entry.type || 'log',
    severity: entry.severityName || entry.severity || 'info',
    message: entry.message || '',
    raw: entry.raw || entry.message || '',
    tags: entry.tags || []
  };
  normalized.normalized = true;
  return normalized;
}

function startSyslogServer(options) {
  const opts = Object.assign({ udp: true, tcp: false, udpPort: 514, tcpPort: 601, callback: null }, options);

  const results = { udp: null, tcp: null };

  if (opts.udp) {
    try {
      udpServer = dgram.createSocket('udp4');
      udpServer.on('message', (msg, rinfo) => {
        const raw = msg.toString('utf8').trim();
        const parsed = parseSyslogMessage(raw);
        if (parsed) {
          parsed.source = rinfo.address;
          parsed.type = 'syslog';
          const entry = addToBuffer(parsed);
          parsedMessages.push(parsed);
          if (parsedMessages.length > MAX_BUFFER) parsedMessages.shift();
          if (typeof opts.callback === 'function') opts.callback(entry);
        }
      });
      udpServer.on('error', err => {
        if (err.code === 'EACCES') {
          results.udp = { error: `Permission denied on UDP port ${opts.udpPort}`, code: 'EACCES' };
        } else {
          results.udp = { error: err.message, code: err.code };
        }
      });
      udpServer.bind(opts.udpPort, () => {
        results.udp = { port: opts.udpPort, bound: true };
      });
    } catch (err) {
      results.udp = { error: err.message, code: err.code || 'UNKNOWN' };
    }
  }

  if (opts.tcp) {
    try {
      tcpServer = net.createServer(socket => {
        let buffer = '';
        socket.on('data', data => {
          buffer += data.toString('utf8');
          const lines = buffer.split('\n');
          buffer = lines.pop();
          lines.forEach(line => {
            const raw = line.trim();
            if (!raw) return;
            const parsed = parseSyslogMessage(raw);
            if (parsed) {
              parsed.source = socket.remoteAddress;
              parsed.type = 'syslog';
              const entry = addToBuffer(parsed);
              parsedMessages.push(parsed);
              if (parsedMessages.length > MAX_BUFFER) parsedMessages.shift();
              if (typeof opts.callback === 'function') opts.callback(entry);
            }
          });
        });
        socket.on('error', () => {});
      });
      tcpServer.on('error', err => {
        if (err.code === 'EACCES') {
          results.tcp = { error: `Permission denied on TCP port ${opts.tcpPort}`, code: 'EACCES' };
        } else {
          results.tcp = { error: err.message, code: err.code };
        }
      });
      tcpServer.listen(opts.tcpPort, () => {
        results.tcp = { port: opts.tcpPort, bound: true };
      });
    } catch (err) {
      results.tcp = { error: err.message, code: err.code || 'UNKNOWN' };
    }
  }

  return results;
}

function stopSyslogServer() {
  const results = { udp: false, tcp: false };
  if (udpServer) {
    try {
      udpServer.close();
      results.udp = true;
    } catch (err) {
      results.udp = false;
    }
    udpServer = null;
  }
  if (tcpServer) {
    try {
      tcpServer.close();
      results.tcp = true;
    } catch (err) {
      results.tcp = false;
    }
    tcpServer = null;
  }
  return results;
}

const ALLOWED_LOG_NAMES = new Set([
  'Security', 'System', 'Application', 'Setup', 'ForwardedEvents',
  'Windows PowerShell', 'Microsoft-Windows-Sysmon/Operational',
  'Microsoft-Windows-Windows Defender/Operational',
  'Microsoft-Windows-TaskScheduler/Operational',
  'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
  'Microsoft-Windows-DNS-Client/Operational',
  'Microsoft-Windows-CodeIntegrity/Operational',
  'Microsoft-Windows-AppLocker/EXE and DLL',
  'Microsoft-Windows-PowerShell/Operational',
  'Microsoft-Windows-SmbClientSecurity/Operational',
  'Windows Networking (V2)',
  'Microsoft-Windows-Hyper-V/Admin'
]);

function validateLogName(logName) {
  if (ALLOWED_LOG_NAMES.has(logName)) return logName;
  if (/^[a-zA-Z0-9\-/\\ ]+$/.test(logName) && logName.length <= 100) return logName;
  throw new Error(`Invalid log name: ${logName}`);
}

function getWindowsEvents(options) {
  const opts = Object.assign({
    logName: 'Security',
    maxEvents: 100,
    filterHash: null,
    startTime: null,
    endTime: null,
    eventIds: []
  }, options);

  let logName;
  try { logName = validateLogName(opts.logName); } catch { return []; }
  const maxEvents = Math.min(500, Math.max(1, opts.maxEvents));

  const conditions = [];
  if (opts.startTime) conditions.push(`StartTime -ge [DateTime]'${opts.startTime}'`);
  if (opts.endTime) conditions.push(`EndTime -le [DateTime]'${opts.endTime}'`);
  if (opts.eventIds.length > 0) {
    const ids = opts.eventIds.map(Number).filter(n => !isNaN(n)).join(',');
    if (ids) conditions.push(`Id -in (${ids})`);
  }

  let filter;
  if (opts.filterHash && typeof opts.filterHash === 'object') {
    filter = `Get-WinEvent -FilterHashtable @{LogName='${logName}';MaxEvents=${maxEvents}`;
    if (opts.startTime) filter += `;StartTime=[DateTime]'${opts.startTime}'`;
    if (opts.endTime) filter += `;EndTime=[DateTime]'${opts.endTime}'`;
    if (opts.eventIds.length > 0) filter += `;Id=${opts.eventIds.map(Number).filter(n => !isNaN(n)).join(',')}`;
    filter += '}';
  } else {
    filter = `Get-WinEvent -LogName '${logName}' -MaxEvents ${maxEvents}`;
    if (conditions.length > 0) {
      filter += ' | Where-Object { ' + conditions.join(' -and ') + ' }';
    }
  }

  const psCmd = `${filter} | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message, Properties | ConvertTo-Json -Compress`;

  try {
    const { spawnSync } = require('child_process');
    const child = spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', psCmd], { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024, timeout: 30000, windowsHide: true });
    if (child.error) return [];
    const output = child.stdout.trim();
    if (!output) return [];
    const parsed = JSON.parse(output);
    const events = Array.isArray(parsed) ? parsed : [parsed];
    return events.map(e => ({
      TimeCreated: e.TimeCreated,
      Id: e.Id,
      LevelDisplayName: e.LevelDisplayName,
      ProviderName: e.ProviderName,
      Message: e.Message,
      Properties: e.Properties || []
    }));
  } catch (err) {
    return { error: 'Failed to retrieve Windows events' };
  }
}

function getEventLogs() {
  const cmd = 'Get-WinEvent -ListLog * | Select-Object LogName, LogType, IsEnabled, LogFilePath | ConvertTo-Json -Compress';
  try {
    const { spawnSync } = require('child_process');
    const child = spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', cmd], { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024, timeout: 15000, windowsHide: true });
    if (child.error) return [];
    const output = child.stdout.trim();
    if (!output) return [];
    const parsed = JSON.parse(output);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return [];
  }
}

function getEventLogStatus(logName) {
  let safeName;
  try { safeName = validateLogName(logName); } catch { return { error: 'Invalid log name' }; }
  const cmd = `Get-WinEvent -LogName '${safeName}' | Measure-Object | Select-Object Count; (Get-Item (Get-WinEvent -ListLog '${safeName}').LogFilePath).Length`;
  try {
    const { spawnSync } = require('child_process');
    const child = spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', cmd], { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024, timeout: 15000, windowsHide: true });
    if (child.error) return { error: 'Failed to get event log status' };
    const output = child.stdout.trim();
    const parts = output.split('\n').filter(Boolean);
    const count = parseInt(parts[0], 10) || 0;
    const fileSize = parseInt(parts[1], 10) || 0;
    return {
      logName,
      recordCount: count,
      fileSize,
      lastWrite: new Date()
    };
  } catch {
    return { error: 'Failed to get event log status' };
  }
}

function getCollectedLogs(limit, offset) {
  const lim = typeof limit === 'number' ? limit : 50;
  const off = typeof offset === 'number' ? offset : 0;
  return collectedLogs.slice(off, off + lim);
}

function clearLogs() {
  collectedLogs.length = 0;
}

function getLogStats() {
  const total = collectedLogs.length;
  const bySeverity = {};
  const bySource = {};
  const byType = {};

  collectedLogs.forEach(entry => {
    const sev = entry.severity || 'unknown';
    bySeverity[sev] = (bySeverity[sev] || 0) + 1;
    const src = entry.source || 'unknown';
    bySource[src] = (bySource[src] || 0) + 1;
    const typ = entry.type || 'unknown';
    byType[typ] = (byType[typ] || 0) + 1;
  });

  return { total, bySeverity, bySource, byType };
}

function forwardToEndpoint(url, filter) {
  if (!url) return Promise.reject(new Error('URL is required'));
  const logs = typeof filter === 'function' ? collectedLogs.filter(filter) : collectedLogs;
  return new Promise((resolve, reject) => {
    const http = url.startsWith('https') ? require('https') : require('http');
    const body = JSON.stringify(logs);
    const parsedUrl = new URL(url);
    const opts = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    };
    const req = http.request(opts, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, data }));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

module.exports = {
  startSyslogServer,
  stopSyslogServer,
  parseSyslogMessage,
  getWindowsEvents,
  getEventLogs,
  getEventLogStatus,
  normalizeLogEntry,
  getCollectedLogs,
  clearLogs,
  getLogStats,
  forwardToEndpoint,
  parsedMessages,
  collectedLogs
};
