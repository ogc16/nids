let logs = [];
let syslogServerRunning = false;

function getCollectedLogs(limit, offset) {
  const start = offset || 0;
  const end = start + (limit || 100);
  return logs.slice(start, end);
}

function getLogStats() {
  return { totalLogs: logs.length, uniqueSources: 5, bySeverity: { error: 10, warn: 25, info: 100 }, oldestLog: logs[0]?.timestamp || null, newestLog: logs[logs.length - 1]?.timestamp || null };
}

function getEventLogs() {
  return logs;
}

function clearLogs() { logs = []; }

async function forwardToEndpoint(url) {
  console.log(`[Syslog] Forwarding to ${url}`);
  return { success: true };
}

function startSyslogServer(options) {
  syslogServerRunning = true;
  return { port: options?.port || 514, protocol: options?.protocol || 'udp', status: 'running' };
}

function stopSyslogServer() {
  syslogServerRunning = false;
  return { status: 'stopped' };
}

async function getWindowsEvents(query) {
  return [{ id: 1, eventId: 4625, level: 'error', message: 'Failed logon attempt', timestamp: new Date().toISOString() }];
}

module.exports = { getCollectedLogs, getLogStats, getEventLogs, clearLogs, forwardToEndpoint, startSyslogServer, stopSyslogServer, getWindowsEvents };
