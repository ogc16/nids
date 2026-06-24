const http = require('http');
const url = require('url');
const os = require('os');
const { v4: uuidv4 } = require('uuid');
const { AppError } = require('./errors');

let ssh2;
try { ssh2 = require('ssh2'); } catch { ssh2 = null; }

const agents = new Map();
let agentServer = null;
let agentServerToken = null;

const knownHosts = new Map();

function connectViaSSH(config) {
  return new Promise((resolve, reject) => {
    if (!ssh2) return reject(new AppError(500, 'ssh2 module not available'));
    const conn = new ssh2.Client();
    const timeout = (config.timeout || 10) * 1000;
    const timer = setTimeout(() => {
      conn.end();
      reject(new AppError(408, 'SSH connection timeout'));
    }, timeout);
    conn.on('ready', () => {
      clearTimeout(timer);
      resolve(conn);
    });
    conn.on('error', (err) => {
      clearTimeout(timer);
      reject(new AppError(500, 'SSH connection failed'));
    });
    conn.on('fingerprint', (hostKey, fingerprint) => {
      const key = `${config.host}:${config.port || 22}`;
      if (config.hostKeyFingerprint) {
        if (fingerprint !== config.hostKeyFingerprint) {
          conn.end();
          return reject(new AppError(500, `Host key mismatch for ${key}. Expected ${config.hostKeyFingerprint}, got ${fingerprint}`));
        }
      } else if (knownHosts.has(key)) {
        if (knownHosts.get(key) !== fingerprint) {
          conn.end();
          return reject(new AppError(500, `Host key changed for ${key}. Possible MITM attack.`));
        }
      } else {
        knownHosts.set(key, fingerprint);
      }
    });
    conn.connect({
      host: config.host,
      port: config.port || 22,
      username: config.username,
      privateKey: config.privateKey,
      password: config.password,
      hostHash: 'sha256',
      hostVerifier: (key) => true,
      readyTimeout: timeout
    });
  });
}

function executeSSHCommand(conn, command) {
  return new Promise((resolve, reject) => {
    conn.exec(command, (err, stream) => {
      if (err) return reject(new AppError(500, `SSH exec error: ${err.message}`));
      let stdout = '';
      let stderr = '';
      stream.on('data', (data) => { stdout += data.toString(); });
      stream.stderr.on('data', (data) => { stderr += data.toString(); });
      stream.on('close', (code) => {
        if (code !== 0 && stderr.trim()) {
          return reject(new AppError(500, `SSH command failed (${code}): ${stderr.trim()}`));
        }
        resolve(stdout.trim());
      });
    });
  });
}

function disconnectSSH(conn) {
  try { conn.end(); } catch {}
}

async function getRemoteConnections(conn) {
  let raw;
  try {
    raw = await executeSSHCommand(conn, 'ss -tuln 2>/dev/null');
  } catch {
    raw = await executeSSHCommand(conn, 'netstat -tuln 2>/dev/null');
  }
  return parseConnections(raw);
}

async function getRemoteProcesses(conn) {
  const raw = await executeSSHCommand(conn, 'ps aux 2>/dev/null');
  return parseProcesses(raw);
}

async function getRemoteDisk(conn) {
  const raw = await executeSSHCommand(conn, 'df -h 2>/dev/null');
  return parseDiskUsage(raw);
}

async function getRemoteMemory(conn) {
  let raw;
  try {
    raw = await executeSSHCommand(conn, 'free -m 2>/dev/null');
  } catch {
    raw = await executeSSHCommand(conn, 'vm_stat 2>/dev/null');
  }
  return parseMemoryInfo(raw);
}

async function getRemoteCPU(conn) {
  let raw;
  try {
    raw = await executeSSHCommand(conn, 'top -bn1 2>/dev/null');
  } catch {
    raw = await executeSSHCommand(conn, 'ps -A -o %cpu 2>/dev/null');
  }
  return parseCPUInfo(raw);
}

async function getRemoteUptime(conn) {
  const raw = await executeSSHCommand(conn, 'uptime 2>/dev/null');
  const m = raw.match(/up\s+(.+?)(?:,\s+\d+ users)?,\s+load average[s]?:\s+(.+)/i);
  if (m) {
    const parts = m[1].trim();
    let days = 0, hours = 0, mins = 0;
    const d = parts.match(/(\d+)\s+day/);
    if (d) days = parseInt(d[1]);
    const h = parts.match(/(\d+):/);
    if (h) hours = parseInt(h[1]);
    const mi = parts.match(/:(\d+)/);
    if (mi) mins = parseInt(mi[1]);
    const totalMinutes = days * 1440 + hours * 60 + mins;
    return { uptime: parts, days, hours, minutes: mins, totalMinutes, loadAverage: m[2].trim() };
  }
  return { raw };
}

async function getRemoteInterfaces(conn) {
  let raw;
  try {
    raw = await executeSSHCommand(conn, 'ip addr 2>/dev/null');
  } catch {
    raw = await executeSSHCommand(conn, 'ifconfig 2>/dev/null');
  }
  const interfaces = [];
  const blocks = raw.split(/\n(?=[^\s])/);
  for (const block of blocks) {
    const nameMatch = block.match(/^(\d+:\s+)?(\w+[\w.:-]*)/);
    if (!nameMatch) continue;
    const name = nameMatch[2];
    const macMatch = block.match(/link\/\w+\s+([0-9a-f:]{17})/i);
    const ipMatch = block.match(/inet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)/);
    const ip6Match = block.match(/inet6\s+([0-9a-f:]+)\/(\d+)/);
    const state = block.includes('state UP') ? 'UP' : block.includes('state DOWN') ? 'DOWN' : 'UNKNOWN';
    interfaces.push({
      name,
      mac: macMatch ? macMatch[1] : null,
      ipv4: ipMatch ? ipMatch[1] : null,
      ipv4Mask: ipMatch ? parseInt(ipMatch[2]) : null,
      ipv6: ip6Match ? ip6Match[1] : null,
      ipv6Mask: ip6Match ? parseInt(ip6Match[2]) : null,
      state
    });
  }
  return interfaces;
}

async function getRemoteRoutingTable(conn) {
  const raw = await executeSSHCommand(conn, 'ip route 2>/dev/null');
  const routes = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    routes.push({
      destination: parts[0],
      via: parts[1] === 'via' ? parts[2] : null,
      dev: parts.indexOf('dev') !== -1 ? parts[parts.indexOf('dev') + 1] : null,
      proto: parts.indexOf('proto') !== -1 ? parts[parts.indexOf('proto') + 1] : null,
      scope: parts.indexOf('scope') !== -1 ? parts[parts.indexOf('scope') + 1] : null,
      src: parts.indexOf('src') !== -1 ? parts[parts.indexOf('src') + 1] : null,
      raw: trimmed
    });
  }
  return routes;
}

async function getRemoteDnsCache(conn) {
  let raw;
  try {
    raw = await executeSSHCommand(conn, 'systemd-resolve --cache 2>/dev/null || resolvectl cache 2>/dev/null');
  } catch {
    try {
      raw = await executeSSHCommand(conn, 'nscd -g 2>/dev/null');
    } catch {
      raw = await executeSSHCommand(conn, 'cat /proc/net/arp 2>/dev/null; echo "---"; host google.com 2>/dev/null || true');
    }
  }
  return { raw };
}

async function getRemoteARP(conn) {
  let raw;
  try {
    raw = await executeSSHCommand(conn, 'arp -a 2>/dev/null');
  } catch {
    raw = await executeSSHCommand(conn, 'ip neigh 2>/dev/null');
  }
  const entries = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.includes('Address') && trimmed.includes('HWtype')) continue;
    if (trimmed.startsWith('?')) continue;
    const arpMatch = trimmed.match(/^\(?([0-9.]+)\)?\s+(?:at\s+)?([0-9a-f:]{17}|<incomplete>)\s+(?:\[ether\]\s+)?(?:on\s+)?(\w+)?\s+(permanent|stale|reachable|delay|failed|incomplete)?/i);
    if (arpMatch) {
      entries.push({
        address: arpMatch[1],
        linkLayer: arpMatch[2] === '<incomplete>' ? null : arpMatch[2],
        interface: arpMatch[3] || null,
        state: arpMatch[4] || null
      });
    }
    const ipNeighMatch = trimmed.match(/^([0-9.]+)\s+dev\s+(\w+)\s+(\w+)\s+(\w+|([0-9a-f:]{17}))/);
    if (ipNeighMatch) {
      entries.push({
        address: ipNeighMatch[1],
        interface: ipNeighMatch[2],
        state: ipNeighMatch[3],
        linkLayer: ipNeighMatch[4] && ipNeighMatch[4].includes(':') ? ipNeighMatch[4] : null
      });
    }
  }
  return entries;
}

function parseConnections(raw) {
  const connections = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('State') || trimmed.startsWith('Proto') || trimmed.startsWith('Active')) continue;
    const parts = trimmed.split(/\s+/);
    if (!parts[0]) continue;
    if (trimmed.includes('LISTEN') || trimmed.includes('ESTAB') || trimmed.includes('TIME_WAIT') || trimmed.includes('CLOSE_WAIT')) {
      if (parts.length >= 5) {
        const local = parts[3] || '';
        const remote = parts[4] || '';
        const lAddr = local.lastIndexOf(':') > local.indexOf('[') ? local.substring(0, local.lastIndexOf(':')) : local;
        const lPort = local.lastIndexOf(':') > local.indexOf('[') ? local.substring(local.lastIndexOf(':') + 1) : '';
        const rAddr = remote.lastIndexOf(':') > remote.indexOf('[') ? remote.substring(0, remote.lastIndexOf(':')) : remote;
        const rPort = remote.lastIndexOf(':') > remote.indexOf('[') ? remote.substring(remote.lastIndexOf(':') + 1) : '';
        connections.push({
          protocol: parts[0] || 'tcp',
          state: trimmed.includes('LISTEN') ? 'LISTEN' : trimmed.includes('ESTAB') ? 'ESTABLISHED' : trimmed.includes('TIME_WAIT') ? 'TIME_WAIT' : trimmed.includes('CLOSE_WAIT') ? 'CLOSE_WAIT' : parts[1] || '',
          localAddress: lAddr.replace(/\[|\]/g, ''),
          localPort: parseInt(lPort) || 0,
          remoteAddress: rAddr.replace(/\[|\]/g, ''),
          remotePort: parseInt(rPort) || 0
        });
      }
    } else if (parts[0].startsWith('tcp') || parts[0].startsWith('udp')) {
      if (parts.length >= 4) {
        connections.push({
          protocol: parts[0],
          state: parts.length > 5 ? parts[5] : 'NONE',
          localAddress: parts[3] ? parts[3].split(':')[0].replace(/\[|\]/g, '') : '',
          localPort: parseInt(parts[3] ? parts[3].split(':').pop() : '0') || 0,
          remoteAddress: parts[4] ? parts[4].split(':')[0].replace(/\[|\]/g, '') : '',
          remotePort: parseInt(parts[4] ? parts[4].split(':').pop() : '0') || 0
        });
      }
    }
  }
  return connections;
}

function parseProcesses(raw) {
  const lines = raw.split('\n');
  if (lines.length < 2) return [];
  const header = lines[0].trim().split(/\s+/);
  const procs = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 10) continue;
    const pidIdx = header.indexOf('PID');
    const userIdx = header.indexOf('USER');
    const cpuIdx = header.indexOf('%CPU');
    const memIdx = header.indexOf('%MEM');
    const vszIdx = header.indexOf('VSZ');
    const rssIdx = header.indexOf('RSS');
    const ttyIdx = header.indexOf('TT');
    const statIdx = header.indexOf('STAT');
    const startIdx = header.indexOf('START');
    const timeIdx = header.indexOf('TIME');
    const commIdx = header.indexOf('COMMAND');
    procs.push({
      user: userIdx !== -1 ? parts[userIdx] : parts[0],
      pid: parseInt(parts[pidIdx !== -1 ? pidIdx : 1]) || 0,
      cpu: parseFloat(parts[cpuIdx !== -1 ? cpuIdx : 2]) || 0,
      mem: parseFloat(parts[memIdx !== -1 ? memIdx : 3]) || 0,
      vsz: parseInt(parts[vszIdx !== -1 ? vszIdx : 4]) || 0,
      rss: parseInt(parts[rssIdx !== -1 ? rssIdx : 5]) || 0,
      tty: ttyIdx !== -1 ? parts[ttyIdx] : (parts[6] || '?'),
      stat: statIdx !== -1 ? parts[statIdx] : (parts[7] || ''),
      start: startIdx !== -1 ? parts[startIdx] : (parts[8] || ''),
      time: timeIdx !== -1 ? parts[timeIdx] : (parts[9] || ''),
      command: commIdx !== -1 ? parts.slice(commIdx).join(' ') : parts.slice(10).join(' ')
    });
  }
  return procs;
}

function parseDiskUsage(raw) {
  const lines = raw.split('\n');
  if (lines.length < 2) return [];
  const disks = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 6) continue;
    if (parts[0].startsWith('tmpfs') || parts[0].startsWith('devtmpfs') || parts[0].startsWith('overlay')) continue;
    disks.push({
      filesystem: parts[0],
      size: parts[1],
      used: parts[2],
      available: parts[3],
      usePercent: parts[4],
      mountedOn: parts[5]
    });
  }
  return disks;
}

function parseMemoryInfo(raw) {
  const lines = raw.split('\n');
  const mem = { total: 0, used: 0, free: 0, shared: 0, buffCache: 0, available: 0, swapTotal: 0, swapUsed: 0, swapFree: 0 };
  for (const line of lines) {
    const trimmed = line.trim();
    const parts = trimmed.split(/\s+/);
    if (trimmed.startsWith('Mem:')) {
      mem.total = parseInt(parts[1]) || 0;
      mem.used = parseInt(parts[2]) || 0;
      mem.free = parseInt(parts[3]) || 0;
      mem.shared = parseInt(parts[4]) || 0;
      mem.buffCache = parseInt(parts[5]) || 0;
      mem.available = parseInt(parts[6]) || 0;
    } else if (trimmed.startsWith('Swap:')) {
      mem.swapTotal = parseInt(parts[1]) || 0;
      mem.swapUsed = parseInt(parts[2]) || 0;
      mem.swapFree = parseInt(parts[3]) || 0;
    } else if (trimmed.startsWith('Pages')) {
      const val = parseInt(trimmed.split(':')[1]) || 0;
      if (trimmed.includes('free')) mem.free += val;
      if (trimmed.includes('active')) mem.used += val;
    }
  }
  return mem;
}

function parseCPUInfo(raw) {
  const lines = raw.split('\n');
  const info = { cores: os.cpus().length, model: '', usage: [], loadAverage: [] };
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('CPU') && trimmed.includes(':')) {
      const parts = trimmed.split(/\s+/);
      const us = parts.filter(p => p.endsWith('us') || p.endsWith('us,'));
      const sy = parts.filter(p => p.endsWith('sy') || p.endsWith('sy,'));
      const id = parts.filter(p => p.endsWith('id') || p.endsWith('id,'));
      if (us.length || sy.length) {
        info.usage.push({
          user: us.length ? parseFloat(us[0]) : 0,
          system: sy.length ? parseFloat(sy[0]) : 0,
          idle: id.length ? parseFloat(id[0]) : 0
        });
      }
    }
    if (trimmed.startsWith('load average')) {
      const m = trimmed.match(/load average[s]?:\s+(.+)/);
      if (m) info.loadAverage = m[1].split(',').map(s => parseFloat(s.trim()));
    }
    if (trimmed.startsWith('model name')) {
      const m = trimmed.match(/:\s*(.+)/);
      if (m) info.model = m[1];
    }
    if (trimmed.match(/^\d+(\.\d+)?$/)) {
      info.usage.push({ percent: parseFloat(trimmed) });
    }
  }
  return info;
}

function startAgentServer(port) {
  return new Promise((resolve, reject) => {
    if (agentServer) return resolve(agentServer.address().port);
    agentServerToken = uuidv4();
    agentServer = http.createServer((req, res) => {
      const parsed = url.parse(req.url, true);
      const path = parsed.pathname;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Access-Control-Allow-Origin', '*');
      const authHeader = req.headers['authorization'];
      if (!authHeader || authHeader !== `Bearer ${agentServerToken}`) {
        res.writeHead(401);
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
      try {
        let data;
        switch (path) {
          case '/status':
            data = { status: 'ok', timestamp: new Date().toISOString(), hostname: os.hostname() };
            break;
          case '/system':
            data = {
              hostname: os.hostname(),
              platform: os.platform(),
              arch: os.arch(),
              release: os.release(),
              uptime: os.uptime(),
              cpus: os.cpus().length,
              totalMemory: os.totalmem(),
              freeMemory: os.freemem(),
              loadAvg: os.loadavg()
            };
            break;
          case '/connections':
            data = { connections: [] };
            break;
          case '/processes':
            data = { processes: [] };
            break;
          case '/disk':
            data = { disk: [] };
            break;
          case '/memory': {
            const usage = process.memoryUsage();
            data = {
              total: os.totalmem(),
              free: os.freemem(),
              heapTotal: usage.heapTotal,
              heapUsed: usage.heapUsed,
              rss: usage.rss
            };
            break;
          }
          case '/cpu':
            data = { cpus: os.cpus(), loadAvg: os.loadavg() };
            break;
          default:
            res.writeHead(404);
            res.end(JSON.stringify({ error: 'Not found' }));
            return;
        }
        res.writeHead(200);
        res.end(JSON.stringify(data));
      } catch (err) {
        res.writeHead(500);
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    agentServer.on('error', (err) => {
      agentServer = null;
      reject(new AppError(500, `Agent server error: ${err.message}`));
    });
    agentServer.listen(port, () => {
      resolve({ port: agentServer.address().port, token: agentServerToken });
    });
  });
}

function stopAgentServer() {
  return new Promise((resolve) => {
    if (!agentServer) return resolve();
    agentServer.close(() => {
      agentServer = null;
      resolve();
    });
  });
}

function registerAgent(config) {
  const id = config.id || uuidv4();
  const agent = {
    id,
    type: config.type || 'ssh',
    host: config.host,
    port: config.port || (config.type === 'http' ? 9100 : 22),
    username: config.username || null,
    label: config.label || `${config.host}:${config.port}`,
    status: 'registered',
    registeredAt: new Date().toISOString(),
    lastSeen: null,
    config
  };
  agents.set(id, agent);
  return agent;
}

async function discoverAgents(subnet) {
  const base = subnet.split('/')[0].split('.').slice(0, 3).join('.');
  const found = [];
  const promises = [];
  for (let i = 1; i <= 254; i++) {
    const ip = `${base}.${i}`;
    promises.push(new Promise((resolve) => {
      const client = http.request({
        hostname: ip,
        port: 9100,
        path: '/status',
        method: 'GET',
        headers: agentServerToken ? { 'Authorization': `Bearer ${agentServerToken}` } : {},
        timeout: 3000
      }, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            const data = JSON.parse(body);
            if (data && data.status === 'ok') {
              const id = uuidv4();
              agents.set(id, {
                id,
                type: 'http',
                host: ip,
                port: 9100,
                username: null,
                label: `${ip}:9100`,
                status: 'online',
                registeredAt: new Date().toISOString(),
                lastSeen: new Date().toISOString(),
                config: { type: 'http', host: ip, port: 9100 }
              });
              found.push(ip);
            }
          } catch {}
          resolve();
        });
        res.on('error', () => resolve());
      });
      client.on('error', () => resolve());
      client.on('timeout', () => { client.destroy(); resolve(); });
      client.end();
    }));
  }
  await Promise.all(promises);
  return found;
}

function getRegisteredAgents() {
  return Array.from(agents.values());
}

function removeAgent(id) {
  return agents.delete(id);
}

async function collectFromAllAgents() {
  const results = [];
  const promises = [];
  for (const agent of agents.values()) {
    if (agent.type === 'http') {
      promises.push(new Promise((resolve) => {
        const headers = agentServerToken ? { 'Authorization': `Bearer ${agentServerToken}` } : {};
        const client = http.request({
          hostname: agent.host,
          port: agent.port,
          path: '/system',
          method: 'GET',
          headers,
          timeout: 5000
        }, (res) => {
          let body = '';
          res.on('data', chunk => body += chunk);
          res.on('end', () => {
            try {
              const data = JSON.parse(body);
              results.push({ agent: agent.id, host: agent.host, success: true, data });
            } catch { results.push({ agent: agent.id, host: agent.host, success: false, error: 'Invalid response' }); }
            resolve();
          });
          res.on('error', (err) => {
            results.push({ agent: agent.id, host: agent.host, success: false, error: err.message });
            resolve();
          });
        });
        client.on('error', (err) => {
          results.push({ agent: agent.id, host: agent.host, success: false, error: err.message });
          resolve();
        });
        client.on('timeout', () => {
          client.destroy();
          results.push({ agent: agent.id, host: agent.host, success: false, error: 'Timeout' });
          resolve();
        });
        client.end();
      }));
    } else if (agent.type === 'ssh') {
      promises.push((async () => {
        let conn;
        try {
          conn = await connectViaSSH(agent.config);
          const system = await executeSSHCommand(conn, 'uname -a');
          const uptime = await getRemoteUptime(conn);
          results.push({
            agent: agent.id,
            host: agent.host,
            success: true,
            data: { system, uptime }
          });
        } catch (err) {
          results.push({ agent: agent.id, host: agent.host, success: false, error: err.message });
        } finally {
          if (conn) disconnectSSH(conn);
        }
      })());
    }
  }
  await Promise.all(promises);
  return results;
}

module.exports = {
  connectViaSSH,
  executeSSHCommand,
  disconnectSSH,
  getRemoteConnections,
  getRemoteProcesses,
  getRemoteDisk,
  getRemoteMemory,
  getRemoteCPU,
  getRemoteUptime,
  getRemoteInterfaces,
  getRemoteRoutingTable,
  getRemoteDnsCache,
  getRemoteARP,
  parseConnections,
  parseProcesses,
  parseDiskUsage,
  parseMemoryInfo,
  parseCPUInfo,
  startAgentServer,
  stopAgentServer,
  registerAgent,
  discoverAgents,
  getRegisteredAgents,
  removeAgent,
  collectFromAllAgents
};
