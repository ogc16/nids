const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const config = require('./config');

const PCAP_DIR = path.join(config.dataDir, 'pcap');
const PCAP_META_FILE = path.join(config.dataDir, 'pcap-captures.json');

let tsharkPath = null;
let tsharkAvailable = false;

function findTshark() {
  if (tsharkPath) return tsharkPath;
  const candidates = ['tshark', 'C:\\Program Files\\Wireshark\\tshark.exe', 'C:\\Program Files (x86)\\Wireshark\\tshark.exe'];
  for (const cmd of candidates) {
    try {
      execSync(`"${cmd}" --version`, { stdio: 'ignore', timeout: 5000 });
      tsharkPath = cmd;
      tsharkAvailable = true;
      return cmd;
    } catch {}
  }
  tsharkAvailable = false;
  return null;
}

function isTsharkAvailable() {
  if (tsharkPath === null) findTshark();
  return tsharkAvailable;
}

function ensurePcapDir() {
  if (!fs.existsSync(PCAP_DIR)) fs.mkdirSync(PCAP_DIR, { recursive: true });
}

function readMeta() {
  try { return JSON.parse(fs.readFileSync(PCAP_META_FILE, 'utf8')); } catch { return []; }
}

function writeMeta(meta) {
  fs.writeFileSync(PCAP_META_FILE, JSON.stringify(meta, null, 2), 'utf8');
}

function nextId(items) {
  return items.reduce((max, i) => Math.max(max, i.id), 0) + 1;
}

function tsharkJson(args) {
  return new Promise((resolve, reject) => {
    const tshark = findTshark();
    if (!tshark) return reject(new Error('Packet analysis tool not available'));
    const child = spawn(tshark, args, { windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => stdout += d);
    child.stderr.on('data', d => stderr += d);
    child.on('close', code => {
      if (code !== 0 && !stdout) return reject(new Error('Packet analysis failed'));
      try { resolve(JSON.parse(stdout)); } catch { resolve(stdout); }
    });
    child.on('error', () => reject(new Error('Packet analysis tool failed to start')));
  });
}

function tsharkRaw(args) {
  return new Promise((resolve, reject) => {
    const tshark = findTshark();
    if (!tshark) return reject(new Error('Packet analysis tool not available'));
    const child = spawn(tshark, args, { windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => stdout += d);
    child.stderr.on('data', d => stderr += d);
    child.on('close', code => {
      if (code !== 0 && !stdout) return reject(new Error('Packet analysis failed'));
      resolve(stdout);
    });
    child.on('error', () => reject(new Error('Packet analysis tool failed to start')));
  });
}

function createCaptureRecord(filename, originalName, size, metadata) {
  ensurePcapDir();
  const meta = readMeta();
  const record = {
    id: nextId(meta),
    filename,
    originalName,
    size,
    uploadedAt: new Date().toISOString(),
    metadata: {
      packets: metadata.packets || null,
      duration: metadata.duration || null,
      protocols: metadata.protocols || [],
      startTime: metadata.startTime || null,
      endTime: metadata.endTime || null,
      ...metadata
    }
  };
  meta.push(record);
  writeMeta(meta);
  return record;
}

async function getPcapFile(id) {
  const meta = readMeta();
  const record = meta.find(m => m.id === parseInt(id));
  if (!record) throw new Error(`Capture #${id} not found`);
  const filePath = path.join(PCAP_DIR, record.filename);
  if (!fs.existsSync(filePath)) throw new Error(`Capture file #${id} not found on disk`);
  return { record, filePath };
}

async function getProtocolHierarchy(id) {
  const { filePath } = await getPcapFile(id);
  const output = await tsharkRaw(['-r', filePath, '-z', 'io,phs']);
  return parsePhsOutput(output);
}

async function getEndpoints(id, type = 'ip') {
  const { filePath } = await getPcapFile(id);
  const output = await tsharkRaw(['-r', filePath, '-z', `endpoints,${type}`]);
  return parseEndpointOutput(output, type);
}

async function getConversations(id, type = 'ip') {
  const { filePath } = await getPcapFile(id);
  const output = await tsharkRaw(['-r', filePath, '-z', `conv,${type}`]);
  return parseConvOutput(output, type);
}

async function getPackets(id, filter, limit = 200, offset = 0) {
  const { filePath } = await getPcapFile(id);
  const fields = ['frame.number', 'frame.time', 'ip.src', 'ip.dst', 'ip.proto', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'frame.len', '_ws.col.Protocol', 'tcp.flags.syn', 'tcp.flags.ack', 'tcp.flags.fin', 'tcp.flags.reset', 'http.request.method', 'http.request.uri', 'http.response.code', 'http.host', 'http.user_agent', 'http.content_type', 'http.referer', 'http.request.full_uri', 'http.response.phrase', 'http.request.version', 'dns.qry.name', 'tls.handshake.type'];
  const args = ['-r', filePath, '-T', 'json', '-e', fields.join(' -e ')];
  if (filter) args.push('-Y', filter);
  args.push('-c', String(limit + offset));
  const output = await tsharkJson(args);
  const packets = Array.isArray(output) ? output : [];
  return {
    total: packets.length,
    offset,
    limit,
    packets: packets.slice(offset, offset + limit).map(p => ({
      number: parseInt(p._source?.layers?.['frame.number']?.[0]),
      time: p._source?.layers?.['frame.time']?.[0],
      srcIp: p._source?.layers?.['ip.src']?.[0] || p._source?.layers?.['ipv6.src']?.[0] || '',
      dstIp: p._source?.layers?.['ip.dst']?.[0] || p._source?.layers?.['ipv6.dst']?.[0] || '',
      protocol: p._source?.layers?.['_ws.col.Protocol']?.[0] || '',
      srcPort: parseInt(p._source?.layers?.['tcp.srcport']?.[0] || p._source?.layers?.['udp.srcport']?.[0] || 0),
      dstPort: parseInt(p._source?.layers?.['tcp.dstport']?.[0] || p._source?.layers?.['udp.dstport']?.[0] || 0),
      length: parseInt(p._source?.layers?.['frame.len']?.[0] || 0),
      info: getPacketInfo(p),
      srcPortDisplay: p._source?.layers?.['tcp.srcport']?.[0] || p._source?.layers?.['udp.srcport']?.[0] || '',
      dstPortDisplay: p._source?.layers?.['tcp.dstport']?.[0] || p._source?.layers?.['udp.dstport']?.[0] || ''
    }))
  };
}

async function getHttpAnalysis(id) {
  const { filePath } = await getPcapFile(id);
  const output = await tsharkRaw(['-r', filePath, '-T', 'json', '-e', 'frame.number', '-e', 'frame.time', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.srcport', '-e', 'tcp.dstport', '-e', 'http.request.method', '-e', 'http.request.uri', '-e', 'http.response.code', '-e', 'http.host', '-e', 'http.user_agent', '-e', 'http.content_type', '-e', 'http.referer', '-e', 'http.request.full_uri', '-e', 'http.response.phrase', '-Y', 'http or http2']);
  const packets = parseTsharkJsonOutput(output);
  const httpFlows = [];
  const methodCount = {};
  const statusCount = {};
  const hostCount = {};
  const uriCount = {};

  (Array.isArray(packets) ? packets : []).forEach(p => {
    const layers = p._source?.layers || {};
    const method = layers['http.request.method']?.[0];
    const uri = layers['http.request.uri']?.[0];
    const status = layers['http.response.code']?.[0];
    const host = layers['http.host']?.[0];
    const ua = layers['http.user_agent']?.[0];
    const contentType = layers['http.content_type']?.[0];
    const referer = layers['http.referer']?.[0];
    const fullUri = layers['http.request.full_uri']?.[0];
    const phrase = layers['http.response.phrase']?.[0];

    const flow = {
      number: parseInt(layers['frame.number']?.[0]),
      time: layers['frame.time']?.[0],
      srcIp: layers['ip.src']?.[0] || '',
      dstIp: layers['ip.dst']?.[0] || '',
      srcPort: parseInt(layers['tcp.srcport']?.[0] || 0),
      dstPort: parseInt(layers['tcp.dstport']?.[0] || 0),
      method: method || null,
      uri: uri || fullUri || null,
      status: status ? parseInt(status) : null,
      host: host || null,
      userAgent: ua || null,
      contentType: contentType || null,
      referer: referer || null,
      phrase: phrase || null
    };
    httpFlows.push(flow);
    if (method) methodCount[method] = (methodCount[method] || 0) + 1;
    if (status) {
      const group = Math.floor(parseInt(status) / 100) + 'xx';
      statusCount[group] = (statusCount[group] || 0) + 1;
      statusCount[status] = (statusCount[status] || 0) + 1;
    }
    if (host) hostCount[host] = (hostCount[host] || 0) + 1;
    if (uri) uriCount[uri] = (uriCount[uri] || 0) + 1;
  });

  return {
    totalHttpPackets: httpFlows.length,
    methodDistribution: Object.entries(methodCount).map(([method, count]) => ({ method, count })),
    statusDistribution: Object.entries(statusCount).map(([code, count]) => ({ code, count })),
    topHosts: Object.entries(hostCount).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([host, count]) => ({ host, count })),
    topUris: Object.entries(uriCount).sort((a, b) => b[1] - a[1]).slice(0, 30).map(([uri, count]) => ({ uri, count })),
    requests: httpFlows.filter(f => f.method).length,
    responses: httpFlows.filter(f => f.status).length,
    httpFlows: httpFlows.slice(0, 500)
  };
}

function parseTsharkJsonOutput(output) {
  try { return JSON.parse(output); } catch { return []; }
}

function getPacketInfo(pkt) {
  const layers = pkt._source?.layers || {};
  if (layers['http.request.method']) {
    const method = layers['http.request.method'][0];
    const uri = layers['http.request.uri']?.[0] || layers['http.request.full_uri']?.[0] || '/';
    const host = layers['http.host']?.[0];
    return `${method} ${uri}${host ? ` (${host})` : ''}`;
  }
  if (layers['http.response.code']) {
    const code = layers['http.response.code'][0];
    const phrase = layers['http.response.phrase']?.[0] || '';
    return `HTTP ${code} ${phrase}`;
  }
  if (layers['dns.qry.name']) return `DNS ${layers['dns.qry.name'][0]}`;
  if (layers['tls.handshake.type']) {
    const type = parseInt(layers['tls.handshake.type'][0]);
    const types = { 1: 'Client Hello', 2: 'Server Hello', 11: 'Certificate', 16: 'Encrypted Extensions' };
    return `TLS ${types[type] || type}`;
  }
  const srcp = layers['tcp.srcport']?.[0] || layers['udp.srcport']?.[0] || '';
  const dstp = layers['tcp.dstport']?.[0] || layers['udp.dstport']?.[0] || '';
  if (layers['tcp.flags.syn']?.[0] === '1' && layers['tcp.flags.ack']?.[0] !== '1') return `SYN ${srcp} -> ${dstp}`;
  if (layers['tcp.flags.fin']?.[0] === '1') return `FIN ${srcp} -> ${dstp}`;
  if (layers['tcp.flags.reset']?.[0] === '1') return `RST ${srcp} -> ${dstp}`;
  return `${srcp} -> ${dstp}`;
}

function parsePhsOutput(output) {
  const lines = output.split('\n').filter(l => l.trim());
  const root = { name: 'Protocol Hierarchy', children: [] };
  const stack = [{ node: root, depth: -1 }];
  for (const line of lines) {
    const trimmed = line.replace(/\s+$/, '');
    const depth = line.length - trimmed.length;
    const statsMatch = trimmed.match(/([^\s]+)\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)%\s+(.+)/);
    if (statsMatch) {
      const node = { name: statsMatch[1], packets: statsMatch[6].trim(), children: [] };
      while (stack.length > 0 && stack[stack.length - 1].depth >= depth) stack.pop();
      if (stack.length > 0) stack[stack.length - 1].node.children.push(node);
      stack.push({ node, depth });
    }
  }
  return root;
}

function parseEndpointOutput(output, type) {
  const lines = output.split('\n').filter(l => l.trim());
  const endpoints = [];
  let capture = false;
  for (const line of lines) {
    if (line.includes('===')) { capture = true; continue; }
    if (!capture) continue;
    if (line.includes('=======')) break;
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 4) {
      const bytesIdx = parts.length - 1;
      const txIdx = parts.length - 3;
      const rxIdx = parts.length - 4;
      endpoints.push({
        address: parts.slice(0, parts.length - 4).join(' '),
        rxPackets: parseInt(parts[rxIdx]) || 0,
        txPackets: parseInt(parts[txIdx]) || 0,
        bytes: parseInt(parts[bytesIdx]) || 0
      });
    }
  }
  return endpoints;
}

function parseConvOutput(output, type) {
  const lines = output.split('\n').filter(l => l.trim());
  const conversations = [];
  let capture = false;
  for (const line of lines) {
    if (line.includes('===')) { capture = true; continue; }
    if (!capture) continue;
    if (line.includes('=======')) break;
    if (line.startsWith('|')) {
      const parts = line.split('|').filter(p => p.trim());
      if (parts.length >= 5) {
        conversations.push({
          addrA: parts[0]?.trim() || '',
          addrB: parts[1]?.trim() || '',
          rxPackets: parseInt(parts[2]) || 0,
          txPackets: parseInt(parts[3]) || 0,
          bytes: parseInt(parts[4]) || 0
        });
      }
    }
  }
  return conversations;
}

async function listInterfaces() {
  const output = await tsharkRaw(['-D']);
  const interfaces = [];
  output.split('\n').filter(l => l.trim()).forEach(line => {
    const match = line.match(/\d+\.\s+(.+?)\s+\((.+?)\)/);
    if (match) interfaces.push({ name: match[1].trim(), description: match[2].trim() });
  });
  return interfaces;
}

async function getPacketCount(id) {
  const { filePath } = await getPcapFile(id);
  const output = await tsharkRaw(['-r', filePath, '-T', 'fields', '-e', 'frame.number', '-c', '1']);
  const countOutput = await tsharkRaw(['-r', filePath, '-T', 'fields', '-e', 'frame.number']);
  return countOutput.split('\n').filter(l => l.trim()).length;
}

async function getCaptureMetadata(id) {
  const { filePath, record } = await getPcapFile(id);
  try {
    const count = await getPacketCount(id);
    record.metadata.packets = count;
    const meta = readMeta();
    const idx = meta.findIndex(m => m.id === parseInt(id));
    if (idx !== -1) { meta[idx].metadata.packets = count; writeMeta(meta); }
  } catch {}
  return record;
}

let activeCaptures = {};

async function startLiveCapture(interfaceName, duration, filter) {
  if (activeCaptures[interfaceName]) throw new Error('Capture already running on this interface');
  const tshark = findTshark();
  if (!tshark) throw new Error('Packet capture tool not available');

  const args = ['-i', interfaceName, '-T', 'json'];
  if (duration > 0) args.push('-a', `duration:${duration}`);
  if (filter) args.push('-Y', filter);

  const child = spawn(tshark, args, { windowsHide: true });
  const captureId = `${interfaceName}-${Date.now()}`;
  let packets = [];

  activeCaptures[captureId] = {
    child, interfaceName, filter, startedAt: new Date().toISOString(),
    packetCount: 0, packets: [],
    cleanup: () => {
      delete activeCaptures[captureId];
    }
  };

  child.stdout.on('data', data => {
    try {
      const lines = data.toString().trim().split('\n').filter(l => l.trim());
      for (const line of lines) {
        try {
          const pkt = JSON.parse(line);
          const info = pkt._source?.layers || {};
          activeCaptures[captureId].packets.push({
            number: ++activeCaptures[captureId].packetCount,
            time: info['frame.time']?.[0] || new Date().toISOString(),
            srcIp: info['ip.src']?.[0] || info['ipv6.src']?.[0] || '',
            dstIp: info['ip.dst']?.[0] || info['ipv6.dst']?.[0] || '',
            protocol: info['_ws.col.Protocol']?.[0] || '',
            srcPort: parseInt(info['tcp.srcport']?.[0] || info['udp.srcport']?.[0] || 0),
            dstPort: parseInt(info['tcp.dstport']?.[0] || info['udp.dstport']?.[0] || 0),
            length: parseInt(info['frame.len']?.[0] || 0)
          });
          if (activeCaptures[captureId].packets.length > 10000) activeCaptures[captureId].packets.shift();
        } catch {}
      }
    } catch {}
  });

  child.on('close', () => {
    if (activeCaptures[captureId]) activeCaptures[captureId].cleanup();
  });
  child.on('error', () => {
    if (activeCaptures[captureId]) activeCaptures[captureId].cleanup();
  });

  return captureId;
}

function stopLiveCapture(captureId) {
  const cap = activeCaptures[captureId];
  if (!cap) throw new Error('Capture not found');
  cap.child.kill();
  cap.cleanup();
  return true;
}

function getActiveCaptures() {
  return Object.entries(activeCaptures).map(([id, cap]) => ({
    id, interfaceName: cap.interfaceName, filter: cap.filter,
    startedAt: cap.startedAt, packetCount: cap.packetCount
  }));
}

function validateDisplayFilter(filter) {
  return new Promise((resolve) => {
    if (!filter || !filter.trim()) return resolve({ valid: true, message: 'Empty filter is valid' });
    const tshark = findTshark();
    if (!tshark) return resolve({ valid: false, message: 'Filter validation not available' });
    const child = spawn(tshark, ['-Y', filter, '-r', path.join(PCAP_DIR, 'dummy')], { windowsHide: true });
    let stderr = '';
    child.stderr.on('data', d => stderr += d);
    child.on('close', code => {
      if (code !== 0 && stderr) resolve({ valid: false, message: 'Invalid filter syntax' });
      else resolve({ valid: true, message: 'Filter syntax is valid' });
    });
    child.on('error', () => resolve({ valid: false, message: 'Could not validate filter' }));
  });
}

async function filterTrafficData(data, filter) {
  if (!filter || !filter.trim()) return data;
  const tokens = filter.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
  return data.filter(item => {
    let result = true;
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      if (token === '&&' || token === 'and') continue;
      if (token === '||' || token === 'or') { result = result || true; continue; }
      if (token === '!') { i++; const neg = evaluateFilterToken(tokens[i], item); result = result && !neg; continue; }
      result = result && evaluateFilterToken(token, item);
    }
    return result;
  });
}

function evaluateFilterToken(token, item) {
  const match = token.match(/^([\w.]+)\s*([!=<>]+|contains|matches)\s*(.+)$/i);
  if (!match) return true;
  const [, field, operator, valueRaw] = match;
  const value = valueRaw.replace(/^"|"$/g, '').toLowerCase();
  const fieldValue = getFieldValue(field, item);
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

function getFieldValue(field, item) {
  const map = {
    'ip.src': 'srcIp', 'ip.dst': 'destIp', 'ip.addr': null,
    'tcp.port': null, 'tcp.srcport': 'srcPort', 'tcp.dstport': 'destPort',
    'udp.srcport': 'srcPort', 'udp.dstport': 'destPort',
    'frame.len': 'bytes', 'frame.protocols': 'protocol',
    'ip.proto': 'protocol'
  };
  if (field === 'ip.addr') return `${item.srcIp} ${item.destIp}`;
  if (field === 'tcp.port') return `${item.srcPort} ${item.destPort}`;
  const mapped = map[field];
  if (mapped && item[mapped] !== undefined) return item[mapped];
  if (item[field] !== undefined) return item[field];
  return null;
}

module.exports = {
  isTsharkAvailable, findTshark, ensurePcapDir, readMeta, writeMeta,
  createCaptureRecord, getPcapFile, getProtocolHierarchy, getEndpoints,
  getConversations, getPackets, getCaptureMetadata, getHttpAnalysis, listInterfaces,
  startLiveCapture, stopLiveCapture, getActiveCaptures, tsharkRaw,
  validateDisplayFilter, filterTrafficData, PCAP_DIR
};
