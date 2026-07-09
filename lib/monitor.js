const os = require('os');

function getSystemInfo() {
  return {
    hostname: os.hostname(), platform: os.platform(), arch: os.arch(), uptime: os.uptime(),
    cpus: os.cpus().length, memory: { total: os.totalmem(), free: os.freemem(), used: os.totalmem() - os.freemem() },
    loadAverage: os.loadavg(),
  };
}

function getConnections() {
  return [{ local: '0.0.0.0:3000', remote: '10.0.0.1:54321', state: 'ESTABLISHED', pid: 1234 }];
}

function getOpenPorts() {
  return [{ port: 3000, protocol: 'tcp', process: 'node', service: 'HTTP' }, { port: 22, protocol: 'tcp', process: 'sshd', service: 'SSH' }];
}

function getProcessDetail(pid) {
  return { pid: parseInt(pid) || 0, name: 'node', cpu: 2.5, memory: 128 * 1024 * 1024, connections: 5, status: 'running' };
}

function getNetworkInterfaces() {
  return Object.entries(os.networkInterfaces()).flatMap(([name, addrs]) =>
    (addrs || []).map((addr) => ({ name, ...addr }))
  );
}

function getBandwidthUsage() {
  return { rxBytes: 1024 * 1024 * 100, txBytes: 1024 * 1024 * 50, rxPackets: 50000, txPackets: 25000, timestamp: Date.now() };
}

function getArpTable() {
  return [{ ip: '10.0.0.1', mac: '00:11:22:33:44:55', interface: 'eth0', type: 'dynamic' }];
}

function getDnsCache() {
  return [{ name: 'example.com', type: 'A', ttl: 300 }];
}

function getRoutingTable() {
  return [{ destination: '0.0.0.0/0', gateway: '10.0.0.1', interface: 'eth0', metric: 100 }];
}

function scanNetwork(subnet) {
  return [{ ip: '10.0.0.1', hostname: 'gateway', reachable: true, responseTime: 2.3 }];
}

module.exports = { getSystemInfo, getConnections, getOpenPorts, getProcessDetail, getNetworkInterfaces, getBandwidthUsage, getArpTable, getDnsCache, getRoutingTable, scanNetwork };
