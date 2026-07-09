const path = require('path');

const PCAP_DIR = path.join(__dirname, '..', 'data', 'pcap');

function analyze(captureSize) {
  const count = captureSize || 100;
  return Array.from({ length: count }, (_, i) => ({
    id: `pcap_pkt_${i}`, timestamp: Date.now() - i * 100, srcIp: '10.0.0.1', dstIp: '8.8.8.8',
    srcPort: 12345 + i, dstPort: 443, protocol: 'TCP', length: 1500, info: `Packet ${i}`,
  }));
}

module.exports = { PCAP_DIR, analyze };
