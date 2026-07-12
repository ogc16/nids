const os = require('os');

const SSID_NAMES = [
  'Corp-WiFi', 'Corp-Guest', 'IoT-Devices', 'IT-Admin', 'VoIP-Net',
  'DevOps-5G', 'HR-Private', 'Guest-Portal', 'Security-Cam', 'Exec-WiFi',
  'Lab-Testing', 'Printer-Net', 'BYOD-Access', 'Legacy-2G', 'Temp-Event'
];

const SECURITY_MODES = ['WPA3-SAE', 'WPA2-PSK', 'WPA2-Enterprise', 'WPA3-Enterprise', 'Open', 'WEP'];
const BANDS = ['2.4GHz', '5GHz', '6GHz'];
const CHANNELS_24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
const CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165];
const CHANNELS_6 = [1, 5, 9];

const VENDORS = [
  'Cisco', 'Aruba', 'Ubiquiti', 'Meraki', 'Ruckus', 'Juniper', 'TP-Link', 'Netgear', 'Alcatel-Lucent', 'Extreme Networks'
];

const CLIENT_OS_TYPES = ['Windows 11', 'macOS 14', 'iOS 17', 'Android 14', 'Linux', 'ChromeOS', 'IoT Device'];

const ANOMALY_TYPES = [
  { type: 'Rogue AP', severity: 'critical', description: 'Unauthorized access point detected on network' },
  { type: 'Evil Twin', severity: 'critical', description: 'Rogue AP mimicking legitimate SSID detected' },
  { type: 'Deauth Flood', severity: 'high', description: 'Excessive deauthentication frames detected' },
  { type: 'Signal Anomaly', severity: 'medium', description: 'Unusual signal strength pattern detected' },
  { type: 'Channel Hopping', severity: 'medium', description: 'AP rapidly switching channels' },
  { type: 'Brute Force WPA', severity: 'high', description: 'Multiple failed WPA handshake attempts' },
  { type: 'MAC Spoofing', severity: 'critical', description: 'Duplicate MAC address detected on different APs' },
  { type: 'Karma Attack', severity: 'critical', description: 'Responding to wildcard probe requests' },
  { type: 'Beacon Flood', severity: 'high', description: 'Excessive beacon frames from unknown source' },
  { type: 'Client Isolation Bypass', severity: 'medium', description: 'Client-to-client traffic detected on isolated network' },
  { type: 'Weak Cipher', severity: 'low', description: 'AP using deprecated encryption (TKIP/RC4)' },
  { type: 'Probe Request Storm', severity: 'medium', description: 'Abnormal volume of probe requests from single client' }
];

function generateBSSID() {
  const prefixes = ['00:1A:2B', '00:22:6B', '44:E1:73', 'AC:8B:A8', 'B4:5D:50', 'C0:25:E9', 'D4:6E:0E', 'E8:94:F6'];
  const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
  const suffix = Array.from({ length: 3 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':');
  return `${prefix}:${suffix}`;
}

function generateMAC() {
  return Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':');
}

function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randChoice(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function generateAccessPoints(count = 12) {
  const aps = [];
  const usedSSIDs = new Set();
  for (let i = 0; i < count; i++) {
    let ssid;
    do { ssid = randChoice(SSID_NAMES); } while (usedSSIDs.has(ssid) && usedSSIDs.size < SSID_NAMES.length);
    usedSSIDs.add(ssid);

    const band = randChoice(BANDS);
    const channels = band === '2.4GHz' ? CHANNELS_24 : band === '5GHz' ? CHANNELS_5 : CHANNELS_6;
    const security = randChoice(SECURITY_MODES);
    const channel = randChoice(channels);
    const signalStrength = band === '2.4GHz' ? randInt(-85, -30) : band === '5GHz' ? randInt(-80, -25) : randInt(-75, -20);
    const clientCount = randInt(0, 35);
    const vendor = randChoice(VENDORS);

    aps.push({
      id: i + 1,
      ssid,
      bssid: generateBSSID(),
      channel,
      band,
      frequency: band === '2.4GHz' ? 2400 + channel * 5 : band === '5GHz' ? 5000 + channel * 5 : 5955 + channel * 5,
      signalStrength,
      signalQuality: Math.max(0, Math.min(100, Math.round((signalStrength + 100) * 1.25))),
      security,
      vendor,
      clientCount,
      status: clientCount > 0 ? 'active' : (Math.random() > 0.3 ? 'idle' : 'down'),
      txPower: randInt(15, 30),
      rxBytes: randInt(1024, 1024 * 1024 * 50),
      txBytes: randInt(512, 1024 * 1024 * 20),
      uptime: randInt(3600, 864000),
      lastSeen: new Date(Date.now() - randInt(0, 3600000)).toISOString(),
      hidden: Math.random() > 0.9,
      wmm: Math.random() > 0.2,
      bandSteering: band === '5GHz' || band === '6GHz',
      maxClients: randInt(20, 200),
      connectedClients: clientCount
    });
  }
  return aps;
}

function generateClients(aps, count = 45) {
  const clients = [];
  for (let i = 0; i < count; i++) {
    const ap = randChoice(aps.filter(a => a.status === 'active'));
    const signalOffset = randInt(-20, 5);
    const signalStrength = ap ? Math.min(-20, ap.signalStrength + signalOffset) : randInt(-85, -40);
    clients.push({
      id: i + 1,
      mac: generateMAC(),
      hostname: `device-${String(i + 1).padStart(3, '0')}`,
      os: randChoice(CLIENT_OS_TYPES),
      ip: `10.0.${randInt(1, 10)}.${randInt(2, 254)}`,
      apBssid: ap?.bssid || 'N/A',
      apSsid: ap?.ssid || 'Disconnected',
      channel: ap?.channel || 0,
      band: ap?.band || 'N/A',
      signalStrength,
      signalQuality: Math.max(0, Math.min(100, Math.round((signalStrength + 100) * 1.25))),
      txRate: randInt(6, 600),
      rxRate: randInt(6, 600),
      txBytes: randInt(100, 1024 * 1024 * 5),
      rxBytes: randInt(500, 1024 * 1024 * 20),
      connected: Math.random() > 0.15,
      authMethod: randChoice(['WPA3-SAE', 'WPA2-PSK', '802.1X', 'Open']),
      vlan: randInt(1, 10),
      firstSeen: new Date(Date.now() - randInt(3600000, 604800000)).toISOString(),
      lastActivity: new Date(Date.now() - randInt(0, 7200000)).toISOString(),
      isRogue: Math.random() > 0.97,
      suspicious: Math.random() > 0.93,
      packetsPerSecond: randInt(0, 500)
    });
  }
  return clients;
}

function generateChannelUtilization(aps) {
  const channels24 = CHANNELS_24.map(ch => {
    const apsOnChannel = aps.filter(a => a.band === '2.4GHz' && a.channel === ch);
    const utilization = apsOnChannel.length > 0 ? Math.min(100, randInt(10, 95) + apsOnChannel.length * 5) : randInt(0, 8);
    const noise = randInt(-95, -80);
    return {
      channel: ch,
      band: '2.4GHz',
      frequency: 2412 + (ch - 1) * 5,
      utilization,
      apCount: apsOnChannel.length,
      noiseFloor: noise,
      snr: apsOnChannel.length > 0 ? randInt(15, 45) : 0,
      interference: utilization > 60 ? 'high' : utilization > 30 ? 'medium' : 'low'
    };
  });

  const channels5 = CHANNELS_5.map(ch => {
    const apsOnChannel = aps.filter(a => a.band === '5GHz' && a.channel === ch);
    const utilization = apsOnChannel.length > 0 ? Math.min(100, randInt(5, 60) + apsOnChannel.length * 3) : randInt(0, 5);
    return {
      channel: ch,
      band: '5GHz',
      frequency: 5000 + ch * 5,
      utilization,
      apCount: apsOnChannel.length,
      noiseFloor: randInt(-95, -85),
      snr: apsOnChannel.length > 0 ? randInt(20, 55) : 0,
      interference: utilization > 50 ? 'high' : utilization > 20 ? 'medium' : 'low'
    };
  });

  const channels6 = CHANNELS_6.map(ch => {
    const apsOnChannel = aps.filter(a => a.band === '6GHz' && a.channel === ch);
    const utilization = apsOnChannel.length > 0 ? Math.min(100, randInt(3, 40) + apsOnChannel.length * 2) : randInt(0, 3);
    return {
      channel: ch,
      band: '6GHz',
      frequency: 5955 + ch * 5,
      utilization,
      apCount: apsOnChannel.length,
      noiseFloor: randInt(-98, -88),
      snr: apsOnChannel.length > 0 ? randInt(25, 60) : 0,
      interference: utilization > 40 ? 'high' : utilization > 15 ? 'medium' : 'low'
    };
  });

  return { '2.4GHz': channels24, '5GHz': channels5, '6GHz': channels6 };
}

function generateAnomalies(aps, clients, count = 8) {
  const anomalies = [];
  for (let i = 0; i < count; i++) {
    const anomaly = randChoice(ANOMALY_TYPES);
    const targetAP = randChoice(aps);
    const targetClient = Math.random() > 0.5 ? randChoice(clients) : null;
    anomalies.push({
      id: i + 1,
      ...anomaly,
      timestamp: new Date(Date.now() - randInt(0, 86400000)).toISOString(),
      targetAP: targetAP?.ssid || 'Unknown',
      targetBssid: targetAP?.bssid || 'N/A',
      targetClient: targetClient?.mac || null,
      sourceIP: targetClient?.ip || `10.0.${randInt(1, 10)}.${randInt(2, 254)}`,
      details: `${anomaly.description} on ${targetAP?.ssid || 'unknown network'}`,
      packetsCaptured: randInt(10, 5000),
      mitigated: Math.random() > 0.6,
      falsePositive: Math.random() > 0.9
    });
  }
  return anomalies.sort((a, b) => {
    const sev = { critical: 0, high: 1, medium: 2, low: 3 };
    return (sev[a.severity] || 4) - (sev[b.severity] || 4);
  });
}

function generateSecurityAudit(aps, clients) {
  const openAPs = aps.filter(a => a.security === 'Open');
  const wepAPs = aps.filter(a => a.security === 'WEP');
  const wpa2Only = aps.filter(a => a.security === 'WPA2-PSK');
  const wpa3APs = aps.filter(a => a.security.startsWith('WPA3'));
  const enterpriseAPs = aps.filter(a => a.security.includes('Enterprise'));

  return {
    overallScore: Math.max(0, 100 - openAPs.length * 10 - wepAPs.length * 15),
    totalAPs: aps.length,
    openNetworks: openAPs.length,
    wepNetworks: wpa2Only.length,
    wpa3Adoption: aps.length > 0 ? Math.round((wpa3APs.length / aps.length) * 100) : 0,
    enterpriseAdoption: aps.length > 0 ? Math.round((enterpriseAPs.length / aps.length) * 100) : 0,
    rogueClients: clients.filter(c => c.isRogue).length,
    suspiciousClients: clients.filter(c => c.suspicious).length,
    recommendations: [
      openAPs.length > 0 ? `Secure ${openAPs.length} open network(s) with WPA3 or WPA2-Enterprise` : null,
      wepAPs.length > 0 ? `Replace ${wpa2Only.length} WEP-enabled APs (deprecated encryption)` : null,
      wpa3APs.length < aps.length / 2 ? 'Upgrade more APs to WPA3 for enhanced security' : null,
      clients.filter(c => c.isRogue).length > 0 ? 'Investigate rogue client connections immediately' : null,
      enterpriseAPs.length < aps.length / 3 ? 'Consider WPA3-Enterprise for critical networks' : null
    ].filter(Boolean),
    complianceStatus: {
      '802.11w_PMF': Math.round(randInt(60, 100)),
      'WPA3_Support': Math.round((wpa3APs.length / Math.max(1, aps.length)) * 100),
      'Enterprise_Auth': Math.round((enterpriseAPs.length / Math.max(1, aps.length)) * 100),
      'Open_Networks': openAPs.length === 0 ? 100 : Math.max(0, 100 - openAPs.length * 10),
      'Hidden_SSID': Math.round((aps.filter(a => a.hidden).length / Math.max(1, aps.length)) * 100)
    }
  };
}

function getWlanReport() {
  const aps = generateAccessPoints(12);
  const clients = generateClients(aps, 45);
  const channels = generateChannelUtilization(aps);
  const anomalies = generateAnomalies(aps, clients, 8);
  const security = generateSecurityAudit(aps, clients);

  const summary = {
    totalAPs: aps.length,
    activeAPs: aps.filter(a => a.status === 'active').length,
    totalClients: clients.length,
    connectedClients: clients.filter(c => c.connected).length,
    totalChannels: CHANNELS_24.length + CHANNELS_5.length + CHANNELS_6.length,
    criticalAnomalies: anomalies.filter(a => a.severity === 'critical').length,
    highAnomalies: anomalies.filter(a => a.severity === 'high').length,
    rogueClients: clients.filter(c => c.isRogue).length,
    bandDistribution: {
      '2.4GHz': aps.filter(a => a.band === '2.4GHz').length,
      '5GHz': aps.filter(a => a.band === '5GHz').length,
      '6GHz': aps.filter(a => a.band === '6GHz').length
    },
    securityDistribution: SECURITY_MODES.reduce((acc, mode) => {
      acc[mode] = aps.filter(a => a.security === mode).length;
      return acc;
    }, {})
  };

  return {
    reportDate: new Date().toISOString(),
    summary,
    accessPoints: aps,
    clients,
    channels,
    anomalies,
    securityAudit: security
  };
}

function getAccessPoints() {
  return generateAccessPoints(12);
}

function getClients() {
  const aps = generateAccessPoints(12);
  return generateClients(aps, 45);
}

function getChannelMap() {
  const aps = generateAccessPoints(12);
  return generateChannelUtilization(aps);
}

function getAnomalies() {
  const aps = generateAccessPoints(12);
  const clients = generateClients(aps, 45);
  return generateAnomalies(aps, clients, 8);
}

function getSecurityAudit() {
  const aps = generateAccessPoints(12);
  const clients = generateClients(aps, 45);
  return generateSecurityAudit(aps, clients);
}

module.exports = {
  getWlanReport, getAccessPoints, getClients, getChannelMap, getAnomalies, getSecurityAudit
};
