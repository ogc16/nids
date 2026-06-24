const fs = require('fs');
const path = require('path');
const { ValidationError } = require('./errors');

const MODELS_DIR = path.resolve(__dirname, '..', 'data', 'ml-models');

const activeThresholds = new Map();

function ensureModelsDir() {
  fs.mkdirSync(MODELS_DIR, { recursive: true });
}

function median(arr) {
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 !== 0 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function mean(arr) {
  return arr.reduce((s, v) => s + v, 0) / arr.length;
}

function stdDev(arr, meanVal) {
  if (arr.length < 2) return 0;
  return Math.sqrt(arr.reduce((s, v) => s + (v - meanVal) ** 2, 0) / (arr.length - 1));
}

function quartiles(arr) {
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const lower = sorted.slice(0, mid);
  const upper = sorted.length % 2 === 0 ? sorted.slice(mid) : sorted.slice(mid + 1);
  return { q1: median(lower), q3: median(upper), iqr: median(upper) - median(lower) };
}

function mad(arr, medianVal) {
  const deviations = arr.map(v => Math.abs(v - medianVal));
  return median(deviations);
}

function zscoreAnomalies(data, threshold) {
  const meanVal = mean(data);
  const stdDevVal = stdDev(data, meanVal);
  const anomalies = [];

  for (let i = 0; i < data.length; i++) {
    const z = stdDevVal === 0 ? 0 : (data[i] - meanVal) / stdDevVal;
    if (Math.abs(z) > threshold) {
      const absZ = Math.abs(z);
      let severity = 'medium';
      if (absZ > threshold * 2) severity = 'critical';
      else if (absZ > threshold * 1.5) severity = 'high';
      anomalies.push({ index: i, value: data[i], score: absZ, severity });
    }
  }

  return { anomalies, stats: { mean: meanVal, stdDev: stdDevVal, median: null, q1: null, q3: null, iqr: null }, method: 'zscore' };
}

function iqrAnomalies(data, threshold) {
  const { q1, q3, iqr: iqrVal } = quartiles(data);
  const lowerBound = q1 - 1.5 * iqrVal;
  const upperBound = q3 + 1.5 * iqrVal;
  const anomalies = [];

  for (let i = 0; i < data.length; i++) {
    if (data[i] < lowerBound || data[i] > upperBound) {
      const dist = Math.min(Math.abs(data[i] - lowerBound), Math.abs(data[i] - upperBound));
      const score = iqrVal === 0 ? 1 : dist / iqrVal;
      let severity = 'medium';
      if (score > 3) severity = 'critical';
      else if (score > 2) severity = 'high';
      anomalies.push({ index: i, value: data[i], score, severity });
    }
  }

  return { anomalies, stats: { mean: mean(data), stdDev: null, median: median(data), q1, q3, iqr: iqrVal }, method: 'iqr' };
}

function madAnomalies(data, threshold) {
  const medianVal = median(data);
  const madVal = mad(data, medianVal);
  const anomalies = [];

  for (let i = 0; i < data.length; i++) {
    const dev = madVal === 0 ? 0 : Math.abs(data[i] - medianVal) / madVal;
    if (dev > threshold) {
      let severity = 'medium';
      if (dev > threshold * 2) severity = 'critical';
      else if (dev > threshold * 1.5) severity = 'high';
      anomalies.push({ index: i, value: data[i], score: dev, severity });
    }
  }

  return { anomalies, stats: { mean: mean(data), stdDev: null, median: medianVal, q1: null, q3: null, iqr: null }, method: 'mad' };
}

function detectAnomalies(data, field, options = {}) {
  if (!Array.isArray(data) || data.length === 0) {
    return { anomalies: [], stats: {}, method: options.method || 'zscore' };
  }

  const values = field ? data.map(item => (typeof item === 'object' ? item[field] : item)).filter(v => v != null && typeof v === 'number') : data.filter(v => typeof v === 'number');

  if (values.length === 0) {
    return { anomalies: [], stats: {}, method: options.method || 'zscore' };
  }

  const { method = 'zscore', threshold = 3 } = options;

  const methods = { zscore: zscoreAnomalies, iqr: iqrAnomalies, mad: madAnomalies };
  const handler = methods[method] || zscoreAnomalies;

  return handler(values, threshold);
}

function buildPortProfile(trafficData) {
  const ports = {};
  let total = 0;
  for (const entry of trafficData) {
    if (entry.dport != null) {
      ports[entry.dport] = (ports[entry.dport] || 0) + 1;
      total++;
    }
    if (entry.sport != null) {
      ports[entry.sport] = (ports[entry.sport] || 0) + 1;
      total++;
    }
  }
  return { distribution: ports, total, entropy: calculateEntropy(ports, total) };
}

function calculateEntropy(distribution, total) {
  if (total === 0) return 0;
  let entropy = 0;
  for (const count of Object.values(distribution)) {
    const p = count / total;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

function buildProtocolProfile(trafficData) {
  const protocols = {};
  let total = 0;
  for (const entry of trafficData) {
    const proto = entry.protocol || entry.proto || 'unknown';
    protocols[proto] = (protocols[proto] || 0) + 1;
    total++;
  }
  return { distribution: protocols, total };
}

function buildByteStats(trafficData) {
  const bytes = trafficData.map(e => e.bytes || e.size || 0).filter(Boolean);
  const packets = trafficData.map(e => e.packets || 1).filter(Boolean);
  return {
    bytesPerSecond: bytes.length > 0 ? mean(bytes) : 0,
    packetsPerSecond: packets.length > 0 ? mean(packets) : 0,
    avgPacketSize: bytes.length > 0 && packets.length > 0 ? bytes.reduce((a, b) => a + b, 0) / packets.reduce((a, b) => a + b, 0) : 0,
    stdDevBytes: bytes.length > 0 ? stdDev(bytes, mean(bytes)) : 0
  };
}

function buildTimeOfDayProfile(trafficData) {
  const hourly = new Array(24).fill(0);
  let total = 0;
  for (const entry of trafficData) {
    const ts = entry.timestamp || entry.time;
    if (ts) {
      const date = new Date(ts);
      const hour = date.getUTCHours();
      hourly[hour]++;
      total++;
    }
  }
  return { hourlyDistribution: hourly.map(c => total > 0 ? c / total : 0), total };
}

function buildTrafficBaseline(trafficData) {
  if (!Array.isArray(trafficData)) {
    throw new ValidationError('trafficData must be an array');
  }
  return {
    portProfile: buildPortProfile(trafficData),
    protocolProfile: buildProtocolProfile(trafficData),
    byteStats: buildByteStats(trafficData),
    timeOfDayProfile: buildTimeOfDayProfile(trafficData),
    lastUpdated: new Date().toISOString()
  };
}

function detectPortAnomalies(currentData, baseline) {
  const anomalies = [];
  const currentPorts = buildPortProfile(currentData);
  const { distribution: baselinePorts, total: baselineTotal } = baseline.portProfile;

  for (const [port, count] of Object.entries(currentPorts.distribution)) {
    const expectedCount = baselinePorts[port] || 0;
    const expectedRate = baselineTotal > 0 ? expectedCount / baselineTotal : 0;
    const currentRate = currentPorts.total > 0 ? count / currentPorts.total : 0;

    if (expectedRate === 0 && currentRate > 0.01) {
      anomalies.push({ type: 'unusual_port', severity: 'high', description: `Unusual port ${port} detected`, details: { port: parseInt(port, 10), count, currentRate } });
    } else if (expectedRate > 0 && currentRate > expectedRate * 3) {
      anomalies.push({ type: 'port_spike', severity: 'medium', description: `Port ${port} traffic spike`, details: { port: parseInt(port, 10), expectedRate, currentRate } });
    }
  }

  return anomalies;
}

function detectProtocolShifts(currentData, baseline) {
  const anomalies = [];
  const currentProtocols = buildProtocolProfile(currentData);
  const { distribution: baselineProtocols, total: baselineTotal } = baseline.protocolProfile;

  for (const [proto, count] of Object.entries(currentProtocols.distribution)) {
    const expectedCount = baselineProtocols[proto] || 0;
    const expectedRate = baselineTotal > 0 ? expectedCount / baselineTotal : 0;
    const currentRate = currentProtocols.total > 0 ? count / currentProtocols.total : 0;

    if (expectedRate === 0 && currentRate > 0.05) {
      anomalies.push({ type: 'new_protocol', severity: 'medium', description: `New protocol ${proto} detected`, details: { protocol: proto, count, currentRate } });
    } else if (expectedRate > 0 && Math.abs(currentRate - expectedRate) > expectedRate * 2 && Math.abs(currentRate - expectedRate) > 0.1) {
      anomalies.push({ type: 'protocol_shift', severity: 'high', description: `Significant shift in ${proto} protocol usage`, details: { protocol: proto, expectedRate, currentRate } });
    }
  }

  return anomalies;
}

function detectVolumeSpikes(currentData, baseline) {
  const anomalies = [];
  const { bytesPerSecond: currentBytes } = buildByteStats(currentData);
  const { bytesPerSecond: baselineBytes, stdDevBytes } = baseline.byteStats;

  if (baselineBytes > 0 && stdDevBytes > 0) {
    const z = (currentBytes - baselineBytes) / stdDevBytes;
    if (Math.abs(z) > 3) {
      anomalies.push({ type: 'volume_spike', severity: z > 0 ? 'high' : 'medium', description: z > 0 ? `Traffic volume spike (z=${z.toFixed(2)})` : `Traffic volume drop (z=${z.toFixed(2)})`, details: { currentBytes, baselineBytes, stdDevBytes, zScore: z } });
    }
  }

  return anomalies;
}

function detectConnectionRateChanges(currentData, baseline) {
  const anomalies = [];
  const rate = currentData.length > 0 ? currentData.length : 0;

  if (!baseline._lastRate) {
    return anomalies;
  }

  const change = baseline._lastRate > 0 ? (rate - baseline._lastRate) / baseline._lastRate : rate > 0 ? 1 : 0;

  if (Math.abs(change) > 0.5) {
    anomalies.push({ type: 'connection_rate_change', severity: Math.abs(change) > 1 ? 'high' : 'medium', description: `${change > 0 ? 'Increase' : 'Decrease'} in connection rate by ${Math.abs(change * 100).toFixed(0)}%`, details: { currentRate: rate, previousRate: baseline._lastRate, change } });
  }

  return anomalies;
}

function detectTrafficAnomalies(currentData, baseline) {
  if (!Array.isArray(currentData)) {
    throw new ValidationError('currentData must be an array');
  }
  if (!baseline || !baseline.portProfile) {
    throw new ValidationError('Invalid baseline model');
  }

  const anomalies = [
    ...detectPortAnomalies(currentData, baseline),
    ...detectProtocolShifts(currentData, baseline),
    ...detectVolumeSpikes(currentData, baseline),
    ...detectConnectionRateChanges(currentData, baseline)
  ];

  const overallAnomalyScore = anomalies.length > 0 ? Math.min(1, anomalies.reduce((s, a) => {
    const severityWeights = { low: 0.25, medium: 0.5, high: 0.75, critical: 1 };
    return s + (severityWeights[a.severity] || 0.5);
  }, 0) / Math.max(1, anomalies.length)) : 0;

  return { anomalies, overallAnomalyScore };
}

function updateBaseline(currentData, baseline, alpha = 0.3) {
  if (!Array.isArray(currentData)) {
    throw new ValidationError('currentData must be an array');
  }
  if (!baseline || !baseline.portProfile) {
    throw new ValidationError('Invalid baseline model');
  }

  const newBaseline = buildTrafficBaseline(currentData);
  const currentPortProfile = newBaseline.portProfile;

  const mergedPorts = { ...baseline.portProfile.distribution };
  for (const [port, count] of Object.entries(currentPortProfile.distribution)) {
    const existing = mergedPorts[port] || 0;
    mergedPorts[port] = Math.round(existing * (1 - alpha) + count * alpha);
  }

  const mergedProtocols = { ...baseline.protocolProfile.distribution };
  for (const [proto, count] of Object.entries(newBaseline.protocolProfile.distribution)) {
    const existing = mergedProtocols[proto] || 0;
    mergedProtocols[proto] = Math.round(existing * (1 - alpha) + count * alpha);
  }

  baseline.portProfile.distribution = mergedPorts;
  baseline.portProfile.total = Object.values(mergedPorts).reduce((s, v) => s + v, 0);
  baseline.portProfile.entropy = calculateEntropy(mergedPorts, baseline.portProfile.total);

  baseline.protocolProfile.distribution = mergedProtocols;
  baseline.protocolProfile.total = Object.values(mergedProtocols).reduce((s, v) => s + v, 0);

  baseline.byteStats.bytesPerSecond = baseline.byteStats.bytesPerSecond * (1 - alpha) + newBaseline.byteStats.bytesPerSecond * alpha;
  baseline.byteStats.avgPacketSize = baseline.byteStats.avgPacketSize * (1 - alpha) + newBaseline.byteStats.avgPacketSize * alpha;
  baseline.byteStats.stdDevBytes = baseline.byteStats.stdDevBytes * (1 - alpha) + newBaseline.byteStats.stdDevBytes * alpha;

  baseline.timeOfDayProfile.hourlyDistribution = baseline.timeOfDayProfile.hourlyDistribution.map((v, i) => v * (1 - alpha) + newBaseline.timeOfDayProfile.hourlyDistribution[i] * alpha);

  baseline._lastRate = currentData.length;
  baseline.lastUpdated = new Date().toISOString();

  return baseline;
}

function detectSpikes(series, options = {}) {
  if (!Array.isArray(series) || series.length < 3) {
    return { spikes: [] };
  }

  const { window: windowSize = 10, threshold = 2 } = options;
  const spikes = [];

  for (let i = 0; i < series.length; i++) {
    const start = Math.max(0, i - windowSize);
    const end = Math.min(series.length, i + windowSize + 1);
    const windowVals = series.slice(start, i).concat(series.slice(i + 1, end)).filter(v => typeof v === 'number');

    if (windowVals.length < 2) continue;

    const windowMean = mean(windowVals);
    const windowStd = stdDev(windowVals, windowMean);
    const z = windowStd === 0 ? 0 : (series[i] - windowMean) / windowStd;

    if (Math.abs(z) > threshold) {
      let severity = 'medium';
      if (Math.abs(z) > threshold * 2) severity = 'critical';
      else if (Math.abs(z) > threshold * 1.5) severity = 'high';
      spikes.push({ index: i, value: series[i], zScore: z, severity });
    }
  }

  return { spikes };
}

function detectTrends(series) {
  if (!Array.isArray(series) || series.length < 4) {
    return { trend: 'stable', slope: 0, confidence: 0 };
  }

  const n = series.length;
  const indices = series.map((_, i) => i);
  const meanX = mean(indices);
  const meanY = mean(series);

  let num = 0;
  let den = 0;
  for (let i = 0; i < n; i++) {
    num += (i - meanX) * (series[i] - meanY);
    den += (i - meanX) ** 2;
  }

  const slope = den === 0 ? 0 : num / den;
  const intercept = meanY - slope * meanX;

  let ssRes = 0;
  let ssTot = 0;
  for (let i = 0; i < n; i++) {
    const predicted = slope * i + intercept;
    ssRes += (series[i] - predicted) ** 2;
    ssTot += (series[i] - meanY) ** 2;
  }

  const r2 = ssTot === 0 ? 0 : 1 - ssRes / ssTot;
  const absSlope = Math.abs(slope);

  let trend = 'stable';
  if (absSlope > 0.1 && r2 > 0.3) {
    trend = slope > 0 ? 'upward' : 'downward';
  }

  return { trend, slope, intercept, confidence: Math.min(1, Math.max(0, r2)) };
}

function detectPeriodicity(series) {
  if (!Array.isArray(series) || series.length < 10) {
    return { periodic: false, period: null, confidence: 0 };
  }

  const n = series.length;
  const meanVal = mean(series);
  const detrended = series.map(v => v - meanVal);

  const maxLag = Math.min(Math.floor(n / 2), 50);
  let bestLag = 0;
  let bestCorr = 0;

  for (let lag = 2; lag <= maxLag; lag++) {
    let num = 0;
    let den1 = 0;
    let den2 = 0;
    const pairs = n - lag;
    for (let i = 0; i < pairs; i++) {
      num += detrended[i] * detrended[i + lag];
      den1 += detrended[i] ** 2;
      den2 += detrended[i + lag] ** 2;
    }
    const denom = Math.sqrt(den1 * den2);
    const corr = denom === 0 ? 0 : num / denom;
    if (corr > bestCorr) {
      bestCorr = corr;
      bestLag = lag;
    }
  }

  const periodic = bestCorr > 0.5 && bestLag >= 2;
  return { periodic, period: periodic ? bestLag : null, confidence: periodic ? Math.min(1, bestCorr) : 0 };
}

function forecastNext(series, horizon = 1) {
  if (!Array.isArray(series) || series.length === 0) {
    return { forecasts: [], confidence: 0 };
  }

  const { trend, slope, intercept, confidence } = detectTrends(series);
  const lastIdx = series.length - 1;
  const forecasts = [];

  for (let i = 1; i <= horizon; i++) {
    forecasts.push(slope * (lastIdx + i) + intercept);
  }

  return { forecasts, confidence };
}

function analyzeUserBehavior(events) {
  if (!Array.isArray(events)) {
    return { anomalies: [], profile: {} };
  }

  const loginTimes = [];
  const failedAttempts = [];
  const accessedResources = new Set();
  const hourCounts = new Array(24).fill(0);
  let totalEvents = 0;

  for (const event of events) {
    totalEvents++;
    if (event.type === 'login' || event.action === 'login') {
      if (event.timestamp) {
        const hour = new Date(event.timestamp).getUTCHours();
        loginTimes.push(hour);
        hourCounts[hour]++;
      }
      if (event.success === false) {
        failedAttempts.push(event);
      }
    }
    if (event.resource) {
      accessedResources.add(event.resource);
    }
  }

  const anomalies = [];

  const loginHour = loginTimes.length > 0 ? mean(loginTimes) : null;
  const unusualHours = hourCounts.filter((c, h) => (h < 6 || h > 22) && c > 0);
  if (unusualHours.length > 0 && totalEvents > 0) {
    const unusualCount = unusualHours.reduce((s, c) => s + c, 0);
    const unusualRate = unusualCount / totalEvents;
    if (unusualRate > 0.3) {
      anomalies.push({ type: 'unusual_hours', severity: 'medium', description: 'Significant activity during unusual hours', details: { unusualHourCount: unusualCount, totalEvents, rate: unusualRate } });
    }
  }

  if (failedAttempts.length > 3) {
    anomalies.push({ type: 'failed_login_burst', severity: failedAttempts.length > 10 ? 'high' : 'medium', description: `${failedAttempts.length} failed login attempts detected`, details: { failedCount: failedAttempts.length, totalEvents } });
  }

  return {
    anomalies,
    profile: {
      totalEvents,
      avgLoginHour: loginHour,
      uniqueResources: accessedResources.size,
      resourceList: [...accessedResources],
      failedLoginCount: failedAttempts.length,
      hourlyDistribution: hourCounts
    }
  };
}

function analyzeNetworkBehavior(flows) {
  if (!Array.isArray(flows)) {
    return { anomalies: [], profile: {} };
  }

  const destinations = new Set();
  const protocols = {};
  const destPorts = new Set();
  let totalFlows = 0;
  let uniqueSources = new Set();

  for (const flow of flows) {
    totalFlows++;
    if (flow.dst) destinations.add(flow.dst);
    if (flow.dport) destPorts.add(flow.dport);
    if (flow.src) uniqueSources.add(flow.src);
    const proto = flow.protocol || flow.proto || 'unknown';
    protocols[proto] = (protocols[proto] || 0) + 1;
  }

  const anomalies = [];
  const connFreq = totalFlows;
  const destDiversity = destinations.size;
  const avgDestPerSource = uniqueSources.size > 0 ? destDiversity / uniqueSources.size : 0;

  if (avgDestPerSource > 50) {
    anomalies.push({ type: 'high_dest_diversity', severity: 'high', description: 'Unusually high destination diversity', details: { destinations: destDiversity, sources: uniqueSources.size, avgPerSource: avgDestPerSource } });
  }

  const uniquePorts = destPorts.size;
  if (uniquePorts > 100) {
    anomalies.push({ type: 'port_scanning', severity: 'high', description: 'Potential port scanning activity', details: { uniquePorts, totalFlows } });
  }

  return {
    anomalies,
    profile: {
      totalFlows,
      uniqueDestinations: destDiversity,
      uniqueSources: uniqueSources.size,
      uniquePorts,
      protocolDistribution: protocols,
      avgConnectionsPerSource: avgDestPerSource
    }
  };
}

function analyzeProcessBehavior(processes) {
  if (!Array.isArray(processes)) {
    return { anomalies: [], profile: {} };
  }

  const anomalies = [];
  const cpus = [];
  const mems = [];
  const processNames = new Set();
  const parentChains = {};

  for (const proc of processes) {
    if (proc.cpu != null) cpus.push(proc.cpu);
    if (proc.memory != null) mems.push(proc.memory);
    if (proc.name) processNames.add(proc.name);
    if (proc.pid && proc.ppid) {
      parentChains[proc.pid] = proc.ppid;
    }
  }

  if (cpus.length > 3) {
    const cpuMean = mean(cpus);
    const cpuStd = stdDev(cpus, cpuMean);
    for (let i = 0; i < cpus.length; i++) {
      const z = cpuStd === 0 ? 0 : (cpus[i] - cpuMean) / cpuStd;
      if (Math.abs(z) > 3) {
        anomalies.push({ type: 'cpu_anomaly', severity: Math.abs(z) > 4 ? 'high' : 'medium', description: `Unusual CPU usage: ${cpus[i].toFixed(1)}%`, details: { index: i, cpu: cpus[i], zScore: z } });
      }
    }
  }

  if (mems.length > 3) {
    const memMean = mean(mems);
    const memStd = stdDev(mems, memMean);
    for (let i = 0; i < mems.length; i++) {
      const z = memStd === 0 ? 0 : (mems[i] - memMean) / memStd;
      if (Math.abs(z) > 3) {
        anomalies.push({ type: 'memory_anomaly', severity: Math.abs(z) > 4 ? 'high' : 'medium', description: `Unusual memory usage: ${mems[i].toFixed(1)}%`, details: { index: i, memory: mems[i], zScore: z } });
      }
    }
  }

  const unusualChains = Object.entries(parentChains).filter(([pid, ppid]) => ppid !== 1 && ppid !== 0 && !parentChains[ppid] && processNames.has(pid));
  if (unusualChains.length > 2) {
    anomalies.push({ type: 'unusual_process_chain', severity: 'high', description: 'Unusual orphan process chains detected', details: { chainCount: unusualChains.length, chains: unusualChains.slice(0, 10) } });
  }

  return {
    anomalies,
    profile: {
      totalProcesses: processes.length,
      uniqueProcesses: processNames.size,
      processList: [...processNames],
      avgCpu: cpus.length > 0 ? mean(cpus) : null,
      avgMemory: mems.length > 0 ? mean(mems) : null,
      parentChains
    }
  };
}

function generateAnomalyAlerts(anomalies) {
  if (!Array.isArray(anomalies)) {
    return [];
  }

  const severityWeights = { low: 0.25, medium: 0.5, high: 0.75, critical: 1 };
  const severityScores = { low: 25, medium: 50, high: 75, critical: 95 };

  return anomalies.map((anomaly, idx) => {
    const severity = anomaly.severity || 'medium';
    const weight = severityWeights[severity] || 0.5;
    const score = anomaly.score != null ? Math.min(100, anomaly.score * 25) : severityScores[severity];
    const confidence = Math.min(100, Math.max(10, score * weight));

    const titles = {
      unusual_port: 'Unusual Port Detection',
      port_spike: 'Port Traffic Spike',
      new_protocol: 'New Protocol Detection',
      protocol_shift: 'Protocol Usage Shift',
      volume_spike: 'Traffic Volume Anomaly',
      connection_rate_change: 'Connection Rate Change',
      unusual_hours: 'Unusual Activity Hours',
      failed_login_burst: 'Failed Login Burst',
      high_dest_diversity: 'High Destination Diversity',
      port_scanning: 'Potential Port Scanning',
      cpu_anomaly: 'CPU Usage Anomaly',
      memory_anomaly: 'Memory Usage Anomaly',
      unusual_process_chain: 'Unusual Process Chain'
    };

    const title = titles[anomaly.type] || `Anomaly #${idx + 1}`;
    const description = anomaly.description || `Anomaly detected with severity ${severity}`;
    const recommendedAction = severity === 'critical' || severity === 'high' ? 'Immediate investigation required' : 'Monitor and review';

    return { score, severity, title, description, recommendedAction, confidence, type: anomaly.type, timestamp: new Date().toISOString(), details: anomaly.details || {} };
  });
}

function suppressFalsePositives(alerts, history) {
  if (!Array.isArray(alerts)) return [];
  if (!Array.isArray(history) || history.length === 0) return alerts;

  const falsePositivePatterns = new Set();
  for (const entry of history) {
    if (entry.outcome === 'false_positive' || entry.suppressed) {
      falsePositivePatterns.add(entry.title || entry.type);
    }
  }

  return alerts.filter(alert => {
    if (falsePositivePatterns.has(alert.title)) {
      return false;
    }
    if (alert.type) {
      const recentSameType = history.filter(h => (h.title === alert.title || h.type === alert.type) && !h.suppressed);
      if (recentSameType.length > 5) {
        const falsePositiveRate = recentSameType.filter(h => h.outcome === 'false_positive').length / recentSameType.length;
        if (falsePositiveRate > 0.7) {
          return false;
        }
      }
    }
    return true;
  }).map(alert => ({ ...alert, suppressed: false }));
}

function saveModel(name, model) {
  if (!name || typeof name !== 'string') {
    throw new ValidationError('Model name must be a non-empty string');
  }
  if (!model) {
    throw new ValidationError('Model data is required');
  }

  ensureModelsDir();
  const safeName = name.replace(/[^a-zA-Z0-9_-]/g, '_');
  const filePath = path.join(MODELS_DIR, `${safeName}.json`);
  const data = JSON.stringify(model, null, 2);
  fs.writeFileSync(filePath, data, 'utf8');
  return { name: safeName, path: filePath, size: Buffer.byteLength(data, 'utf8'), savedAt: new Date().toISOString() };
}

function loadModel(name) {
  if (!name || typeof name !== 'string') {
    throw new ValidationError('Model name must be a non-empty string');
  }

  ensureModelsDir();
  const safeName = name.replace(/[^a-zA-Z0-9_-]/g, '_');
  const filePath = path.join(MODELS_DIR, `${safeName}.json`);

  if (!fs.existsSync(filePath)) {
    throw new ValidationError(`Model "${safeName}" not found`);
  }

  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw);
}

function listModels() {
  ensureModelsDir();

  const files = fs.readdirSync(MODELS_DIR).filter(f => f.endsWith('.json'));
  return files.map(f => {
    const filePath = path.join(MODELS_DIR, f);
    const stat = fs.statSync(filePath);
    const name = f.replace('.json', '');
    let metadata = {};
    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(raw);
      metadata = {
        hasPortProfile: !!parsed.portProfile,
        hasProtocolProfile: !!parsed.protocolProfile,
        lastUpdated: parsed.lastUpdated || null,
        type: parsed.method || parsed.trend || 'unknown'
      };
    } catch {
      metadata = { hasPortProfile: false, hasProtocolProfile: false, lastUpdated: null, type: 'unknown' };
    }
    return { name, path: filePath, size: stat.size, modifiedAt: stat.mtime.toISOString(), ...metadata };
  });
}

function deleteModel(name) {
  if (!name || typeof name !== 'string') {
    throw new ValidationError('Model name must be a non-empty string');
  }

  ensureModelsDir();
  const safeName = name.replace(/[^a-zA-Z0-9_-]/g, '_');
  const filePath = path.join(MODELS_DIR, `${safeName}.json`);

  if (!fs.existsSync(filePath)) {
    throw new ValidationError(`Model "${safeName}" not found`);
  }

  fs.unlinkSync(filePath);
  return { name: safeName, deleted: true, deletedAt: new Date().toISOString() };
}

function createThresholdRule(name, config) {
  if (!name || typeof name !== 'string') {
    throw new ValidationError('Rule name must be a non-empty string');
  }
  if (!config || !config.field) {
    throw new ValidationError('Rule config must include a field');
  }

  const operators = ['gt', 'lt', 'gte', 'lte'];
  if (config.operator && !operators.includes(config.operator)) {
    throw new ValidationError(`Operator must be one of: ${operators.join(', ')}`);
  }

  if (config.value == null) {
    throw new ValidationError('Rule config must include a value');
  }

  const rule = {
    name,
    field: config.field,
    operator: config.operator || 'gt',
    value: config.value,
    window: config.window || 60,
    cooldown: config.cooldown || 300,
    createdAt: new Date().toISOString(),
    lastTriggered: null,
    cooldownUntil: null
  };

  activeThresholds.set(name, rule);
  return rule;
}

function evaluateThresholdRule(rule, data) {
  if (!rule) {
    throw new ValidationError('Rule is required');
  }
  if (!Array.isArray(data)) {
    throw new ValidationError('Data must be an array');
  }

  const now = Date.now();

  if (rule.cooldownUntil && now < rule.cooldownUntil) {
    return { triggered: false, reason: 'cooldown', cooldownRemaining: rule.cooldownUntil - now };
  }

  const operators = {
    gt: (a, b) => a > b,
    lt: (a, b) => a < b,
    gte: (a, b) => a >= b,
    lte: (a, b) => a <= b
  };

  const opFn = operators[rule.operator] || operators.gt;

  for (const entry of data) {
    const value = typeof entry === 'object' ? entry[rule.field] : entry;
    if (value != null && opFn(value, rule.value)) {
      rule.lastTriggered = new Date().toISOString();
      rule.cooldownUntil = now + (rule.cooldown * 1000);
      return { triggered: true, value, threshold: rule.value, operator: rule.operator, field: rule.field, name: rule.name, timestamp: rule.lastTriggered };
    }
  }

  return { triggered: false, reason: 'no_match' };
}

function getActiveThresholds() {
  return [...activeThresholds.values()].map(rule => ({
    ...rule,
    isInCooldown: rule.cooldownUntil ? Date.now() < rule.cooldownUntil : false
  }));
}

module.exports = {
  detectAnomalies,
  buildTrafficBaseline,
  detectTrafficAnomalies,
  updateBaseline,
  detectSpikes,
  detectTrends,
  detectPeriodicity,
  forecastNext,
  analyzeUserBehavior,
  analyzeNetworkBehavior,
  analyzeProcessBehavior,
  generateAnomalyAlerts,
  suppressFalsePositives,
  saveModel,
  loadModel,
  listModels,
  deleteModel,
  createThresholdRule,
  evaluateThresholdRule,
  getActiveThresholds
};
