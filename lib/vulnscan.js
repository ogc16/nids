let scans = [];
let scanResults = {};

function startScan(targets) {
  const scanId = `scan_${Date.now()}`;
  scans.push({ scanId, targets: targets || ['10.0.0.1'], status: 'running', progress: 0, startedAt: new Date().toISOString() });
  scanResults[scanId] = [];
  return scanId;
}

function getScanStatus(scanId) {
  return scans.find((s) => s.scanId === scanId) || null;
}

function getScanResults(scanId) {
  if (!scanResults[scanId]) return null;
  return {
    scanId, findings: scanResults[scanId] || [],
    summary: { critical: 2, high: 5, medium: 8, low: 12, total: 27 },
  };
}

function cancelScan(scanId) {
  const scan = scans.find((s) => s.scanId === scanId);
  if (scan) scan.status = 'cancelled';
}

function getScanHistory() { return scans; }

function getVulnerabilityReport(filters) {
  return {
    filters: filters || {},
    findings: [
      { id: 'CVE-2024-1234', severity: 'critical', score: 9.8, name: 'Remote Code Execution', affected: '10.0.0.1', status: 'open' },
      { id: 'CVE-2024-5678', severity: 'high', score: 7.5, name: 'SQL Injection', affected: '10.0.0.12', status: 'open' },
    ],
  };
}

function assessAsset(asset) {
  return { assetId: asset.id || asset._id || 'unknown', findings: 5, riskScore: 6.5 };
}

module.exports = { startScan, getScanStatus, getScanResults, cancelScan, getScanHistory, getVulnerabilityReport, assessAsset };
