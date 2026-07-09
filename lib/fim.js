let baseline = [];
let scanHistory = [];
let watcherTimer = null;

function getBaseline() { return baseline; }

function createBaseline(paths) {
  baseline = (paths || []).map((p) => ({ filePath: p, hash: `hash_${Date.now()}`, size: 1024 }));
  return baseline;
}

function addToBaseline(filePath) {
  const entry = { filePath, hash: `hash_${Date.now()}`, size: 1024 };
  baseline.push(entry);
  return entry;
}

function runScan() {
  const scan = { id: `scan_${Date.now()}`, timestamp: new Date().toISOString(), changed: 0, added: 0, removed: 0 };
  scanHistory.push(scan);
  return scan;
}

function getFIMReport() { return { baseline, scanHistory }; }
function getScanHistory() { return scanHistory; }
function getLastScan() { return scanHistory[scanHistory.length - 1] || null; }

function getConfig() { return { enabled: true, interval: 3600, paths: ['/etc', '/usr/local'] }; }

function saveConfig(body) { return { ...body }; }

function startWatcher(intervalMs) {
  if (watcherTimer) clearInterval(watcherTimer);
  watcherTimer = setInterval(() => runScan(), intervalMs || 60000);
}

function stopWatcher() {
  if (watcherTimer) { clearInterval(watcherTimer); watcherTimer = null; }
}

function removeFromBaseline(filePath) {
  baseline = baseline.filter((e) => e.filePath !== filePath);
}

function clearBaseline() { baseline = []; }

module.exports = { getBaseline, createBaseline, addToBaseline, runScan, getFIMReport, getScanHistory, getLastScan, getConfig, saveConfig, startWatcher, stopWatcher, removeFromBaseline, clearBaseline };
