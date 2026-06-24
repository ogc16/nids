const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const BASELINE_PATH = path.join(__dirname, '..', 'data', 'fim-baseline.json');
const CONFIG_PATH = path.join(__dirname, '..', 'data', 'fim-config.json');
const HISTORY_PATH = path.join(__dirname, '..', 'data', 'fim-history.json');

const DEFAULT_CONFIG = {
  monitoredPaths: [],
  excludePatterns: ['*.log', '*.tmp', 'node_modules/'],
  scanInterval: 300,
  maxBaselineSize: 100000,
  alertOnChange: true,
  enabled: true
};

const CRITICAL_EXTENSIONS = new Set(['.exe', '.dll', '.so', '.conf', '.pem', '.key']);

let watcherTimer = null;
let scanHistory = [];

function ensureDir(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function readJSON(filePath, fallback) {
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    }
  } catch {}
  return fallback;
}

function writeJSON(filePath, data) {
  ensureDir(filePath);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

function hashFile(filePath) {
  try {
    const content = fs.readFileSync(filePath);
    const hash = crypto.createHash('sha256').update(content).digest('hex');
    const stat = fs.statSync(filePath);
    return {
      filePath: path.resolve(filePath),
      hash,
      fileSize: stat.size,
      lastModified: stat.mtime.toISOString(),
      permissions: stat.mode.toString(8),
      owner: ''
    };
  } catch {
    return null;
  }
}

function collectFiles(dirPath, excludePatterns) {
  const results = [];
  const excludeRegexes = (excludePatterns || []).map(p => {
    const pattern = p.replace(/\./g, '\\.').replace(/\*/g, '.*').replace(/\//g, '[/\\\\]');
    return new RegExp(`^${pattern}$`, 'i');
  });

  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (excludeRegexes.some(r => r.test(entry.name) || r.test(fullPath))) continue;
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        results.push(fullPath);
      }
    }
  }

  walk(dirPath);
  return results;
}

function matchExclude(filePath, excludePatterns) {
  const name = path.basename(filePath);
  return (excludePatterns || []).some(p => {
    const pattern = p.replace(/\./g, '\\.').replace(/\*/g, '.*').replace(/\//g, '[/\\\\]');
    const re = new RegExp(`^${pattern}$`, 'i');
    return re.test(name) || re.test(filePath);
  });
}

const ALLOWED_BASE_DIRS = [
  path.resolve(process.env.FIM_BASE_DIR || process.cwd()),
  process.env.ProgramFiles || 'C:\\Program Files',
  process.env.SystemRoot || 'C:\\Windows',
  path.join(process.cwd(), 'data')
].map(p => path.resolve(p));

function isPathAllowed(targetPath) {
  const resolved = path.resolve(targetPath);
  return ALLOWED_BASE_DIRS.some(base => resolved.startsWith(base));
}

function resolvePaths(paths) {
  const resolved = [];
  for (const p of paths) {
    const absPath = path.resolve(p);
    if (!isPathAllowed(absPath)) continue;
    try {
      const stat = fs.statSync(absPath);
      if (stat.isDirectory()) {
        resolved.push(...collectFiles(absPath, []));
      } else if (stat.isFile()) {
        resolved.push(absPath);
      }
    } catch {}
  }
  return resolved;
}

function createBaseline(paths) {
  const config = getConfig();
  const allPaths = resolvePaths(paths);
  const baseline = [];

  for (const fp of allPaths) {
    if (matchExclude(fp, config.excludePatterns)) continue;
    const entry = hashFile(fp);
    if (entry) baseline.push(entry);
    if (baseline.length >= config.maxBaselineSize) break;
  }

  writeJSON(BASELINE_PATH, baseline);
  return baseline;
}

function getBaseline() {
  return readJSON(BASELINE_PATH, []);
}

function getBaselineForPath(filePath) {
  const baseline = getBaseline();
  const resolved = path.resolve(filePath);
  return baseline.find(e => e.filePath === resolved) || null;
}

function clearBaseline() {
  writeJSON(BASELINE_PATH, []);
}

function addToBaseline(filePath) {
  const config = getConfig();
  const resolved = path.resolve(filePath);
  if (!isPathAllowed(resolved)) return null;
  if (matchExclude(resolved, config.excludePatterns)) return null;
  const entry = hashFile(resolved);
  if (!entry) return null;

  const baseline = getBaseline();
  const idx = baseline.findIndex(e => e.filePath === resolved);
  if (idx >= 0) {
    baseline[idx] = entry;
  } else {
    if (baseline.length >= config.maxBaselineSize) return null;
    baseline.push(entry);
  }
  writeJSON(BASELINE_PATH, baseline);
  return entry;
}

function removeFromBaseline(filePath) {
  const resolved = path.resolve(filePath);
  const baseline = getBaseline();
  const filtered = baseline.filter(e => e.filePath !== resolved);
  if (filtered.length === baseline.length) return false;
  writeJSON(BASELINE_PATH, filtered);
  return true;
}

function runScan() {
  const baseline = getBaseline();
  const config = getConfig();
  const changed = [];
  const added = [];
  const removed = [];
  const errors = [];
  const scannedPaths = new Set();

  for (const entry of baseline) {
    scannedPaths.add(entry.filePath);
    try {
      if (!fs.existsSync(entry.filePath)) {
        removed.push({
          filePath: entry.filePath,
          changeType: 'deleted',
          oldHash: entry.hash,
          newHash: null,
          oldSize: entry.fileSize,
          newSize: null,
          oldModified: entry.lastModified,
          newModified: null
        });
        continue;
      }
      const current = hashFile(entry.filePath);
      if (!current) {
        errors.push({ filePath: entry.filePath, error: 'Failed to hash file' });
        continue;
      }
      if (current.hash !== entry.hash) {
        changed.push({
          filePath: entry.filePath,
          changeType: 'modified',
          oldHash: entry.hash,
          newHash: current.hash,
          oldSize: entry.fileSize,
          newSize: current.fileSize,
          oldModified: entry.lastModified,
          newModified: current.lastModified
        });
      }
    } catch (err) {
      errors.push({ filePath: entry.filePath, error: err.message });
    }
  }

  for (const monitoredPath of config.monitoredPaths) {
    const absPath = path.resolve(monitoredPath);
    try {
      const stat = fs.statSync(absPath);
      if (stat.isDirectory()) {
        const files = collectFiles(absPath, config.excludePatterns);
        for (const fp of files) {
          if (!scannedPaths.has(fp)) {
            scannedPaths.add(fp);
            const current = hashFile(fp);
            if (current) {
              added.push({
                filePath: fp,
                changeType: 'added',
                oldHash: null,
                newHash: current.hash,
                oldSize: null,
                newSize: current.fileSize,
                oldModified: null,
                newModified: current.lastModified
              });
            }
          }
        }
      }
    } catch {}
  }

  const result = {
    scanId: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
    timestamp: new Date().toISOString(),
    totalFiles: baseline.length,
    changed,
    added,
    removed,
    errors
  };

  scanHistory.push(result);
  if (scanHistory.length > 100) scanHistory = scanHistory.slice(-100);
  try { writeJSON(HISTORY_PATH, scanHistory); } catch {}

  const allChanges = [...changed, ...added, ...removed];
  if (allChanges.length > 0 && config.alertOnChange) {
    if (typeof onChangeCallback === 'function') {
      onChangeCallback(result);
    }
  }

  return result;
}

function runScanForPath(filePath) {
  const resolved = path.resolve(filePath);
  const baseline = getBaseline();
  const entry = baseline.find(e => e.filePath === resolved);

  if (!entry) {
    return { filePath: resolved, changeType: 'unknown', error: 'Not in baseline' };
  }

  try {
    if (!fs.existsSync(resolved)) {
      return {
        filePath: resolved,
        changeType: 'deleted',
        oldHash: entry.hash,
        newHash: null,
        oldSize: entry.fileSize,
        newSize: null,
        oldModified: entry.lastModified,
        newModified: null
      };
    }
    const current = hashFile(resolved);
    if (!current) {
      return { filePath: resolved, error: 'Failed to hash file' };
    }
    if (current.hash !== entry.hash) {
      return {
        filePath: resolved,
        changeType: 'modified',
        oldHash: entry.hash,
        newHash: current.hash,
        oldSize: entry.fileSize,
        newSize: current.fileSize,
        oldModified: entry.lastModified,
        newModified: current.lastModified
      };
    }
    return { filePath: resolved, changeType: 'unchanged' };
  } catch (err) {
    return { filePath: resolved, error: err.message };
  }
}

let onChangeCallback = null;

function startWatcher(intervalMs) {
  if (watcherTimer) return;
  const interval = intervalMs || 60000;
  watcherTimer = setInterval(() => {
    runScan();
  }, interval);
  if (watcherTimer.unref) watcherTimer.unref();
}

function stopWatcher() {
  if (watcherTimer) {
    clearInterval(watcherTimer);
    watcherTimer = null;
  }
}

function isWatching() {
  return watcherTimer !== null;
}

function onChangesDetected(callback) {
  onChangeCallback = callback;
}

let scheduledTimer = null;

function scheduleScan(cronExpression) {
  if (scheduledTimer) clearInterval(scheduledTimer);
  const intervalMs = parseCronToMs(cronExpression);
  scheduledTimer = setInterval(() => {
    runScan();
  }, intervalMs);
  if (scheduledTimer.unref) scheduledTimer.unref();
}

function parseCronToMs(expression) {
  const parts = expression.trim().split(/\s+/);
  if (parts.length === 1) return parseInt(parts[0], 10) * 1000;
  if (parts.length === 5) {
    const min = parts[0] === '*' ? 1 : parseInt(parts[0], 10);
    return min * 60 * 1000;
  }
  return 300000;
}

function getScanHistory() {
  try {
    const stored = readJSON(HISTORY_PATH, []);
    if (stored.length > 0) scanHistory = stored;
  } catch {}
  return [...scanHistory];
}

function getLastScan() {
  const history = getScanHistory();
  return history.length > 0 ? history[history.length - 1] : null;
}

function getConfig() {
  return { ...DEFAULT_CONFIG, ...readJSON(CONFIG_PATH, {}) };
}

function saveConfig(config) {
  const merged = { ...DEFAULT_CONFIG, ...config };
  writeJSON(CONFIG_PATH, merged);
  return merged;
}

function getFIMReport() {
  const config = getConfig();
  const baseline = getBaseline();
  const lastScan = getLastScan();
  const history = getScanHistory();

  let totalChanges = 0;
  let criticalChanges = 0;

  for (const scan of history) {
    const changes = [...(scan.changed || []), ...(scan.added || []), ...(scan.removed || [])];
    totalChanges += changes.length;
    for (const ch of changes) {
      const ext = path.extname(ch.filePath).toLowerCase();
      if (CRITICAL_EXTENSIONS.has(ext)) criticalChanges++;
    }
  }

  let health = 'healthy';
  if (criticalChanges > 0) health = 'critical';
  else if (totalChanges > 0) health = 'warning';

  return {
    totalMonitored: baseline.length,
    monitoredPaths: config.monitoredPaths,
    lastScan: lastScan ? {
      scanId: lastScan.scanId,
      timestamp: lastScan.timestamp,
      totalChanges: (lastScan.changed || []).length + (lastScan.added || []).length + (lastScan.removed || []).length
    } : null,
    totalChanges,
    criticalChanges,
    health,
    watcherActive: isWatching(),
    enabled: config.enabled
  };
}

module.exports = {
  createBaseline,
  getBaseline,
  getBaselineForPath,
  clearBaseline,
  addToBaseline,
  removeFromBaseline,
  runScan,
  runScanForPath,
  startWatcher,
  stopWatcher,
  isWatching,
  onChangesDetected,
  scheduleScan,
  getScanHistory,
  getLastScan,
  getConfig,
  saveConfig,
  getFIMReport
};
