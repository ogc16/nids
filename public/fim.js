const FIM_API = '/api/fim';

async function loadBaseline() {
  try {
    const data = await apiFetch(`${FIM_API}/baseline`);
    const tbody = document.getElementById('baselineTableBody');
    const stats = document.getElementById('fimStats');

    if (!data || (Array.isArray(data) && data.length === 0)) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-secondary);padding:24px">No baseline entries yet</td></tr>';
      document.getElementById('filesMonitored').textContent = '0';
      return;
    }

    const items = Array.isArray(data) ? data : data.items || data.entries || [];
    tbody.innerHTML = items.map(item => {
      const path = item.path || item.file_path || item.file || '-';
      const hash = item.hash || item.file_hash || '-';
      const hashPreview = hash !== '-' ? hash.substring(0, 16) + '...' : '-';
      const size = item.size || item.file_size || 0;
      const sizeStr = size ? formatSize(size) : '-';
      const modified = formatDate(item.last_modified || item.modified || item.mtime);
      return `<tr>
        <td style="font-family:Consolas,monospace;font-size:12px">${escapeHtml(path)}</td>
        <td style="font-family:Consolas,monospace;font-size:12px;color:var(--text-secondary)">${escapeHtml(hashPreview)}</td>
        <td>${sizeStr}</td>
        <td>${modified}</td>
      </tr>`;
    }).join('');

    document.getElementById('filesMonitored').textContent = items.length;
  } catch (err) {
    showToast('Failed to load baseline: ' + err.message, 'error');
  }
}

async function loadLastScan() {
  try {
    const data = await apiFetch(`${FIM_API}/last-scan`);
    if (data && data.timestamp) {
      document.getElementById('lastScanTime').textContent = formatDate(data.timestamp);
      document.getElementById('lastScanSub').textContent = `Files: ${data.files_scanned || data.files || 0}, Changes: ${data.changes_found || data.changes || 0}`;
    }
  } catch {
    // no scan yet
  }
}

async function loadScanHistory() {
  try {
    const data = await apiFetch(`${FIM_API}/scans`);
    const tbody = document.getElementById('scanHistoryBody');

    if (!data || (Array.isArray(data) && data.length === 0)) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-secondary);padding:24px">No scan history available</td></tr>';
      return;
    }

    const items = Array.isArray(data) ? data : data.items || data.scans || [];
    tbody.innerHTML = items.map(s => `<tr>
      <td style="font-family:Consolas,monospace;font-size:12px;color:var(--text-secondary)">${escapeHtml(s.id || s.scan_id || '-')}</td>
      <td>${formatDate(s.timestamp || s.scan_time || s.time)}</td>
      <td>${s.files_scanned || s.files || 0}</td>
      <td>${s.changes_found || s.changes || 0}</td>
      <td style="color:var(--accent-green)">+${s.added || 0}</td>
      <td style="color:var(--accent-orange)">${s.modified || 0}</td>
      <td style="color:var(--accent-red)">${s.deleted || 0}</td>
    </tr>`).join('');

    const totalChanges = items.reduce((sum, s) => sum + (s.changes_found || s.changes || 0), 0);
    const criticalChanges = items.reduce((sum, s) => sum + (s.modified || 0) + (s.deleted || 0), 0);
    document.getElementById('totalChanges').textContent = totalChanges;
    document.getElementById('criticalChanges').textContent = criticalChanges;
  } catch {
    // no history
  }
}

async function loadScanResults() {
  try {
    const data = await apiFetch(`${FIM_API}/report`);
    const tbody = document.getElementById('scanResultsBody');

    if (!data || (Array.isArray(data) && data.length === 0)) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary);padding:24px">No scan results yet — run a scan to detect changes</td></tr>';
      return;
    }

    const items = Array.isArray(data) ? data : data.items || data.results || data.changes || [];
    if (items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--accent-green);padding:24px">No changes detected — all files match baseline</td></tr>';
      return;
    }

    tbody.innerHTML = items.map(item => {
      const changeType = (item.change_type || item.type || 'modified').toLowerCase();
      const badgeClass = changeType === 'added' ? 'tag tag-new' : changeType === 'deleted' ? 'tag-critical' : 'tag tag-high';
      return `<tr>
        <td style="font-family:Consolas,monospace;font-size:12px">${escapeHtml(item.path || item.file || '-')}</td>
        <td><span class="${badgeClass}">${changeType}</span></td>
        <td style="font-family:Consolas,monospace;font-size:12px;color:var(--text-secondary)">${item.previous_hash ? item.previous_hash.substring(0, 16) + '...' : '-'}</td>
        <td style="font-family:Consolas,monospace;font-size:12px;color:var(--text-secondary)">${item.current_hash ? item.current_hash.substring(0, 16) + '...' : '-'}</td>
        <td>${formatDate(item.timestamp || item.time || item.detected_at)}</td>
      </tr>`;
    }).join('');
  } catch (err) {
    const tbody = document.getElementById('scanResultsBody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary);padding:24px">No scan results available</td></tr>';
  }
}

async function loadWatcherStatus() {
  try {
    const data = await apiFetch(`${FIM_API}/watch/status`);
    if (data) {
      const running = data.running || data.active || data.status === 'running';
      updateWatcherUI(running);
      if (data.interval) {
        document.getElementById('watchInterval').value = data.interval;
      }
    }
  } catch {
    // watcher not available
  }
}

function updateWatcherUI(running) {
  const statusEl = document.getElementById('watcherStatus');
  const startBtn = document.getElementById('watchStartBtn');
  const stopBtn = document.getElementById('watchStopBtn');

  if (running) {
    statusEl.textContent = 'Running';
    statusEl.className = 'tag tag-online';
    startBtn.disabled = true;
    stopBtn.disabled = false;
  } else {
    statusEl.textContent = 'Stopped';
    statusEl.className = 'tag tag-offline';
    startBtn.disabled = false;
    stopBtn.disabled = true;
  }
}

async function createBaseline() {
  const input = document.getElementById('baselinePaths');
  const paths = input.value.trim();
  if (!paths) {
    showToast('Please enter at least one file or directory path', 'error');
    return;
  }

  const btn = event.target;
  btn.disabled = true;
  showLoading('Creating baseline...');

  try {
    await apiFetch(`${FIM_API}/baseline`, {
      method: 'POST',
      body: JSON.stringify({ paths: paths.split(',').map(p => p.trim()).filter(p => p) })
    });
    showToast('Baseline created successfully');
    input.value = '';
    await Promise.all([loadBaseline(), loadLastScan()]);
  } catch (err) {
    showToast('Failed to create baseline: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    hideLoading();
  }
}

async function addToBaseline() {
  const input = document.getElementById('singleFilePath');
  const path = input.value.trim();
  if (!path) {
    showToast('Please enter a file path', 'error');
    return;
  }

  const btn = event.target;
  btn.disabled = true;

  try {
    await apiFetch(`${FIM_API}/baseline/add`, {
      method: 'POST',
      body: JSON.stringify({ path })
    });
    showToast('File added to baseline');
    input.value = '';
    await loadBaseline();
  } catch (err) {
    showToast('Failed to add file: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

async function clearBaseline() {
  if (!confirm('Are you sure you want to clear the entire baseline?')) return;

  showLoading('Clearing baseline...');
  try {
    await apiFetch(`${FIM_API}/baseline`, { method: 'DELETE' });
    showToast('Baseline cleared');
    await Promise.all([loadBaseline(), loadScanResults(), loadScanHistory()]);
  } catch (err) {
    showToast('Failed to clear baseline: ' + err.message, 'error');
  } finally {
    hideLoading();
  }
}

async function runScan() {
  const btn = document.querySelector('.btn-primary[onclick="runScan()"]');
  if (btn) btn.disabled = true;
  showLoading('Running integrity scan...');

  try {
    const result = await apiFetch(`${FIM_API}/scan`, { method: 'POST' });
    showToast('Scan completed: ' + (result.changes_found || result.changes || 0) + ' changes found');
    await Promise.all([loadScanResults(), loadScanHistory(), loadLastScan()]);
  } catch (err) {
    showToast('Scan failed: ' + err.message, 'error');
  } finally {
    if (btn) btn.disabled = false;
    hideLoading();
  }
}

async function startWatcher() {
  const interval = parseInt(document.getElementById('watchInterval').value, 10) || 60;
  const btn = document.getElementById('watchStartBtn');
  btn.disabled = true;
  showLoading('Starting watcher...');

  try {
    await apiFetch(`${FIM_API}/watch/start`, {
      method: 'POST',
      body: JSON.stringify({ interval })
    });
    showToast('Watcher started');
    updateWatcherUI(true);
  } catch (err) {
    showToast('Failed to start watcher: ' + err.message, 'error');
    btn.disabled = false;
  } finally {
    hideLoading();
  }
}

async function stopWatcher() {
  const btn = document.getElementById('watchStopBtn');
  btn.disabled = true;
  showLoading('Stopping watcher...');

  try {
    await apiFetch(`${FIM_API}/watch/stop`, { method: 'POST' });
    showToast('Watcher stopped');
    updateWatcherUI(false);
  } catch (err) {
    showToast('Failed to stop watcher: ' + err.message, 'error');
    btn.disabled = false;
  } finally {
    hideLoading();
  }
}

function formatSize(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

document.addEventListener('DOMContentLoaded', () => {
  Promise.all([loadBaseline(), loadLastScan(), loadScanHistory(), loadScanResults(), loadWatcherStatus()]);
});
