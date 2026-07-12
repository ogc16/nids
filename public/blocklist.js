let blEntries = [];
let blFilter = 'all';
let blRefreshTimer;

function blTagClass(tag) {
  const t = tag.toLowerCase().replace(/\s+/g, '-');
  if (['tor', 'c2', 'malware', 'web-exploit', 'sqli', 'path-traversal'].includes(t)) return 'tor';
  if (['brute-force', 'multi-service'].includes(t)) return 'brute-force';
  if (['recon', 'port-scan'].includes(t)) return 'recon';
  return '';
}

function blFormatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

document.addEventListener('DOMContentLoaded', async () => {
  const ipInput = document.getElementById('blIpInput');
  const reasonInput = document.getElementById('blReasonInput');
  const severityInput = document.getElementById('blSeverityInput');
  const tagsInput = document.getElementById('blTagsInput');
  const addBtn = document.getElementById('blAddBtn');
  const refreshBtn = document.getElementById('blRefreshBtn');
  const exportBtn = document.getElementById('blExportCsv');
  const tabs = document.getElementById('blTabs');
  const tableBody = document.getElementById('blTableBody');
  const emptyEl = document.getElementById('blEmpty');
  const statsEl = document.getElementById('blStats');

  async function loadStats() {
    try {
      const s = await apiFetch('/blocklist/stats');
      statsEl.innerHTML = `
        <div class="bl-stat"><div class="bl-stat-value">${s.total}</div><div class="bl-stat-label">Total Entries</div></div>
        <div class="bl-stat blocked"><div class="bl-stat-value">${s.blocked}</div><div class="bl-stat-label">Blocked</div></div>
        <div class="bl-stat high"><div class="bl-stat-value">${s.flagged}</div><div class="bl-stat-label">Flagged Only</div></div>
        <div class="bl-stat critical"><div class="bl-stat-value">${s.totalHits}</div><div class="bl-stat-label">Total Hits</div></div>
        <div class="bl-stat critical"><div class="bl-stat-value">${s.bySeverity.critical || 0}</div><div class="bl-stat-label">Critical</div></div>
        <div class="bl-stat medium"><div class="bl-stat-value">${s.bySeverity.high || 0}</div><div class="bl-stat-label">High</div></div>
      `;
    } catch {}
  }

  async function loadEntries() {
    try {
      blEntries = await apiFetch('/blocklist');
      renderTable();
      await loadStats();
    } catch (err) {
      showToast('Failed to load blocklist', 'error');
    }
  }

  function renderTable() {
    let filtered = [...blEntries];
    if (blFilter === 'blocked') filtered = filtered.filter(e => e.blocked);
    if (blFilter === 'flagged') filtered = filtered.filter(e => !e.blocked);

    if (filtered.length === 0) {
      tableBody.innerHTML = '';
      emptyEl.style.display = 'block';
      return;
    }
    emptyEl.style.display = 'none';

    tableBody.innerHTML = filtered.map(e => `
      <tr>
        <td><span class="bl-status-dot ${e.blocked ? 'blocked' : 'flagged'}"></span>${e.blocked ? 'Blocked' : 'Flagged'}</td>
        <td class="bl-ip-cell">${e.ip}</td>
        <td><span class="bl-severity-badge ${e.severity}">${e.severity}</span></td>
        <td><div class="bl-reason-text" title="${e.reason}">${e.reason}</div></td>
        <td><div class="bl-tags">${(e.tags || []).map(t => `<span class="bl-tag ${blTagClass(t)}">${t}</span>`).join('')}</div></td>
        <td><span class="bl-hits">${(e.hits || 0).toLocaleString()}</span></td>
        <td>${blFormatTime(e.flaggedAt)}</td>
        <td>
          <div class="bl-actions">
            ${e.blocked
              ? `<button class="btn btn-secondary btn-sm bl-unblock-btn" data-ip="${e.ip}">Unblock</button>`
              : `<button class="btn btn-primary btn-sm bl-block-btn" data-ip="${e.ip}">Block</button>`}
            <button class="btn btn-secondary btn-sm bl-edit-btn" data-ip="${e.ip}">Edit</button>
            <button class="btn btn-secondary btn-sm bl-remove-btn" data-ip="${e.ip}" style="color:var(--accent-red)">Remove</button>
          </div>
        </td>
      </tr>
    `).join('');

    tableBody.querySelectorAll('.bl-block-btn').forEach(btn => {
      btn.onclick = async () => {
        try {
          await apiFetch(`/blocklist/${btn.dataset.ip}/block`, { method: 'POST' });
          showToast(`${btn.dataset.ip} blocked`, 'success');
          await loadEntries();
        } catch (err) { showToast(err.message, 'error'); }
      };
    });

    tableBody.querySelectorAll('.bl-unblock-btn').forEach(btn => {
      btn.onclick = async () => {
        try {
          await apiFetch(`/blocklist/${btn.dataset.ip}/unblock`, { method: 'POST' });
          showToast(`${btn.dataset.ip} unblocked`, 'success');
          await loadEntries();
        } catch (err) { showToast(err.message, 'error'); }
      };
    });

    tableBody.querySelectorAll('.bl-edit-btn').forEach(btn => {
      btn.onclick = () => {
        const entry = blEntries.find(e => e.ip === btn.dataset.ip);
        if (!entry) return;
        openEditModal(entry);
      };
    });

    tableBody.querySelectorAll('.bl-remove-btn').forEach(btn => {
      btn.onclick = async () => {
        if (!confirm(`Remove ${btn.dataset.ip} from blocklist?`)) return;
        try {
          await apiFetch(`/blocklist/${btn.dataset.ip}`, { method: 'DELETE' });
          showToast(`${btn.dataset.ip} removed`, 'success');
          await loadEntries();
        } catch (err) { showToast(err.message, 'error'); }
      };
    });
  }

  function openEditModal(entry) {
    const modal = document.getElementById('blFlagModal');
    modal.style.display = 'flex';
    document.getElementById('blModalTitle').textContent = `Edit ${entry.ip}`;
    document.getElementById('blModalIp').textContent = entry.ip;
    document.getElementById('blModalReason').value = entry.reason || '';
    document.getElementById('blModalSeverity').value = entry.severity || 'medium';
    document.getElementById('blModalTags').value = (entry.tags || []).join(', ');

    document.getElementById('blModalSaveBtn').onclick = async () => {
      const reason = document.getElementById('blModalReason').value.trim();
      const severity = document.getElementById('blModalSeverity').value;
      const tags = document.getElementById('blModalTags').value.split(',').map(t => t.trim()).filter(Boolean);
      try {
        await apiFetch(`/blocklist/${entry.ip}`, { method: 'PATCH', body: JSON.stringify({ reason, severity, tags }) });
        modal.style.display = 'none';
        showToast('Entry updated', 'success');
        await loadEntries();
      } catch (err) { showToast(err.message, 'error'); }
    };
  }

  addBtn.onclick = async () => {
    const ip = ipInput.value.trim();
    if (!ip) { showToast('Enter an IP address', 'error'); return; }
    const reason = reasonInput.value.trim() || 'Flagged by analyst';
    const severity = severityInput.value;
    const tags = tagsInput.value.split(',').map(t => t.trim()).filter(Boolean);
    try {
      await apiFetch('/blocklist', { method: 'POST', body: JSON.stringify({ ip, reason, severity, tags }) });
      ipInput.value = '';
      reasonInput.value = '';
      tagsInput.value = '';
      showToast(`${ip} flagged`, 'success');
      await loadEntries();
    } catch (err) { showToast(err.message, 'error'); }
  };

  refreshBtn.onclick = loadEntries;

  exportBtn.onclick = () => {
    const csv = ['IP,Status,Severity,Reason,Tags,Hits,Flagged At,Blocked At']
      .concat(blEntries.map(e =>
        `${e.ip},${e.blocked ? 'Blocked' : 'Flagged'},${e.severity},"${(e.reason || '').replace(/"/g, '""')}",${(e.tags || []).join(';')},${e.hits || 0},${e.flaggedAt || ''},${e.blockedAt || ''}`
      )).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'blocklist.csv'; a.click();
    URL.revokeObjectURL(url);
  };

  tabs.querySelectorAll('.tab').forEach(tab => {
    tab.onclick = () => {
      tabs.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      blFilter = tab.dataset.filter;
      renderTable();
    };
  });

  await loadEntries();
  blRefreshTimer = setInterval(loadEntries, 15000);

  window.addEventListener('beforeunload', () => {
    if (blRefreshTimer) clearInterval(blRefreshTimer);
  });
});
