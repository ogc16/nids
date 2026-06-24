function httpStatusClass(code) {
  if (!code) return 'tag-default';
  if (code < 300) return 'tag-active';
  if (code < 400) return 'tag-in-progress';
  if (code < 500) return 'tag-critical';
  return 'tag-critical';
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function formatDuration(sec) {
  if (sec == null) return '-';
  if (sec < 1) return (sec * 1000).toFixed(0) + 'ms';
  if (sec < 60) return sec.toFixed(1) + 's';
  return Math.floor(sec / 60) + 'm ' + Math.floor(sec % 60) + 's';
}

document.addEventListener('DOMContentLoaded', async () => {
  const methodFilter = document.getElementById('methodFilter');
  const statusGroupFilter = document.getElementById('statusGroupFilter');
  const searchFilter = document.getElementById('searchFilter');
  const wiresharkFilter = document.getElementById('wiresharkFilter');
  const filterStatus = document.getElementById('wiresharkFilterStatus');
  const tbody = document.getElementById('webTrafficTableBody');
  const prevBtn = document.getElementById('prevPageBtn');
  const nextBtn = document.getElementById('nextPageBtn');
  const paginationInfo = document.getElementById('paginationInfo');

  let chartInstances = {};
  let currentPage = 1;
  let totalPages = 1;
  let wiresharkFilterActive = '';

  async function loadSummary() {
    try {
      const summary = await apiFetch('/web-traffic/summary');
      document.getElementById('totalRequests').textContent = summary.totalRequests.toLocaleString();
      document.getElementById('uniqueMethods').textContent = summary.methodDistribution.length;
      document.getElementById('errorRate').textContent = summary.errorRate + '%';
      document.getElementById('uniqueUris').textContent = summary.uniqueUris;

      const methods = summary.methodDistribution.sort((a, b) => b.count - a.count);
      const colors = ['#58a6ff', '#3fb950', '#d29922', '#f85149', '#bc8cff', '#39d2c0', '#8b949e'];
      if (chartInstances.methods) chartInstances.methods.destroy();
      chartInstances.methods = new Chart(document.getElementById('methodChart'), {
        type: 'doughnut',
        data: {
          labels: methods.map(m => m.method),
          datasets: [{
            data: methods.map(m => m.count),
            backgroundColor: colors.slice(0, methods.length),
            borderColor: '#1c2333',
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          plugins: {
            title: { display: true, text: 'HTTP Methods', color: '#8b949e' },
            legend: { position: 'bottom', labels: { color: '#8b949e' } }
          }
        }
      });

      const statusGroups = summary.statusCodeGroups;
      const statusLabels = ['2xx', '3xx', '4xx', '5xx'];
      const statusValues = statusLabels.map(l => statusGroups[l] || 0);
      const statusColors = ['#3fb950', '#d29922', '#f85149', '#bc8cff'];
      if (chartInstances.status) chartInstances.status.destroy();
      chartInstances.status = new Chart(document.getElementById('statusChart'), {
        type: 'bar',
        data: {
          labels: statusLabels,
          datasets: [{
            label: 'Responses',
            data: statusValues,
            backgroundColor: statusColors,
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          plugins: {
            title: { display: true, text: 'Status Code Groups', color: '#8b949e' },
            legend: { display: false }
          },
          scales: {
            x: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(48,54,61,0.3)' } },
            y: { beginAtZero: true, ticks: { color: '#8b949e', stepSize: 1 }, grid: { color: 'rgba(48,54,61,0.3)' } }
          }
        }
      });

      const topUrisEl = document.getElementById('topUrisList');
      topUrisEl.innerHTML = '<div style="display:grid;gap:4px">' + summary.topUris.map(u =>
        `<div style="display:flex;justify-content:space-between;padding:4px 8px;background:var(--bg-secondary);border-radius:4px;font-size:12px">
          <span style="color:var(--text-primary);font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:280px">${u.uri}</span>
          <span style="color:var(--text-secondary);margin-left:12px;white-space:nowrap">${u.count}</span>
        </div>`
      ).join('') + '</div>';

      const topHostsEl = document.getElementById('topHostsList');
      topHostsEl.innerHTML = '<div style="display:grid;gap:4px">' + summary.topHosts.map(h =>
        `<div style="display:flex;justify-content:space-between;padding:4px 8px;background:var(--bg-secondary);border-radius:4px;font-size:12px">
          <span style="color:var(--text-primary);font-family:monospace">${h.host}</span>
          <span style="color:var(--text-secondary)">${h.count}</span>
        </div>`
      ).join('') + '</div>';

      const methodSet = new Set();
      methods.forEach(m => methodSet.add(m.method));
      methodFilter.innerHTML = '<option value="">All Methods</option>';
      [...methodSet].sort().forEach(m => {
        const opt = document.createElement('option');
        opt.value = m;
        opt.textContent = m;
        methodFilter.appendChild(opt);
      });
    } catch (err) {
      showToast('Failed to load web traffic summary', 'error');
    }
  }

  async function loadRequests(page) {
    try {
      const params = new URLSearchParams();
      if (wiresharkFilterActive) params.set('displayFilter', wiresharkFilterActive);
      if (methodFilter.value) params.set('method', methodFilter.value);
      if (statusGroupFilter.value) params.set('status', statusGroupFilter.value);
      if (searchFilter.value) params.set('search', searchFilter.value);
      params.set('page', page);
      params.set('limit', '50');

      const result = await apiFetch('/web-traffic/requests?' + params.toString());
      const items = Array.isArray(result) ? result : (result.items || []);
      const pagination = result.pagination || {};
      currentPage = pagination.page || page;
      totalPages = pagination.totalPages || 1;

      tbody.innerHTML = items.map(item => `
        <tr class="${item.httpStatus && item.httpStatus >= 400 ? 'row-blocked' : ''}">
          <td style="white-space:nowrap">${item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : '-'}</td>
          <td><span class="tag tag-${(item.httpMethod || '').toLowerCase()}">${item.httpMethod || '-'}</span></td>
          <td style="font-family:monospace;font-size:12px;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${item.httpUri || ''}">${item.httpUri || '-'}</td>
          <td><span class="tag ${httpStatusClass(item.httpStatus)}">${item.httpStatus || '-'}</span></td>
          <td style="font-family:monospace;font-size:12px">${item.httpHost || '-'}</td>
          <td>${formatBytes(item.bytes)}</td>
          <td>${formatDuration(item.duration)}</td>
          <td style="font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${item.httpUserAgent || ''}">${item.httpUserAgent ? item.httpUserAgent.split('/').slice(0,2).join('/') : '-'}</td>
        </tr>
      `).join('');

      paginationInfo.textContent = `Page ${currentPage} of ${totalPages} (${pagination.total || items.length} records)`;
      prevBtn.disabled = currentPage <= 1;
      nextBtn.disabled = currentPage >= totalPages;
    } catch (err) {
      showToast('Failed to load web requests', 'error');
    }
  }

  function loadData() {
    loadSummary();
    loadRequests(1);
  }

  methodFilter.onchange = () => loadRequests(1);
  statusGroupFilter.onchange = () => loadRequests(1);
  searchFilter.oninput = () => loadRequests(1);
  wiresharkFilter.onkeydown = (e) => { if (e.key === 'Enter') applyWiresharkFilter(); };

  document.getElementById('applyWiresharkFilter').onclick = applyWiresharkFilter;
  document.getElementById('clearWiresharkFilter').onclick = () => {
    wiresharkFilter.value = '';
    wiresharkFilterActive = '';
    filterStatus.textContent = '';
    loadData();
  };

  prevBtn.onclick = () => { if (currentPage > 1) loadRequests(currentPage - 1); };
  nextBtn.onclick = () => { if (currentPage < totalPages) loadRequests(currentPage + 1); };

  function applyWiresharkFilter() {
    const filter = wiresharkFilter.value.trim();
    if (!filter) {
      wiresharkFilterActive = '';
      filterStatus.textContent = '';
      loadData();
      return;
    }
    wiresharkFilterActive = filter;
    filterStatus.innerHTML = `<span class="tag tag-in-progress">Filter applied</span>`;
    loadData();
  }

  document.getElementById('openInWiresharkBtn').onclick = () => {
    const filter = wiresharkFilter.value.trim();
    if (filter) {
      navigator.clipboard.writeText(filter).then(() => {
        showToast('Wireshark display filter copied to clipboard', 'success');
      }).catch(() => {
        showToast('Select the filter text and copy manually', 'error');
      });
    } else {
      const method = methodFilter.value;
      const status = statusGroupFilter.value;
      let suggestion = '';
      if (method) suggestion = `http.method=="${method}"`;
      if (status) suggestion += (suggestion ? ' && ' : '') + `http.status >= ${status}00 && http.status < ${parseInt(status)+1}00`;
      if (!suggestion) suggestion = 'http.request.method || http.response.code';
      wiresharkFilter.value = suggestion;
      wiresharkFilterActive = suggestion;
      filterStatus.innerHTML = `<span class="tag tag-active">Built-in filter applied</span>`;
      loadData();
    }
  };

  document.getElementById('exportWebTrafficCsv').onclick = () => {
    const a = document.createElement('a');
    a.href = '/api/web-traffic/export';
    a.download = '';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  await loadData();
});
