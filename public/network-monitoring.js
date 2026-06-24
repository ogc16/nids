function trafficStatusClass(status) {
  if (status === 'allowed') return 'tag-active';
  if (status === 'blocked') return 'tag-critical';
  return 'tag-in-progress';
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function formatDuration(sec) {
  if (sec < 1) return (sec * 1000).toFixed(0) + 'ms';
  if (sec < 60) return sec.toFixed(1) + 's';
  return Math.floor(sec / 60) + 'm ' + Math.floor(sec % 60) + 's';
}

document.addEventListener('DOMContentLoaded', async () => {
  const protocolFilter = document.getElementById('protocolFilter');
  const statusFilter = document.getElementById('statusFilter');
  const appFilter = document.getElementById('appFilter');
  const searchInput = document.getElementById('searchInput');
  const wiresharkFilter = document.getElementById('wiresharkFilter');
  const filterStatus = document.getElementById('wiresharkFilterStatus');

  let chartInstances = {};
  let data = [];
  let refreshInterval;
  let wiresharkFilterActive = '';

  async function loadData() {
    try {
      const query = wiresharkFilterActive ? `?displayFilter=${encodeURIComponent(wiresharkFilterActive)}` : '';
      data = await apiFetch('/network-traffic' + query);
      const stats = await apiFetch('/network-traffic/stats');

      document.getElementById('totalFlows').textContent = stats.totalFlows;
      document.getElementById('suspiciousFlows').textContent = stats.suspiciousCount;
      document.getElementById('blockedFlows').textContent = stats.blockedCount;
      document.getElementById('totalData').textContent = formatBytes(stats.totalBytes);

      const protocols = [...new Set(data.map(t => t.protocol))].sort();
      protocolFilter.innerHTML = '<option value="">All Protocols</option>';
      protocols.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p;
        opt.textContent = p;
        protocolFilter.appendChild(opt);
      });

      const apps = [...new Set(data.map(t => t.application))].sort();
      appFilter.innerHTML = '<option value="">All Applications</option>';
      apps.forEach(a => {
        const opt = document.createElement('option');
        opt.value = a;
        opt.textContent = a;
        appFilter.appendChild(opt);
      });

      renderCharts();
      renderTable();
    } catch (err) {
      showToast('Failed to load network traffic data', 'error');
    }
  }

  function renderTable() {
    let filtered = [...data];
    const proto = protocolFilter.value;
    const stat = statusFilter.value;
    const app = appFilter.value;
    const search = searchInput.value.toLowerCase();

    if (proto) filtered = filtered.filter(t => t.protocol === proto);
    if (stat) filtered = filtered.filter(t => t.status === stat);
    if (app) filtered = filtered.filter(t => t.application === app);
    if (search) filtered = filtered.filter(t =>
      t.srcIp.toLowerCase().includes(search) ||
      t.destIp.toLowerCase().includes(search) ||
      t.protocol.toLowerCase().includes(search) ||
      (t.country && t.country.toLowerCase().includes(search))
    );

    const tbody = document.getElementById('trafficTableBody');
    tbody.innerHTML = filtered.map(item => `
      <tr class="${item.status === 'suspicious' ? 'row-suspicious' : item.status === 'blocked' ? 'row-blocked' : ''}">
        <td>${formatDate(item.timestamp)}</td>
        <td>${item.srcIp}:${item.srcPort}</td>
        <td>${item.destIp}:${item.destPort}</td>
        <td><span class="tag tag-${item.protocol.toLowerCase()}">${item.protocol}</span></td>
        <td>${formatBytes(item.bytes)}</td>
        <td>${formatDuration(item.duration)}</td>
        <td>${item.application}</td>
        <td>${item.country || '-'}</td>
        <td><span class="tag ${trafficStatusClass(item.status)}">${item.status}</span></td>
        <td><button class="btn btn-secondary btn-sm view-flow" data-id="${item.id}">Details</button></td>
      </tr>
    `).join('');

    tbody.querySelectorAll('.view-flow').forEach(btn => {
      btn.onclick = async (e) => {
        e.stopPropagation();
        const id = btn.dataset.id;
        try {
          const item = await apiFetch(`/network-traffic/${id}`);
          const ruleInfo = item.ruleId
            ? await apiFetch(`/detection-rules/${item.ruleId}`).then(r => r.name).catch(() => 'Unknown')
            : 'N/A';
          openModal(`Flow #${item.id}`, [
            { label: 'Timestamp', value: formatDate(item.timestamp) },
            { label: 'Source', value: `${item.srcIp}:${item.srcPort}` },
            { label: 'Destination', value: `${item.destIp}:${item.destPort}` },
            { label: 'Protocol', value: `<span class="tag tag-${item.protocol.toLowerCase()}">${item.protocol}</span>` },
            { label: 'Status', value: `<span class="tag ${trafficStatusClass(item.status)}">${item.status}</span>` },
            { label: 'Bytes', value: formatBytes(item.bytes) },
            { label: 'Packets', value: item.packets.toLocaleString() },
            { label: 'Duration', value: formatDuration(item.duration) },
            { label: 'Application', value: item.application },
            { label: 'Country', value: item.country || 'Unknown' },
            { label: 'Asset ID', value: item.assetId ? `#${item.assetId}` : 'N/A' },
            { label: 'Matched Rule', value: ruleInfo }
          ]);
        } catch (err) {
          showToast('Failed to load flow details', 'error');
        }
      };
    });
  }

  function renderCharts() {
    const protoData = {};
    const appData = {};
    data.forEach(t => {
      protoData[t.protocol] = (protoData[t.protocol] || 0) + t.bytes;
      appData[t.application] = (appData[t.application] || 0) + 1;
    });

    const protoLabels = Object.keys(protoData);
    const protoValues = Object.values(protoData);
    const colors = ['#58a6ff', '#3fb950', '#d29922', '#f85149', '#bc8cff', '#39d2c0', '#8b949e'];

    if (chartInstances.protocol) chartInstances.protocol.destroy();
    chartInstances.protocol = new Chart(document.getElementById('protocolChart'), {
      type: 'doughnut',
      data: {
        labels: protoLabels,
        datasets: [{
          data: protoValues,
          backgroundColor: colors.slice(0, protoLabels.length),
          borderColor: '#1c2333',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#8b949e' } }
        }
      }
    });

    if (chartInstances.app) chartInstances.app.destroy();
    chartInstances.app = new Chart(document.getElementById('appChart'), {
      type: 'bar',
      data: {
        labels: Object.keys(appData),
        datasets: [{
          label: 'Flows',
          data: Object.values(appData),
          backgroundColor: colors.slice(0, Object.keys(appData).length),
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(48,54,61,0.3)' } },
          y: { beginAtZero: true, ticks: { color: '#8b949e', stepSize: 1 }, grid: { color: 'rgba(48,54,61,0.3)' } }
        }
      }
    });
  }

  protocolFilter.onchange = renderTable;
  statusFilter.onchange = renderTable;
  appFilter.onchange = renderTable;
  searchInput.oninput = renderTable;
  wiresharkFilter.onkeydown = (e) => { if (e.key === 'Enter') applyWiresharkFilter(); };

  document.getElementById('applyWiresharkFilter').onclick = applyWiresharkFilter;
  document.getElementById('clearWiresharkFilter').onclick = () => {
    wiresharkFilter.value = '';
    wiresharkFilterActive = '';
    filterStatus.textContent = '';
    loadData();
  };

  document.getElementById('openInWiresharkBtn').onclick = () => {
    const filter = wiresharkFilter.value.trim();
    if (filter) {
      navigator.clipboard.writeText(filter).then(() => {
        showToast('Wireshark display filter copied to clipboard', 'success');
      }).catch(() => {
        showToast('Select the filter text and copy manually', 'error');
      });
    } else {
      const selectedProtocol = protocolFilter.value;
      const selectedStatus = statusFilter.value;
      let suggestion = '';
      if (selectedProtocol) suggestion = `ip.proto=="${selectedProtocol}"`;
      if (selectedStatus) suggestion += (suggestion ? ' && ' : '') + `frame.protocols contains "${selectedStatus}"`;
      if (!suggestion) suggestion = 'ip.src==10.0.0.1 || ip.dst==10.0.0.1';
      wiresharkFilter.value = suggestion;
      wiresharkFilterActive = suggestion;
      filterStatus.innerHTML = `<span class="tag tag-active">Built-in filter applied</span>`;
      loadData();
    }
  };

  document.getElementById('exportTrafficCsv').onclick = () => {
    const a = document.createElement('a');
    a.href = '/api/network-traffic/export';
    a.download = '';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

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

  await loadData();

  document.addEventListener('new-traffic-flow', (e) => {
    data.unshift(e.detail);
    const statsEl = document.getElementById('totalFlows');
    if (statsEl) statsEl.textContent = parseInt(statsEl.textContent) + 1;
    renderTable();
  });

  refreshInterval = setInterval(async () => {
    await loadData();
  }, 10000);

  window.addEventListener('beforeunload', () => {
    if (refreshInterval) clearInterval(refreshInterval);
  });
});
