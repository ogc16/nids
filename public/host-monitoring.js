let refreshInterval;
const REFRESH_MS = 10000;

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(2) + ' GB';
}

function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const parts = [];
  if (d > 0) parts.push(d + 'd');
  if (h > 0) parts.push(h + 'h');
  parts.push(m + 'm');
  return parts.join(' ');
}

document.addEventListener('DOMContentLoaded', async () => {
  document.querySelectorAll('.tab').forEach(tab => {
    tab.onclick = () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      document.querySelectorAll('.tab-content').forEach(tc => tc.style.display = 'none');
      document.getElementById(tab.dataset.tab + 'Tab').style.display = 'block';
    };
  });

  document.getElementById('refreshBtn').onclick = loadAll;
  document.getElementById('connSearch').oninput = renderConnections;
  document.getElementById('connStateFilter').onchange = renderConnections;
  document.getElementById('portSearch').oninput = renderPorts;
  document.getElementById('closeProcessModal').onclick = () => {
    document.getElementById('processModal').style.display = 'none';
  };
  document.getElementById('processModal').onclick = (e) => {
    if (e.target === e.currentTarget) document.getElementById('processModal').style.display = 'none';
  };

  document.getElementById('scanNetworkBtn').onclick = scanNetwork;
  document.getElementById('subnetInput').addEventListener('keydown', e => { if (e.key === 'Enter') scanNetwork(); });
  document.getElementById('refreshArpBtn').onclick = loadArpTable;
  document.getElementById('refreshRoutesBtn').onclick = loadRoutingTable;

  // Auto-detect subnet from ARP or interfaces
  try {
    const arp = await apiFetch('/monitor/arp');
    if (arp.length > 0) {
      const ips = arp.filter(a => /^\d+\.\d+\.\d+\.\d+$/.test(a.IPAddress) && !a.IPAddress.endsWith('.255') && !a.IPAddress.endsWith('.0'));
      if (ips.length > 0) {
        const parts = ips[0].IPAddress.split('.');
        parts[3] = '0';
        document.getElementById('subnetInput').value = parts.join('.');
      }
    }
    if (!document.getElementById('subnetInput').value) {
      const ifaces = await apiFetch('/monitor/interfaces');
      const extIface = ifaces.find(i => !i.internal && i.address && /^\d+\.\d+\.\d+\.\d+$/.test(i.address));
      if (extIface) {
        const parts = extIface.address.split('.');
        parts[3] = '0';
        document.getElementById('subnetInput').value = parts.join('.');
      }
    }
  } catch {}

  await loadAll();
  await loadArpTable();
  await loadRoutingTable();
  refreshInterval = setInterval(loadAll, REFRESH_MS);
  window.addEventListener('beforeunload', () => { if (refreshInterval) clearInterval(refreshInterval); });
});

let systemInfo = {};
let connections = [];
let openPorts = [];
let bandwidth = [];

async function loadAll() {
  document.getElementById('refreshTimer').textContent = 'Refreshing...';
  await Promise.all([loadSystem(), loadConnections(), loadPorts(), loadBandwidth()]);
  document.getElementById('refreshTimer').textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

async function loadSystem() {
  try {
    systemInfo = await apiFetch('/monitor/system');
    document.getElementById('hostName').textContent = systemInfo.hostname || '-';
    document.getElementById('hostOS').textContent = systemInfo.os || '';
    document.getElementById('uptime').textContent = systemInfo.uptime ? formatUptime(systemInfo.uptime) : '-';
    document.getElementById('cpuUsage').textContent = systemInfo.cpuUsage != null ? `${systemInfo.cpuUsage}%` : '-';
    document.getElementById('cpuModel').textContent = systemInfo.cpu ? systemInfo.cpu.slice(0, 50) + '...' : '';
    const totalMem = systemInfo.totalMemory || 0;
    const freeMem = systemInfo.freeMemory || 0;
    const usedMem = totalMem - freeMem;
    const memPct = totalMem > 0 ? ((usedMem / totalMem) * 100).toFixed(1) : 0;
    document.getElementById('memoryUsage').textContent = formatBytes(usedMem);
    document.getElementById('memoryDetail').textContent = `${memPct}% of ${formatBytes(totalMem)}`;
  } catch {}
}

let allConnections = [];

async function loadConnections() {
  try {
    allConnections = await apiFetch('/monitor/connections');
    connections = allConnections;
    renderConnections();
  } catch {}
}

function renderConnections() {
  const search = (document.getElementById('connSearch').value || '').toLowerCase();
  const stateFilter = document.getElementById('connStateFilter').value.toLowerCase();
  let filtered = connections;
  if (stateFilter) filtered = filtered.filter(c => (c.State || '').toLowerCase() === stateFilter);
  if (search) filtered = filtered.filter(c =>
    (c.LocalAddress || '').toLowerCase().includes(search) ||
    String(c.LocalPort || '').includes(search) ||
    (c.RemoteAddress || '').toLowerCase().includes(search) ||
    String(c.RemotePort || '').includes(search) ||
    (c.ProcessName || '').toLowerCase().includes(search)
  );

  const tbody = document.getElementById('connectionsBody');
  tbody.innerHTML = filtered.length === 0
    ? '<tr><td colspan="6">No connections found</td></tr>'
    : filtered.slice(0, 200).map(c => {
        const stateClass = {
          'Established': 'tag-active',
          'Listen': 'tag-in-progress',
          'Listening': 'tag-in-progress',
          'TimeWait': 'tag-deprecated',
          'CloseWait': 'tag-critical'
        }[c.State] || 'tag-deprecated';
        return `<tr>
          <td>${c.LocalPort ? 'TCP' : 'UDP'}</td>
          <td>${c.LocalAddress || '*'}:${c.LocalPort || '-'}</td>
          <td>${c.RemoteAddress || '*'}:${c.RemotePort || '-'}</td>
          <td><span class="tag ${stateClass}">${c.State || 'N/A'}</span></td>
          <td>${c.ProcessName || 'unknown'}</td>
          <td><a class="clickable view-process" data-pid="${c.OwningProcess}">${c.OwningProcess || '-'}</a></td>
        </tr>`;
      }).join('');

  tbody.querySelectorAll('.view-process').forEach(el => {
    el.onclick = async (e) => {
      e.stopPropagation();
      await showProcessDetail(el.dataset.pid);
    };
  });
}

async function loadPorts() {
  try {
    openPorts = await apiFetch('/monitor/ports');
    renderPorts();
  } catch {}
}

function renderPorts() {
  const search = (document.getElementById('portSearch').value || '').toLowerCase();
  let filtered = openPorts;
  if (search) filtered = filtered.filter(p =>
    String(p.LocalPort || '').includes(search) ||
    (p.ProcessName || '').toLowerCase().includes(search) ||
    (p.LocalAddress || '').toLowerCase().includes(search)
  );

  const tbody = document.getElementById('portsBody');
  tbody.innerHTML = filtered.length === 0
    ? '<tr><td colspan="7">No open ports found</td></tr>'
    : filtered.sort((a, b) => a.LocalPort - b.LocalPort).map(p => `<tr>
        <td><strong>${p.LocalPort}</strong></td>
        <td><span class="tag tag-${(p.Protocol || 'tcp').toLowerCase()}">${p.Protocol || 'TCP'}</span></td>
        <td>${p.LocalAddress || '*'}</td>
        <td>${p.ProcessName || 'unknown'}</td>
        <td><a class="clickable view-process" data-pid="${p.OwningProcess}">${p.OwningProcess || '-'}</a></td>
        <td style="font-size:11px;color:var(--text-secondary);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${p.ProcessPath || ''}</td>
        <td><button class="btn btn-secondary btn-sm kill-port" data-pid="${p.OwningProcess}" data-port="${p.LocalPort}" data-proto="${p.Protocol}">Kill</button></td>
      </tr>`).join('');

  tbody.querySelectorAll('.view-process').forEach(el => {
    el.onclick = async (e) => {
      e.stopPropagation();
      await showProcessDetail(el.dataset.pid);
    };
  });

  tbody.querySelectorAll('.kill-port').forEach(el => {
    el.onclick = async (e) => {
      e.stopPropagation();
      const pid = el.dataset.pid;
      const port = el.dataset.port;
      if (!confirm(`Kill process ${pid} (port ${port})?`)) return;
      try {
        await apiFetch(`/monitor/process/${pid}`, { method: 'DELETE' });
        showToast(`Process ${pid} terminated`, 'success');
        await loadPorts();
      } catch (err) {
        showToast(`Failed: ${err.message}`, 'error');
      }
    };
  });
}

async function loadBandwidth() {
  try {
    bandwidth = await apiFetch('/monitor/bandwidth');
    const interfaces = await apiFetch('/monitor/interfaces');
    renderBandwidth(interfaces);
  } catch {}
}

function renderBandwidth(interfaces) {
  const cards = document.getElementById('interfaceCards');
  cards.innerHTML = interfaces.map(iface => `
    <div class="stat-card stat-info">
      <div class="stat-label">${iface.name}</div>
      <div class="stat-value" style="font-size:16px">${iface.address || '-'}</div>
      <div class="stat-sub">${iface.internal ? 'Internal' : 'External'} &middot; ${iface.mac || ''}</div>
    </div>
  `).join('');

  const tbody = document.getElementById('bandwidthBody');
  tbody.innerHTML = bandwidth.length === 0
    ? '<tr><td colspan="4">No bandwidth data available</td></tr>'
    : bandwidth.map(b => `<tr>
        <td>${b.name}</td>
        <td>${b.speed || '-'}</td>
        <td>${formatBytes(b.receivedBytes || 0)}</td>
        <td>${formatBytes(b.sentBytes || 0)}</td>
      </tr>`).join('');
}

async function loadArpTable() {
  try {
    const arp = await apiFetch('/monitor/arp');
    const tbody = document.getElementById('arpTableBody');
    tbody.innerHTML = arp.length === 0
      ? '<tr><td colspan="3">No ARP entries found</td></tr>'
      : arp.map(a => `<tr><td>${a.IPAddress}</td><td style="font-family:monospace">${a.LinkLayerAddress}</td><td><span class="tag tag-${a.State === 'Permanent' ? 'active' : a.State === 'Stale' ? 'deprecated' : 'in-progress'}">${a.State}</span></td></tr>`).join('');
  } catch {}
}

async function loadRoutingTable() {
  try {
    const routes = await apiFetch('/monitor/routing-table');
    const tbody = document.getElementById('routesTableBody');
    tbody.innerHTML = routes.length === 0
      ? '<tr><td colspan="4">No routes found</td></tr>'
      : routes.map(r => `<tr><td style="font-family:monospace">${r.DestinationPrefix}</td><td style="font-family:monospace">${r.NextHop || '-'}</td><td>${r.InterfaceAlias || ''}</td><td>${r.RouteMetric || '-'}</td></tr>`).join('');
  } catch {}
}

async function scanNetwork() {
  const subnet = document.getElementById('subnetInput').value.trim();
  if (!subnet) return showToast('Enter a subnet (e.g. 192.168.1.0)', 'error');
  const btn = document.getElementById('scanNetworkBtn');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  const tbody = document.getElementById('scanResults');
  tbody.innerHTML = '<tr><td colspan="4"><div class="loading-text">Scanning network (this may take a minute)...</div></td></tr>';
  try {
    const devices = await apiFetch('/monitor/scan', {
      method: 'POST',
      body: JSON.stringify({ subnet })
    });
    tbody.innerHTML = devices.length === 0
      ? '<tr><td colspan="4">No devices found on this subnet</td></tr>'
      : devices.map(d => `<tr>
          <td style="font-family:monospace">${d.ip}</td>
          <td>${d.hostname || '-'}</td>
          <td style="font-family:monospace">${d.mac || '-'}</td>
          <td><span class="tag tag-active">Online</span></td>
        </tr>`).join('');
    showToast(`Found ${devices.length} device(s) on ${subnet}`, 'success');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4">Error: ${err.message}</td></tr>`;
  }
  btn.disabled = false;
  btn.textContent = 'Scan Network';
}

async function showProcessDetail(pid) {
  const modal = document.getElementById('processModal');
  modal.style.display = 'flex';
  document.getElementById('processDetailBody').innerHTML = '<div class="loading-text">Loading...</div>';
  try {
    const p = await apiFetch(`/monitor/process/${pid}`);
    if (!p || p.error) {
      document.getElementById('processDetailBody').innerHTML = `<div class="empty-state"><h3>Process #${pid}</h3><p>${p?.error || 'Not found'}</p></div>`;
      return;
    }
    document.getElementById('processDetailBody').innerHTML = `
      <div class="detail-row"><div class="detail-label">PID</div><div class="detail-value">${p.Id}</div></div>
      <div class="detail-row"><div class="detail-label">Name</div><div class="detail-value">${p.ProcessName}</div></div>
      <div class="detail-row"><div class="detail-label">Path</div><div class="detail-value" style="font-size:11px;word-break:break-all">${p.Path || '-'}</div></div>
      <div class="detail-row"><div class="detail-label">Command</div><div class="detail-value" style="font-size:11px;word-break:break-all">${p.CommandLine || '-'}</div></div>
      <div class="detail-row"><div class="detail-label">User</div><div class="detail-value">${p.User || '-'}</div></div>
      <div class="detail-row"><div class="detail-label">Memory</div><div class="detail-value">${formatBytes(p.WorkingSet)} (Virtual: ${formatBytes(p.VirtualSize)})</div></div>
      <div class="detail-row"><div class="detail-label">Threads</div><div class="detail-value">${p.Threads}</div></div>
      <div class="detail-row"><div class="detail-label">Handles</div><div class="detail-value">${p.Handles}</div></div>
      <div class="detail-row"><div class="detail-label">CPU Time</div><div class="detail-value">${p.CPU != null ? p.CPU.toFixed(2) + 's' : '-'}</div></div>
      <div class="detail-row"><div class="detail-label">Started</div><div class="detail-value">${p.StartTime ? new Date(p.StartTime).toLocaleString() : '-'}</div></div>
      <div class="detail-row"><div class="detail-label">Responding</div><div class="detail-value">${p.Responding ? 'Yes' : 'No'}</div></div>
    `;
  } catch (err) {
    document.getElementById('processDetailBody').innerHTML = `<div class="empty-state"><h3>Error</h3><p>${err.message}</p></div>`;
  }
}
