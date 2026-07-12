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

function signalBars(dbm) {
  const level = dbm > -50 ? 5 : dbm > -60 ? 4 : dbm > -70 ? 3 : dbm > -80 ? 2 : 1;
  let html = '<span class="signal-bar s' + level + '">';
  for (let i = 1; i <= 5; i++) {
    const h = 6 + i * 3;
    html += `<span style="height:${h}px" class="${i <= level ? 'active' : ''}"></span>`;
  }
  return html + '</span> ' + dbm + ' dBm';
}

function securityTag(sec) {
  if (sec.includes('WPA3')) return `<span class="tag tag-active">${sec}</span>`;
  if (sec.includes('Enterprise')) return `<span class="tag tag-development">${sec}</span>`;
  if (sec === 'Open') return `<span class="tag tag-critical">${sec}</span>`;
  if (sec === 'WEP') return `<span class="tag tag-high">${sec}</span>`;
  return `<span class="tag tag-medium">${sec}</span>`;
}

function severityTag(sev) {
  const cls = { critical: 'tag-critical', high: 'tag-high', medium: 'tag-medium', low: 'tag-low' };
  return `<span class="tag ${cls[sev] || 'tag-medium'}">${sev}</span>`;
}

let reportData = null;
let chartInstances = {};

document.addEventListener('DOMContentLoaded', async () => {
  document.querySelectorAll('.tab').forEach(tab => {
    tab.onclick = () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      document.querySelectorAll('.tab-content').forEach(tc => tc.style.display = 'none');
      document.getElementById(tab.dataset.tab + 'Tab').style.display = 'block';
    };
  });

  document.getElementById('wlanRefreshBtn').onclick = loadReport;
  document.getElementById('exportWlanCsv').onclick = exportCsv;
  document.getElementById('apBandFilter').onchange = renderAPs;
  document.getElementById('apStatusFilter').onchange = renderAPs;
  document.getElementById('apSearch').oninput = renderAPs;
  document.getElementById('clientBandFilter').onchange = renderClients;
  document.getElementById('clientStatusFilter').onchange = renderClients;
  document.getElementById('clientSearch').oninput = renderClients;
  document.getElementById('channelBandFilter').onchange = renderChannels;
  document.getElementById('anomalySeverityFilter').onchange = renderAnomalies;
  document.getElementById('anomalyStatusFilter').onchange = renderAnomalies;
  document.getElementById('anomalySearch').oninput = renderAnomalies;

  await loadReport();
  setInterval(loadReport, 15000);
});

async function loadReport() {
  try {
    reportData = await apiFetch('/wlan/report');
    renderStatCards();
    renderOverviewCharts();
    renderAPs();
    renderClients();
    renderChannels();
    renderAnomalies();
    renderSecurity();
    document.getElementById('wlanRefreshTimer').textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch (err) {
    showToast('Failed to load WLAN report', 'error');
  }
}

function renderStatCards() {
  const s = reportData.summary;
  document.getElementById('wlanTotalAPs').textContent = s.totalAPs;
  document.getElementById('wlanActiveAPs').textContent = s.activeAPs + ' active';
  document.getElementById('wlanTotalClients').textContent = s.totalClients;
  document.getElementById('wlanConnectedClients').textContent = s.connectedClients + ' connected';
  document.getElementById('wlanCriticalAnomalies').textContent = s.criticalAnomalies;
  document.getElementById('wlanHighAnomalies').textContent = s.highAnomalies + ' high severity';
  document.getElementById('wlanRogueClients').textContent = s.rogueClients;
}

function renderOverviewCharts() {
  const s = reportData.summary;
  const colors = ['#58a6ff', '#3fb950', '#d29922', '#f85149', '#bc8cff', '#39d2c0'];

  if (chartInstances.band) chartInstances.band.destroy();
  chartInstances.band = new Chart(document.getElementById('bandChart'), {
    type: 'doughnut',
    data: {
      labels: Object.keys(s.bandDistribution),
      datasets: [{
        data: Object.values(s.bandDistribution),
        backgroundColor: ['#58a6ff', '#3fb950', '#bc8cff'],
        borderColor: '#1c2333', borderWidth: 2
      }]
    },
    options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: '#8b949e' } } } }
  });

  if (chartInstances.security) chartInstances.security.destroy();
  chartInstances.security = new Chart(document.getElementById('securityChart'), {
    type: 'doughnut',
    data: {
      labels: Object.keys(s.securityDistribution).filter(k => s.securityDistribution[k] > 0),
      datasets: [{
        data: Object.keys(s.securityDistribution).filter(k => s.securityDistribution[k] > 0).map(k => s.securityDistribution[k]),
        backgroundColor: colors.slice(0, Object.keys(s.securityDistribution).filter(k => s.securityDistribution[k] > 0).length),
        borderColor: '#1c2333', borderWidth: 2
      }]
    },
    options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: '#8b949e' } } } }
  });

  const aps = reportData.accessPoints;
  const signalBuckets = { '-30 to -40': 0, '-41 to -50': 0, '-51 to -60': 0, '-61 to -70': 0, '-71 to -80': 0, '-81 to -90': 0 };
  aps.forEach(a => {
    const s = a.signalStrength;
    if (s > -40) signalBuckets['-30 to -40']++;
    else if (s > -50) signalBuckets['-41 to -50']++;
    else if (s > -60) signalBuckets['-51 to -60']++;
    else if (s > -70) signalBuckets['-61 to -70']++;
    else if (s > -80) signalBuckets['-71 to -80']++;
    else signalBuckets['-81 to -90']++;
  });
  if (chartInstances.signal) chartInstances.signal.destroy();
  chartInstances.signal = new Chart(document.getElementById('signalChart'), {
    type: 'bar',
    data: {
      labels: Object.keys(signalBuckets),
      datasets: [{ label: 'APs', data: Object.values(signalBuckets), backgroundColor: '#58a6ff', borderRadius: 4 }]
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

  const clients = reportData.clients;
  const osData = {};
  clients.forEach(c => { osData[c.os] = (osData[c.os] || 0) + 1; });
  if (chartInstances.os) chartInstances.os.destroy();
  chartInstances.os = new Chart(document.getElementById('osChart'), {
    type: 'doughnut',
    data: {
      labels: Object.keys(osData),
      datasets: [{
        data: Object.values(osData),
        backgroundColor: colors.slice(0, Object.keys(osData).length),
        borderColor: '#1c2333', borderWidth: 2
      }]
    },
    options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: '#8b949e', font: { size: 11 } } } } }
  });
}

function renderAPs() {
  const band = document.getElementById('apBandFilter').value;
  const status = document.getElementById('apStatusFilter').value;
  const search = document.getElementById('apSearch').value.toLowerCase();
  let filtered = [...reportData.accessPoints];
  if (band) filtered = filtered.filter(a => a.band === band);
  if (status) filtered = filtered.filter(a => a.status === status);
  if (search) filtered = filtered.filter(a =>
    a.ssid.toLowerCase().includes(search) || a.bssid.toLowerCase().includes(search) || a.vendor.toLowerCase().includes(search)
  );

  document.getElementById('apGrid').innerHTML = filtered.map(a => `
    <div class="ap-card">
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <div>
          <div class="ap-ssid">${a.hidden ? '(Hidden)' : a.ssid}</div>
          <div class="ap-meta">
            <span>${a.bssid}</span>
            <span>${a.vendor}</span>
          </div>
        </div>
        <span class="tag tag-${a.status === 'active' ? 'active' : a.status === 'idle' ? 'in-progress' : 'off'}">${a.status}</span>
      </div>
      <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
        ${securityTag(a.security)}
        <span class="tag tag-${a.band === '6GHz' ? 'development' : a.band === '5GHz' ? 'medium' : 'in-progress'}">${a.band}</span>
        <span class="tag tag-medium">Ch ${a.channel}</span>
      </div>
      <div style="margin-top:10px;font-size:12px;color:var(--text-secondary)">
        <div style="display:flex;justify-content:space-between">
          <span>Signal: ${signalBars(a.signalStrength)}</span>
          <span>${a.signalQuality}%</span>
        </div>
        <div style="display:flex;justify-content:space-between;margin-top:4px">
          <span>Clients: ${a.connectedClients}/${a.maxClients}</span>
          <span>Tx: ${a.txPower} dBm</span>
        </div>
        <div style="display:flex;justify-content:space-between;margin-top:4px">
          <span>Traffic: ${formatBytes(a.txBytes)} TX / ${formatBytes(a.rxBytes)} RX</span>
          <span>Uptime: ${formatUptime(a.uptime)}</span>
        </div>
        <div style="margin-top:6px">
          ${a.wmm ? '<span class="tag tag-active" style="font-size:10px">WMM</span> ' : ''}
          ${a.bandSteering ? '<span class="tag tag-development" style="font-size:10px">Band Steering</span> ' : ''}
          ${a.hidden ? '<span class="tag tag-high" style="font-size:10px">Hidden SSID</span>' : ''}
        </div>
      </div>
    </div>
  `).join('');
}

function renderClients() {
  const band = document.getElementById('clientBandFilter').value;
  const statusFilter = document.getElementById('clientStatusFilter').value;
  const search = document.getElementById('clientSearch').value.toLowerCase();
  let filtered = [...reportData.clients];
  if (band) filtered = filtered.filter(c => c.band === band);
  if (statusFilter === 'connected') filtered = filtered.filter(c => c.connected);
  if (statusFilter === 'rogue') filtered = filtered.filter(c => c.isRogue);
  if (statusFilter === 'suspicious') filtered = filtered.filter(c => c.suspicious);
  if (search) filtered = filtered.filter(c =>
    c.mac.toLowerCase().includes(search) || c.hostname.toLowerCase().includes(search) ||
    c.ip.includes(search) || c.apSsid.toLowerCase().includes(search)
  );

  const tbody = document.getElementById('clientsTableBody');
  tbody.innerHTML = filtered.map(c => `
    <tr class="${c.isRogue ? 'row-blocked' : c.suspicious ? 'row-suspicious' : ''}">
      <td style="font-family:monospace;font-size:12px">${c.mac}</td>
      <td>${c.hostname}</td>
      <td><span class="tag tag-medium">${c.os}</span></td>
      <td style="font-family:monospace">${c.ip}</td>
      <td>${c.apSsid}</td>
      <td>${signalBars(c.signalStrength)}</td>
      <td><span class="tag tag-${c.band === '6GHz' ? 'development' : c.band === '5GHz' ? 'medium' : 'in-progress'}">${c.band}</span></td>
      <td>${c.txRate}/${c.rxRate} Mbps</td>
      <td>
        ${c.isRogue ? '<span class="tag tag-critical">Rogue</span>' :
          c.suspicious ? '<span class="tag tag-high">Suspicious</span>' :
          c.connected ? '<span class="tag tag-active">Connected</span>' :
          '<span class="tag tag-deprecated">Disconnected</span>'}
      </td>
      <td><button class="btn btn-secondary btn-sm view-client" data-id="${c.id}">Details</button></td>
    </tr>
  `).join('');

  tbody.querySelectorAll('.view-client').forEach(btn => {
    btn.onclick = () => {
      const c = reportData.clients.find(cl => cl.id === parseInt(btn.dataset.id));
      if (!c) return;
      openModal(`Client: ${c.hostname}`, [
        { label: 'MAC Address', value: `<span style="font-family:monospace">${c.mac}</span>` },
        { label: 'Hostname', value: c.hostname },
        { label: 'OS', value: c.os },
        { label: 'IP Address', value: `<span style="font-family:monospace">${c.ip}</span>` },
        { label: 'Connected AP', value: `${c.apSsid} (${c.apBssid})` },
        { label: 'Channel / Band', value: `${c.channel} / ${c.band}` },
        { label: 'Signal', value: `${c.signalStrength} dBm (${c.signalQuality}%)` },
        { label: 'Tx/Rx Rate', value: `${c.txRate}/${c.rxRate} Mbps` },
        { label: 'Traffic', value: `${formatBytes(c.txBytes)} TX / ${formatBytes(c.rxBytes)} RX` },
        { label: 'Packets/sec', value: c.packetsPerSecond },
        { label: 'Auth Method', value: c.authMethod },
        { label: 'VLAN', value: c.vlan },
        { label: 'First Seen', value: formatDate(c.firstSeen) },
        { label: 'Last Activity', value: formatDate(c.lastActivity) },
        { label: 'Status', value: c.isRogue ? '<span class="tag tag-critical">Rogue</span>' : c.suspicious ? '<span class="tag tag-high">Suspicious</span>' : c.connected ? '<span class="tag tag-active">Connected</span>' : '<span class="tag tag-deprecated">Disconnected</span>' }
      ]);
    };
  });
}

function renderChannels() {
  const band = document.getElementById('channelBandFilter').value;
  const channels = reportData.channels[band] || [];

  const grid = document.getElementById('channelGrid');
  grid.innerHTML = channels.map(ch => `
    <div class="channel-cell ${ch.interference}">
      <div class="ch-num">${ch.channel}</div>
      <div class="ch-util">${ch.utilization}%</div>
    </div>
  `).join('');

  const tbody = document.getElementById('channelTableBody');
  tbody.innerHTML = channels.map(ch => `
    <tr>
      <td><strong>${ch.channel}</strong></td>
      <td>${ch.band}</td>
      <td>${ch.frequency} MHz</td>
      <td>
        <div style="display:flex;align-items:center;gap:8px">
          <div class="security-bar" style="flex:1;max-width:100px">
            <div class="security-bar-fill" style="width:${ch.utilization}%;background:${ch.utilization > 60 ? 'var(--accent-red)' : ch.utilization > 30 ? 'var(--accent-orange)' : 'var(--accent-green)'}"></div>
          </div>
          <span style="font-size:12px">${ch.utilization}%</span>
        </div>
      </td>
      <td>${ch.apCount}</td>
      <td>${ch.noiseFloor} dBm</td>
      <td>${ch.snr} dB</td>
      <td><span class="tag tag-${ch.interference === 'high' ? 'critical' : ch.interference === 'medium' ? 'high' : 'active'}">${ch.interference}</span></td>
    </tr>
  `).join('');
}

function renderAnomalies() {
  const severity = document.getElementById('anomalySeverityFilter').value;
  const statusFilter = document.getElementById('anomalyStatusFilter').value;
  const search = document.getElementById('anomalySearch').value.toLowerCase();
  let filtered = [...reportData.anomalies];
  if (severity) filtered = filtered.filter(a => a.severity === severity);
  if (statusFilter === 'mitigated') filtered = filtered.filter(a => a.mitigated);
  if (statusFilter === 'active') filtered = filtered.filter(a => !a.mitigated);
  if (search) filtered = filtered.filter(a =>
    a.type.toLowerCase().includes(search) || a.targetAP.toLowerCase().includes(search) || a.details.toLowerCase().includes(search)
  );

  document.getElementById('anomalyList').innerHTML = filtered.map(a => `
    <div class="anomaly-card" style="border-left:3px solid var(--accent-${a.severity === 'critical' ? 'red' : a.severity === 'high' ? 'orange' : a.severity === 'medium' ? 'blue' : 'green'})">
      <div class="anomaly-header">
        <div class="anomaly-type">${a.type}</div>
        <div style="display:flex;gap:6px">
          ${severityTag(a.severity)}
          ${a.mitigated ? '<span class="tag tag-active">Mitigated</span>' : '<span class="tag tag-critical">Active</span>'}
          ${a.falsePositive ? '<span class="tag tag-deprecated">False Positive</span>' : ''}
        </div>
      </div>
      <div class="anomaly-desc">${a.details}</div>
      <div class="anomaly-meta">
        <span>Target: ${a.targetAP} (${a.targetBssid})</span>
        ${a.targetClient ? `<span>Client: ${a.targetClient}</span>` : ''}
        <span>Source: ${a.sourceIP}</span>
        <span>Packets: ${a.packetsCaptured.toLocaleString()}</span>
        <span>${formatDate(a.timestamp)}</span>
      </div>
    </div>
  `).join('');
}

function renderSecurity() {
  const sec = reportData.securityAudit;
  const scoreClass = sec.overallScore >= 70 ? 'wlan-score-good' : sec.overallScore >= 40 ? 'wlan-score-warn' : 'wlan-score-bad';

  document.getElementById('securityStatCards').innerHTML = `
    <div class="stat-card stat-info">
      <div class="wlan-score">
        <div class="wlan-score-ring ${scoreClass}">${sec.overallScore}</div>
        <div>
          <div class="stat-label">Security Score</div>
          <div class="stat-sub">${sec.overallScore >= 70 ? 'Good' : sec.overallScore >= 40 ? 'Needs Improvement' : 'Critical'}</div>
        </div>
      </div>
    </div>
    <div class="stat-card stat-critical"><div class="stat-label">Open Networks</div><div class="stat-value">${sec.openNetworks}</div><div class="stat-sub">Unsecured APs</div></div>
    <div class="stat-card stat-warning"><div class="stat-label">WEP Networks</div><div class="stat-value">${sec.wepNetworks}</div><div class="stat-sub">Deprecated encryption</div></div>
    <div class="stat-card stat-success"><div class="stat-label">WPA3 Adoption</div><div class="stat-value">${sec.wpa3Adoption}%</div><div class="stat-sub">${sec.enterpriseAdoption}% Enterprise</div></div>
    <div class="stat-card stat-critical"><div class="stat-label">Rogue Clients</div><div class="stat-value">${sec.rogueClients}</div><div class="stat-sub">${sec.suspiciousClients} suspicious</div></div>
  `;

  const compliance = sec.complianceStatus;
  document.getElementById('complianceBars').innerHTML = Object.entries(compliance).map(([key, val]) => {
    const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    const color = val >= 70 ? 'var(--accent-green)' : val >= 40 ? 'var(--accent-orange)' : 'var(--accent-red)';
    return `
      <div style="margin-bottom:12px">
        <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
          <span>${label}</span>
          <span style="color:var(--text-secondary)">${val}%</span>
        </div>
        <div class="security-bar">
          <div class="security-bar-fill" style="width:${val}%;background:${color}"></div>
        </div>
      </div>
    `;
  }).join('');

  document.getElementById('securityRecommendations').innerHTML = sec.recommendations.length === 0
    ? '<div style="padding:16px;color:var(--text-secondary);font-size:13px">No recommendations - all checks passed</div>'
    : sec.recommendations.map(r => `
      <div style="padding:10px 16px;border-bottom:1px solid var(--border);font-size:13px;display:flex;gap:8px;align-items:center">
        <span style="color:var(--accent-orange)">&#9888;</span> ${r}
      </div>
    `).join('');
}

function exportCsv() {
  if (!reportData) return;
  const rows = [['SSID', 'BSSID', 'Channel', 'Band', 'Security', 'Signal (dBm)', 'Signal %', 'Clients', 'Max Clients', 'Status', 'Vendor', 'Tx Power', 'Uptime (s)', 'Traffic TX', 'Traffic RX']];
  reportData.accessPoints.forEach(a => {
    rows.push([a.ssid, a.bssid, a.channel, a.band, a.security, a.signalStrength, a.signalQuality, a.connectedClients, a.maxClients, a.status, a.vendor, a.txPower, a.uptime, a.txBytes, a.rxBytes]);
  });
  const csv = rows.map(r => r.map(v => `"${v}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'wlan-report.csv';
  a.click();
  URL.revokeObjectURL(url);
  showToast('WLAN report exported as CSV', 'success');
}
