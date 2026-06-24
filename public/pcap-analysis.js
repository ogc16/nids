let captures = [];
let currentCaptureId = null;
let chartInstances = {};
let packetOffset = 0;
const PACKET_LIMIT = 200;

function formatBytes(bytes) {
  if (!bytes) return '-';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function formatDate(dateStr) {
  if (!dateStr) return '-';
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

document.addEventListener('DOMContentLoaded', async () => {
  await loadTsharkStatus();
  await loadCaptures();

  document.getElementById('uploadPcapBtn').onclick = () => {
    document.getElementById('uploadSection').style.display = 'block';
    document.getElementById('captureSection').style.display = 'none';
  };
  document.getElementById('closeUploadBtn').onclick = () => {
    document.getElementById('uploadSection').style.display = 'none';
  };

  document.getElementById('liveCaptureBtn').onclick = async () => {
    document.getElementById('captureSection').style.display = 'block';
    document.getElementById('uploadSection').style.display = 'none';
    await loadInterfaces();
  };
  document.getElementById('closeCaptureBtn').onclick = () => {
    document.getElementById('captureSection').style.display = 'none';
  };

  document.getElementById('uploadBtn').onclick = uploadPcap;
  document.getElementById('startCaptureBtn').onclick = startCapture;
  document.getElementById('refreshCapturesBtn').onclick = loadCaptures;
  document.getElementById('closeAnalysisBtn').onclick = closeAnalysis;
  document.getElementById('exportPcapBtn').onclick = exportPcap;
  document.getElementById('applyPacketFilter').onclick = loadPackets;

  document.getElementById('endpointTypeFilter').onchange = () => loadAnalysis(currentCaptureId);
  document.getElementById('convTypeFilter').onchange = () => loadAnalysis(currentCaptureId);

  document.getElementById('packetFilter').addEventListener('keydown', e => {
    if (e.key === 'Enter') loadPackets();
  });
});

async function loadTsharkStatus() {
  try {
    const status = await apiFetch('/pcap/status');
    const el = document.getElementById('tsharkStatus');
    if (status.tsharkAvailable) {
      el.className = 'tag tag-active';
      el.textContent = 'TShark Available';
    } else {
      el.className = 'tag tag-deprecated';
      el.textContent = 'TShark Not Found';
    }
  } catch {
    const el = document.getElementById('tsharkStatus');
    el.className = 'tag tag-critical';
    el.textContent = 'Status Unknown';
  }
}

async function loadCaptures() {
  try {
    const result = await apiFetch('/pcap/captures');
    captures = result.items || [];
    renderCaptures();
  } catch (err) {
    document.getElementById('capturesList').innerHTML = `<div class="empty-state"><h3>Error loading captures</h3><p>${err.message}</p></div>`;
  }
}

function renderCaptures() {
  const container = document.getElementById('capturesList');
  if (captures.length === 0) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon">&#128220;</div><h3>No captures yet</h3><p>Upload a PCAP file or start a live capture to begin analysis</p></div>`;
    return;
  }
  const tsharkAvailable = document.getElementById('tsharkStatus').textContent.includes('Available');
  container.innerHTML = `<div class="data-table-wrapper"><table class="data-table"><thead><tr><th>File</th><th>Original Name</th><th>Size</th><th>Packets</th><th>Uploaded</th><th></th></tr></thead><tbody>${captures.map(c => {
    const isAnalyzing = currentCaptureId === c.id;
    return `<tr class="${isAnalyzing ? 'row-suspicious' : ''}" style="cursor:pointer" data-id="${c.id}">
      <td class="clickable">${c.filename}</td>
      <td>${c.originalName}</td>
      <td>${formatBytes(c.size)}</td>
      <td>${c.metadata && c.metadata.packets != null ? c.metadata.packets.toLocaleString() : '-'}</td>
      <td>${formatDate(c.uploadedAt)}</td>
      <td>
        <button class="btn btn-secondary btn-sm analyze-btn" data-id="${c.id}" ${tsharkAvailable ? '' : 'disabled'}>Analyze</button>
        <button class="btn btn-danger btn-sm delete-btn" data-id="${c.id}">Delete</button>
      </td>
    </tr>`;
  }).join('')}</tbody></table></div>`;

  container.querySelectorAll('.analyze-btn').forEach(btn => {
    btn.onclick = e => { e.stopPropagation(); loadAnalysis(parseInt(btn.dataset.id)); };
  });
  container.querySelectorAll('.delete-btn').forEach(btn => {
    btn.onclick = async e => {
      e.stopPropagation();
      if (!confirm('Delete this capture?')) return;
      await apiFetch(`/pcap/captures/${btn.dataset.id}`, { method: 'DELETE' });
      if (currentCaptureId === parseInt(btn.dataset.id)) closeAnalysis();
      await loadCaptures();
    };
  });
  container.querySelectorAll('tr[data-id]').forEach(row => {
    row.onclick = () => loadAnalysis(parseInt(row.dataset.id));
  });
}

async function uploadPcap() {
  const input = document.getElementById('pcapFileInput');
  if (!input.files || !input.files[0]) return showToast('Select a PCAP file', 'error');

  const progress = document.getElementById('uploadProgress');
  progress.style.display = 'block';

  const formData = new FormData();
  formData.append('pcap', input.files[0]);

  try {
    const res = await fetch('/api/pcap/upload', {
      method: 'POST',
      headers: { Authorization: `Bearer ${getCookie('nids_token')}` },
      credentials: 'include',
      body: formData
    });
    if (!res.ok) throw new Error((await res.json()).error || 'Upload failed');
    const record = await res.json();
    showToast(`Uploaded "${record.originalName}" successfully`);
    document.getElementById('uploadSection').style.display = 'none';
    input.value = '';
    await loadCaptures();
    await loadAnalysis(record.id);
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    progress.style.display = 'none';
  }
}

function getCookie(name) {
  const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : null;
}

async function loadInterfaces() {
  const sel = document.getElementById('captureInterface');
  sel.innerHTML = '<option value="">Loading...</option>';
  try {
    const result = await apiFetch('/capture/interfaces');
    if (!result.available || result.interfaces.length === 0) {
      sel.innerHTML = '<option value="">No interfaces available (install tshark)</option>';
      return;
    }
    sel.innerHTML = result.interfaces.map(i => `<option value="${i.name}">${i.name} (${i.description})</option>`).join('');
  } catch {
    sel.innerHTML = '<option value="">Failed to load interfaces</option>';
  }
}

async function startCapture() {
  const iface = document.getElementById('captureInterface').value;
  if (!iface) return showToast('Select an interface', 'error');

  const duration = parseInt(document.getElementById('captureDuration').value) || 30;
  const filter = document.getElementById('captureFilter').value.trim();

  const statusEl = document.getElementById('captureStatus');
  statusEl.style.display = 'block';
  statusEl.innerHTML = '<div class="loading-text">Capturing...</div>';

  try {
    await apiFetch('/capture/start', {
      method: 'POST',
      body: JSON.stringify({ interface: iface, duration, filter })
    });
    showToast(`Capture started on ${iface} for ${duration}s`);

    setTimeout(async () => {
      await apiFetch('/capture/stop', {
        method: 'POST',
        body: JSON.stringify({ captureId: `${iface}-${Date.now() - duration * 1000}` })
      }).catch(() => {});
      statusEl.innerHTML = '<div class="tag tag-active">Capture complete</div>';
      await loadCaptures();
    }, duration * 1000 + 1000);

    document.getElementById('captureSection').style.display = 'none';
  } catch (err) {
    statusEl.innerHTML = `<div class="tag tag-critical">Error: ${err.message}</div>`;
  }
}

async function loadAnalysis(id) {
  currentCaptureId = id;
  const view = document.getElementById('analysisView');
  view.style.display = 'block';

  document.getElementById('analysisTitle').textContent = `Analyzing: ${captures.find(c => c.id === id)?.originalName || `#${id}`}`;

  try {
    const capture = await apiFetch(`/pcap/captures/${id}`);
    document.getElementById('analysisPackets').textContent = capture.metadata?.packets?.toLocaleString() || '-';
    document.getElementById('analysisSize').textContent = formatBytes(capture.size);
    document.getElementById('analysisProtocols').textContent = capture.metadata?.protocols?.length || '-';
    document.getElementById('analysisDate').textContent = formatDate(capture.uploadedAt);
  } catch {}

  renderCaptures();

  try {
    const hierarchy = await apiFetch(`/pcap/captures/${id}/analysis/protocols`);
    renderProtocolHierarchy(hierarchy);
  } catch (err) {
    document.getElementById('protocolHierarchy').innerHTML = `<div class="empty-state"><p>Failed to load: ${err.message}</p></div>`;
  }

  try {
    const type = document.getElementById('endpointTypeFilter').value;
    const endpoints = await apiFetch(`/pcap/captures/${id}/analysis/endpoints?type=${type}`);
    document.getElementById('endpointsTableBody').innerHTML = endpoints.length === 0
      ? '<tr><td colspan="3">No endpoints found</td></tr>'
      : endpoints.slice(0, 50).map(e => `<tr><td>${e.address}</td><td>${(e.rxPackets + e.txPackets).toLocaleString()}</td><td>${formatBytes(e.bytes)}</td></tr>`).join('');
  } catch (err) {
    document.getElementById('endpointsTableBody').innerHTML = `<tr><td colspan="3">${err.message}</td></tr>`;
  }

  try {
    const convType = document.getElementById('convTypeFilter').value;
    const convs = await apiFetch(`/pcap/captures/${id}/analysis/conversations?type=${convType}`);
    document.getElementById('conversationsTableBody').innerHTML = convs.length === 0
      ? '<tr><td colspan="5">No conversations found</td></tr>'
      : convs.slice(0, 100).map(c => `<tr><td>${c.addrA}</td><td>${c.addrB}</td><td>${c.rxPackets.toLocaleString()}</td><td>${c.txPackets.toLocaleString()}</td><td>${formatBytes(c.bytes)}</td></tr>`).join('');
  } catch (err) {
    document.getElementById('conversationsTableBody').innerHTML = `<tr><td colspan="5">${err.message}</td></tr>`;
  }

  packetOffset = 0;
  await loadPackets();
}

function renderProtocolHierarchy(hierarchy) {
  const container = document.getElementById('protocolHierarchy');
  if (!hierarchy || !hierarchy.children || hierarchy.children.length === 0) {
    container.innerHTML = '<div class="empty-state"><p>No protocol data available</p></div>';
    return;
  }
  container.innerHTML = `<div style="font-family:monospace;font-size:12px;padding:8px">${renderTree(hierarchy, '')}</div>`;
}

function renderTree(node, indent) {
  let html = '';
  if (node.name && node.name !== 'Protocol Hierarchy') {
    const stats = node.packets ? ` - ${node.packets}` : '';
    html += `<div style="padding:2px 0">${indent}<span style="color:var(--accent-blue)">${node.name}</span>${stats}</div>`;
  }
  if (node.children) {
    node.children.forEach(child => {
      html += renderTree(child, indent + '&nbsp;&nbsp;&nbsp;&nbsp;');
    });
  }
  return html;
}

async function loadPackets() {
  if (!currentCaptureId) return;
  const filter = document.getElementById('packetFilter').value.trim();
  const tbody = document.getElementById('packetsTableBody');

  try {
    const result = await apiFetch(`/pcap/captures/${currentCaptureId}/packets?filter=${encodeURIComponent(filter)}&limit=${PACKET_LIMIT}&offset=${packetOffset}`);
    const packets = result.packets || [];

    tbody.innerHTML = packets.length === 0
      ? '<tr><td colspan="7">No packets found</td></tr>'
      : packets.map(p => `<tr>
        <td>${p.number}</td>
        <td style="font-size:11px;white-space:nowrap">${p.time ? new Date(p.time).toLocaleTimeString() : '-'}</td>
        <td>${p.srcIp}${p.srcPortDisplay ? `:${p.srcPortDisplay}` : ''}</td>
        <td>${p.dstIp}${p.dstPortDisplay ? `:${p.dstPortDisplay}` : ''}</td>
        <td><span class="tag tag-${p.protocol.toLowerCase() || 'tcp'}">${p.protocol || 'Unknown'}</span></td>
        <td>${p.length || 0}</td>
        <td style="font-size:11px;color:var(--text-secondary)">${p.info || ''}</td>
      </tr>`).join('');

    const total = result.total || 0;
    const totalPages = Math.ceil(total / PACKET_LIMIT);
    const currentPage = Math.floor(packetOffset / PACKET_LIMIT) + 1;
    const pagination = document.getElementById('packetPagination');
    pagination.innerHTML = `
      <button class="btn btn-secondary btn-sm" ${packetOffset <= 0 ? 'disabled' : ''} id="prevPackets">Previous</button>
      <span style="padding:4px 8px;font-size:12px;color:var(--text-secondary)">Page ${currentPage}${total > 0 ? ` of ${totalPages}` : ''}</span>
      <button class="btn btn-secondary btn-sm" ${packetOffset + PACKET_LIMIT >= total ? 'disabled' : ''} id="nextPackets">Next</button>
    `;
    document.getElementById('prevPackets').onclick = () => { packetOffset = Math.max(0, packetOffset - PACKET_LIMIT); loadPackets(); };
    document.getElementById('nextPackets').onclick = () => { packetOffset += PACKET_LIMIT; loadPackets(); };
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7">Error: ${err.message}</td></tr>`;
  }
}

async function exportPcap() {
  if (!currentCaptureId) return;
  const a = document.createElement('a');
  a.href = `/api/pcap/captures/${currentCaptureId}/export`;
  a.download = '';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function closeAnalysis() {
  currentCaptureId = null;
  document.getElementById('analysisView').style.display = 'none';
  renderCaptures();
}
