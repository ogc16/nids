function monitoringClass(status) {
  if (status === 'Online') return 'health-online';
  if (status === 'Degraded') return 'health-degraded';
  return 'health-offline';
}

function riskClass(level) {
  return `tag-${level.toLowerCase()}`;
}

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const assets = await apiFetch('/network-assets');
    const incidents = await apiFetch('/incidents');

    function getLinkedIncidents(asset) {
      return incidents.filter(inc =>
        inc.sourceIp && asset.ipRange && (
          inc.sourceIp.startsWith(asset.ipRange.split('/')[0].replace('.0', '')) ||
          inc.sourceIp === asset.ipRange.split('/')[0] ||
          (asset.ipRange.includes('-') && ipInRange(inc.sourceIp, asset.ipRange))
        )
      );
    }

    function ipInRange(ip, range) {
      const [start, end] = range.split('-');
      const ipNum = ip.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0);
      const startNum = start.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0);
      const endNum = end.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0);
      return ipNum >= startNum && ipNum <= endNum;
    }

    function classifyAsset(a) {
      if (a.riskLevel === 'Critical' || a.riskLevel === 'High') return 'crit';
      if (a.ipRange.includes('10.0.1') || a.type === 'Firewall' || a.type === 'Gateway' || a.type === 'Server') return 'dmz';
      return 'int';
    }

    const crit = assets.filter(a => classifyAsset(a) === 'crit');
    const int = assets.filter(a => classifyAsset(a) === 'int');
    const dmz = assets.filter(a => classifyAsset(a) === 'dmz');

    renderAssetGroup('criticalInfraGroup', crit, 'criticalInfraCount', incidents);
    renderAssetGroup('internalGroup', int, 'internalCount', incidents);
    renderAssetGroup('dmzGroup', dmz, 'dmzCount', incidents);

    document.getElementById('criticalInfraCount').textContent = `${crit.length} asset${crit.length !== 1 ? 's' : ''}`;
    document.getElementById('internalCount').textContent = `${int.length} asset${int.length !== 1 ? 's' : ''}`;
    document.getElementById('dmzCount').textContent = `${dmz.length} asset${dmz.length !== 1 ? 's' : ''}`;
  } catch (err) {
    showToast('Failed to load assets', 'error');
  }
});

function getLinkedIncidentsStatic(asset, incidents) {
  return incidents.filter(inc =>
    inc.sourceIp && asset.ipRange && (
      inc.sourceIp.startsWith(asset.ipRange.split('/')[0].replace('.0', '')) ||
      inc.sourceIp === asset.ipRange.split('/')[0] ||
      (asset.ipRange.includes('-') && ipInRangeStatic(inc.sourceIp, asset.ipRange))
    )
  );
}

function ipInRangeStatic(ip, range) {
  const [start, end] = range.split('-');
  const ipNum = ip.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0);
  const startNum = start.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0);
  const endNum = end.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0);
  return ipNum >= startNum && ipNum <= endNum;
}

function renderAssetGroup(elementId, items, countId, incidents) {
  const el = document.getElementById(elementId);
  if (items.length === 0) {
    el.innerHTML = '<div class="group-item" style="justify-content:center;color:var(--text-secondary);cursor:default">No assets</div>';
    return;
  }
  el.innerHTML = items.map(item => {
    const linked = getLinkedIncidentsStatic(item, incidents || []);
    const openCount = linked.filter(i => i.status !== 'Resolved' && i.status !== 'Closed').length;
    return `
      <div class="group-item" data-id="${item.id}">
        <div class="item-main">
          <div class="item-title"><span class="health-dot ${monitoringClass(item.monitoringStatus)}"></span>${item.assetName}</div>
          <div class="item-meta">
            <span class="tag ${riskClass(item.riskLevel)}">${item.riskLevel}</span>
            <span>${item.ipRange}</span>
            <span>&#8226;</span>
            <span>${item.type}</span>
            <span>&#8226;</span>
            <span>${item.monitoringStatus}</span>
            <span>&#8226;</span>
            <span>${item.owner}</span>
            <span>&#8226;</span>
            <span>${openCount} open incident${openCount !== 1 ? 's' : ''}</span>
            <span>&#8226;</span>
            <span>Scanned: ${formatDate(item.lastScanned)}</span>
          </div>
        </div>
        <div class="item-actions">
          <button class="btn btn-primary btn-sm edit-asset" data-id="${item.id}">Edit</button>
          <button class="btn btn-secondary btn-sm view-asset" data-id="${item.id}">Details</button>
          <button class="btn btn-danger btn-sm delete-asset" data-id="${item.id}" data-name="${item.assetName}">Delete</button>
        </div>
      </div>
    `;
  }).join('');

  el.querySelectorAll('.delete-asset').forEach(btn => {
    btn.onclick = async (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      const name = btn.dataset.name;
      if (!confirm(`Delete asset "${name}"? This cannot be undone.`)) return;
      try {
        await apiFetch(`/network-assets/${id}`, { method: 'DELETE' });
        showToast(`Asset "${name}" deleted`);
        setTimeout(() => location.reload(), 1000);
      } catch (err) {
        showToast('Failed to delete asset', 'error');
      }
    };
  });

  el.querySelectorAll('.edit-asset').forEach(btn => {
    btn.onclick = async (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      try {
        const item = await apiFetch(`/network-assets/${id}`);
        const backdrop = document.createElement('div');
        backdrop.className = 'modal-backdrop';
        backdrop.innerHTML = `
          <div class="modal">
            <div class="modal-header">
              <h3>Edit Asset: ${item.assetName}</h3>
              <button class="modal-close">&times;</button>
            </div>
            <div class="modal-body">
              <div class="form-group">
                <label>Asset Name</label>
                <input type="text" id="editAssetName" class="form-control" value="${item.assetName}">
              </div>
              <div class="form-group">
                <label>IP Range</label>
                <input type="text" id="editIpRange" class="form-control" value="${item.ipRange}">
              </div>
              <div class="form-row">
                <div class="form-group">
                  <label>Type</label>
                  <select id="editType" class="form-control">
                    <option ${item.type === 'Server' ? 'selected' : ''}>Server</option>
                    <option ${item.type === 'Workstation' ? 'selected' : ''}>Workstation</option>
                    <option ${item.type === 'Network Device' ? 'selected' : ''}>Network Device</option>
                    <option ${item.type === 'Firewall' ? 'selected' : ''}>Firewall</option>
                    <option ${item.type === 'Gateway' ? 'selected' : ''}>Gateway</option>
                    <option ${item.type === 'Database' ? 'selected' : ''}>Database</option>
                    <option ${item.type === 'Cloud Instance' ? 'selected' : ''}>Cloud Instance</option>
                    <option ${item.type === 'IoT' ? 'selected' : ''}>IoT Device</option>
                    <option ${item.type === 'Container' ? 'selected' : ''}>Container</option>
                  </select>
                </div>
                <div class="form-group">
                  <label>Risk Level</label>
                  <select id="editRiskLevel" class="form-control">
                    <option ${item.riskLevel === 'Critical' ? 'selected' : ''}>Critical</option>
                    <option ${item.riskLevel === 'High' ? 'selected' : ''}>High</option>
                    <option ${item.riskLevel === 'Medium' ? 'selected' : ''}>Medium</option>
                    <option ${item.riskLevel === 'Low' ? 'selected' : ''}>Low</option>
                  </select>
                </div>
              </div>
              <div class="form-row">
                <div class="form-group">
                  <label>Monitoring Status</label>
                  <select id="editMonitoringStatus" class="form-control">
                    <option ${item.monitoringStatus === 'Online' ? 'selected' : ''}>Online</option>
                    <option ${item.monitoringStatus === 'Degraded' ? 'selected' : ''}>Degraded</option>
                    <option ${item.monitoringStatus === 'Offline' ? 'selected' : ''}>Offline</option>
                  </select>
                </div>
                <div class="form-group">
                  <label>Owner</label>
                  <input type="text" id="editOwner" class="form-control" value="${item.owner}">
                </div>
              </div>
              <div class="form-actions" style="margin-top:16px">
                <button id="saveEditAsset" class="btn btn-primary">Save Changes</button>
                <button class="btn btn-secondary modal-close">Cancel</button>
              </div>
            </div>
          </div>
        `;
        document.body.appendChild(backdrop);
        backdrop.querySelectorAll('.modal-close').forEach(b => b.onclick = () => backdrop.remove());
        backdrop.onclick = (e) => { if (e.target === backdrop) backdrop.remove(); };

        document.getElementById('saveEditAsset').onclick = async () => {
          const updates = {
            assetName: document.getElementById('editAssetName').value,
            ipRange: document.getElementById('editIpRange').value,
            type: document.getElementById('editType').value,
            riskLevel: document.getElementById('editRiskLevel').value,
            monitoringStatus: document.getElementById('editMonitoringStatus').value,
            owner: document.getElementById('editOwner').value
          };
          try {
            await apiFetch(`/network-assets/${id}`, { method: 'PUT', body: JSON.stringify(updates) });
            showToast('Asset updated');
            backdrop.remove();
            setTimeout(() => location.reload(), 1000);
          } catch (err) {
            showToast('Failed to update asset', 'error');
          }
        };
      } catch (err) {
        showToast('Failed to load asset details', 'error');
      }
    };
  });

  el.querySelectorAll('.view-asset').forEach(btn => {
    btn.onclick = async (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      try {
        const item = await apiFetch(`/network-assets/${id}`);
        const allIncidents = await apiFetch('/incidents');
        const linked = getLinkedIncidentsStatic(item, allIncidents);
        const linkedHtml = linked.length > 0
          ? linked.map(inc =>
              `<div style="padding:3px 0;font-size:12px">
                <a href="/incidents.html?id=${inc.id}" class="clickable">#${inc.id}</a>
                ${inc.title}
                <span style="color:var(--text-secondary)">${inc.status}</span>
              </div>`
            ).join('')
          : '<span style="color:var(--text-secondary)">No linked incidents</span>';

        openModal(`Asset #${item.id}: ${item.assetName}`, [
          { label: 'Asset Name', value: item.assetName },
          { label: 'IP Range', value: item.ipRange },
          { label: 'Type', value: item.type },
          { label: 'Monitoring Status', value: `<span class="health-dot ${monitoringClass(item.monitoringStatus)}"></span>${item.monitoringStatus}` },
          { label: 'Risk Level', value: `<span class="tag ${riskClass(item.riskLevel)}">${item.riskLevel}</span>` },
          { label: 'Owner', value: item.owner },
          { label: 'Open Incidents', value: `${item.openIncidentCount || 0}` },
          { label: 'Last Incident', value: item.lastIncidentDate ? formatDate(item.lastIncidentDate) : 'None' },
          { label: 'Last Scanned', value: formatDate(item.lastScanned) },
          { label: `Linked Incidents (${linked.length})`, value: linkedHtml }
        ]);
      } catch (err) {
        showToast('Failed to load asset details', 'error');
      }
    };
  });
}
