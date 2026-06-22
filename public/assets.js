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
    const risks = item.risks || [];
    const riskSummary = risks.length > 0
      ? risks.map(r => `<span class="tag tag-${r.priority.toLowerCase()}">${r.risk.substring(0, 30)}${r.risk.length > 30 ? '...' : ''}</span>`).join(' ')
      : '';
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
          ${riskSummary ? `<div class="item-meta" style="margin-top:4px">${riskSummary}</div>` : ''}
        </div>
        <div class="item-actions">
          <button class="btn btn-primary btn-sm edit-asset" data-id="${item.id}">Edit</button>
          <button class="btn btn-secondary btn-sm view-asset" data-id="${item.id}">Details</button>
          <button class="btn btn-info btn-sm collect-logs" data-id="${item.id}" data-name="${item.assetName}">Collect Logs</button>
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
          const existingRisks = item.risks || [];
          const riskInputs = existingRisks.map((r, i) => `
            <div class="risk-entry" style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:8px">
              <div class="form-group" style="margin-bottom:6px">
                <label style="font-size:11px">Risk Description</label>
                <input type="text" class="form-control edit-risk-desc" value="${r.risk}" style="font-size:12px">
              </div>
              <div style="display:flex;gap:6px">
                <select class="form-control edit-risk-likelihood" style="font-size:11px;padding:4px 6px">
                  ${['Very Low','Low','Medium','High','Very High'].map(o => `<option ${r.likelihood === o ? 'selected' : ''}>${o}</option>`).join('')}
                </select>
                <select class="form-control edit-risk-severity" style="font-size:11px;padding:4px 6px">
                  ${['Low','Medium','High','Critical'].map(o => `<option ${r.severity === o ? 'selected' : ''}>${o}</option>`).join('')}
                </select>
                <select class="form-control edit-risk-priority" style="font-size:11px;padding:4px 6px">
                  ${['Low','Medium','High','Critical'].map(o => `<option ${r.priority === o ? 'selected' : ''}>${o}</option>`).join('')}
                </select>
                <button type="button" class="btn btn-danger btn-sm edit-remove-risk" style="padding:2px 8px;font-size:11px">X</button>
              </div>
            </div>
          `).join('');

          backdrop.innerHTML = `
          <div class="modal" style="width:600px">
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
              <div class="form-group">
                <label>Description</label>
                <textarea id="editDescription" class="form-control" style="min-height:50px;font-size:12px">${item.description || ''}</textarea>
              </div>
              <div style="margin-top:12px">
                <label style="font-size:12px;font-weight:600;display:block;margin-bottom:6px">Risk Assessment</label>
                <div id="editRisksContainer">${riskInputs}</div>
                <button type="button" id="editAddRiskBtn" class="btn btn-secondary btn-sm" style="margin-top:4px">+ Add Risk</button>
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

        document.getElementById('editAddRiskBtn').onclick = () => {
          const container = document.getElementById('editRisksContainer');
          const entry = document.createElement('div');
          entry.className = 'risk-entry';
          entry.style.cssText = 'background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:8px';
          entry.innerHTML = `
            <div class="form-group" style="margin-bottom:6px">
              <label style="font-size:11px">Risk Description</label>
              <input type="text" class="form-control edit-risk-desc" placeholder="Describe the risk" style="font-size:12px">
            </div>
            <div style="display:flex;gap:6px">
              <select class="form-control edit-risk-likelihood" style="font-size:11px;padding:4px 6px">
                <option>Very Low</option><option>Low</option><option selected>Medium</option><option>High</option><option>Very High</option>
              </select>
              <select class="form-control edit-risk-severity" style="font-size:11px;padding:4px 6px">
                <option>Low</option><option>Medium</option><option>High</option><option>Critical</option>
              </select>
              <select class="form-control edit-risk-priority" style="font-size:11px;padding:4px 6px">
                <option>Low</option><option>Medium</option><option>High</option><option>Critical</option>
              </select>
              <button type="button" class="btn btn-danger btn-sm remove-risk" style="padding:2px 8px;font-size:11px">X</button>
            </div>
          `;
          container.appendChild(entry);
        };

        document.getElementById('editRisksContainer').addEventListener('click', (e) => {
          if (e.target.classList.contains('remove-risk')) {
            e.target.closest('.risk-entry').remove();
          }
        });

        document.getElementById('saveEditAsset').onclick = async () => {
          const riskEntries = document.querySelectorAll('#editRisksContainer .risk-entry');
          const risks = Array.from(riskEntries).map(entry => ({
            risk: entry.querySelector('.edit-risk-desc').value,
            likelihood: entry.querySelector('.edit-risk-likelihood').value,
            severity: entry.querySelector('.edit-risk-severity').value,
            priority: entry.querySelector('.edit-risk-priority').value
          })).filter(r => r.risk.trim());

          const updates = {
            assetName: document.getElementById('editAssetName').value,
            ipRange: document.getElementById('editIpRange').value,
            type: document.getElementById('editType').value,
            riskLevel: document.getElementById('editRiskLevel').value,
            monitoringStatus: document.getElementById('editMonitoringStatus').value,
            owner: document.getElementById('editOwner').value,
            description: document.getElementById('editDescription').value,
            risks
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

  el.querySelectorAll('.collect-logs').forEach(btn => {
    btn.onclick = async (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      const name = btn.dataset.name;
      btn.disabled = true;
      btn.textContent = 'Collecting...';
      try {
        const result = await apiFetch(`/network-assets/${id}/collect-logs`, { method: 'POST' });
        showLogViewer(result);
      } catch (err) {
        showToast('Failed to collect logs: ' + err.message, 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Collect Logs';
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

        const risks = item.risks || [];
        const riskRows = risks.length > 0
          ? risks.map(r => `
              <div style="background:var(--bg-secondary);border-radius:6px;padding:10px;margin-bottom:8px">
                <div style="font-size:13px;font-weight:500;margin-bottom:4px">${r.risk}</div>
                <div style="display:flex;gap:8px;font-size:11px;color:var(--text-secondary)">
                  <span>Likelihood: <span class="tag tag-${r.likelihood === 'Very High' || r.likelihood === 'High' ? 'high' : r.likelihood === 'Medium' ? 'medium' : 'low'}">${r.likelihood}</span></span>
                  <span>Severity: <span class="tag tag-${r.severity.toLowerCase()}">${r.severity}</span></span>
                  <span>Priority: <span class="tag tag-${r.priority.toLowerCase()}">${r.priority}</span></span>
                </div>
              </div>
            `).join('')
          : '<span style="color:var(--text-secondary)">No risks identified</span>';

        openModal(`Asset #${item.id}: ${item.assetName}`, [
          { label: 'Asset Name', value: item.assetName },
          { label: 'IP Range', value: item.ipRange },
          { label: 'Type', value: item.type },
          { label: 'Monitoring Status', value: `<span class="health-dot ${monitoringClass(item.monitoringStatus)}"></span>${item.monitoringStatus}` },
          { label: 'Risk Level', value: `<span class="tag ${riskClass(item.riskLevel)}">${item.riskLevel}</span>` },
          { label: 'Owner', value: item.owner },
          { label: 'Description', value: item.description || 'None' },
          { label: 'Risk Analysis', value: riskRows },
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

function showLogViewer(result) {
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';

  const levelClass = (lvl) => {
    if (lvl === 'error') return 'tag-critical';
    if (lvl === 'warn') return 'tag-high';
    return 'tag-active';
  };
  const levelLabel = (lvl) => {
    if (lvl === 'error') return 'ERR';
    if (lvl === 'warn') return 'WARN';
    return 'INFO';
  };

  const summary = result.summary;
  const sampleRows = result.samples.map(s => `
    <tr>
      <td style="white-space:nowrap;font-size:11px;color:var(--text-secondary)">${formatDate(s.timestamp)}</td>
      <td style="font-size:11px">${s.logType}</td>
      <td><span class="tag ${levelClass(s.level)}" style="font-size:10px;padding:1px 6px">${levelLabel(s.level)}</span></td>
      <td style="font-size:12px;font-family:monospace;max-width:500px;overflow:hidden;text-overflow:ellipsis">${s.message}</td>
      <td style="font-size:11px;color:var(--text-secondary)">${s.srcIp}</td>
    </tr>
  `).join('');

  const timeSpan = new Date(result.timeRange.start).toLocaleString() + ' → ' + new Date(result.timeRange.end).toLocaleString();

  backdrop.innerHTML = `
    <div class="modal" style="width:900px;max-width:95vw">
      <div class="modal-header">
        <h3>Log Collection: ${result.assetName}</h3>
        <button class="modal-close">&times;</button>
      </div>
      <div class="modal-body">
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px">
          <div class="stat-card-small" style="flex:1;min-width:100px"><div class="stat-value">${summary.totalEvents.toLocaleString()}</div><div class="stat-label">Total Events</div></div>
          <div class="stat-card-small" style="flex:1;min-width:100px"><div class="stat-value" style="color:var(--accent-yellow)">${summary.warnings}</div><div class="stat-label">Warnings</div></div>
          <div class="stat-card-small" style="flex:1;min-width:100px"><div class="stat-value" style="color:var(--accent-red)">${summary.errors}</div><div class="stat-label">Errors</div></div>
          <div class="stat-card-small" style="flex:1;min-width:100px"><div class="stat-value" style="color:var(--accent-orange)">${summary.suspicious}</div><div class="stat-label">Suspicious</div></div>
          <div class="stat-card-small" style="flex:1;min-width:100px"><div class="stat-value">${result.logSource}</div><div class="stat-label">Log Source</div></div>
        </div>
        <div style="font-size:12px;color:var(--text-secondary);margin-bottom:12px">
          Time Range: ${timeSpan} &bull; Log Types: ${result.logTypes.join(', ')}
        </div>
        <div style="max-height:400px;overflow-y:auto;border:1px solid var(--border);border-radius:6px">
          <table style="width:100%;border-collapse:collapse">
            <thead>
              <tr style="background:var(--bg-secondary);position:sticky;top:0">
                <th style="padding:6px 10px;text-align:left;font-size:11px;font-weight:600">Timestamp</th>
                <th style="padding:6px 10px;text-align:left;font-size:11px;font-weight:600">Type</th>
                <th style="padding:6px 10px;text-align:left;font-size:11px;font-weight:600">Level</th>
                <th style="padding:6px 10px;text-align:left;font-size:11px;font-weight:600">Message</th>
                <th style="padding:6px 10px;text-align:left;font-size:11px;font-weight:600">Source IP</th>
              </tr>
            </thead>
            <tbody>${sampleRows}</tbody>
          </table>
        </div>
        <div style="font-size:11px;color:var(--text-secondary);margin-top:8px">Showing ${result.samples.length} of ${summary.totalEvents.toLocaleString()} events</div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary modal-close">Close</button>
      </div>
    </div>
  `;

  document.body.appendChild(backdrop);
  backdrop.querySelectorAll('.modal-close').forEach(b => b.onclick = () => backdrop.remove());
  backdrop.onclick = (e) => { if (e.target === backdrop) backdrop.remove(); };
  document.addEventListener('keydown', function handler(e) { if (e.key === 'Escape') { backdrop.remove(); document.removeEventListener('keydown', handler); } });
}

