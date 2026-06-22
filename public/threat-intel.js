function threatStatusClass(status) {
  if (status === 'Active Threats') return 'tag-critical';
  if (status === 'Monitoring') return 'tag-medium';
  return 'tag-low';
}

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const data = await apiFetch('/threat-intel');

    const active = data.filter(t => t.status === 'Active Threats');
    const monitoring = data.filter(t => t.status === 'Monitoring');
    const mitigated = data.filter(t => t.status === 'Mitigated');

    renderThreatGroup('activeThreatsGroup', active, 'activeThreatsCount');
    renderThreatGroup('monitoringGroup', monitoring, 'monitoringCount');
    renderThreatGroup('mitigatedGroup', mitigated, 'mitigatedCount');

    document.getElementById('activeThreatsCount').textContent = `${active.length} threat${active.length !== 1 ? 's' : ''}`;
    document.getElementById('monitoringCount').textContent = `${monitoring.length} threat${monitoring.length !== 1 ? 's' : ''}`;
    document.getElementById('mitigatedCount').textContent = `${mitigated.length} threat${mitigated.length !== 1 ? 's' : ''}`;
  } catch (err) {
    showToast('Failed to load threat intelligence', 'error');
  }
});

function renderThreatGroup(elementId, items, countId) {
  const el = document.getElementById(elementId);
  if (items.length === 0) {
    el.innerHTML = '<div class="group-item" style="justify-content:center;color:var(--text-secondary);cursor:default">No threats</div>';
    return;
  }
  el.innerHTML = items.map(item => `
    <div class="group-item" data-id="${item.id}">
      <div class="item-main">
        <div class="item-title">${item.threatName}</div>
        <div class="item-meta">
          <span class="tag ${threatStatusClass(item.status)}">${item.status}</span>
          <span>${item.category}</span>
          <span>&#8226;</span>
          <span>${item.cveId}</span>
          <span>&#8226;</span>
          <span>Risk Score: ${item.riskScore}</span>
          <span>&#8226;</span>
          <span>Source: ${item.source}</span>
          <span>&#8226;</span>
          <span>${formatDateShort(item.dateAdded)}</span>
        </div>
      </div>
      <div class="item-actions">
        <button class="btn btn-secondary btn-sm view-threat" data-id="${item.id}">Details</button>
      </div>
    </div>
  `).join('');

  el.querySelectorAll('.view-threat').forEach(btn => {
    btn.onclick = async (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      try {
        const item = await apiFetch(`/threat-intel/${id}`);
        openModal(`Threat #${item.id}`, [
          { label: 'Threat Name', value: item.threatName },
          { label: 'Category', value: item.category },
          { label: 'CVE ID', value: item.cveId || 'N/A' },
          { label: 'Risk Score', value: `${item.riskScore}/100` },
          { label: 'Source', value: item.source },
          { label: 'Status', value: `<span class="tag ${threatStatusClass(item.status)}">${item.status}</span>` },
          { label: 'Date Added', value: formatDateShort(item.dateAdded) }
        ]);
      } catch (err) {
        showToast('Failed to load threat details', 'error');
      }
    };
  });
}
