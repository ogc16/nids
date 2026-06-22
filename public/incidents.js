document.addEventListener('DOMContentLoaded', async () => {
  const severityFilter = document.getElementById('severityFilter');
  const statusFilter = document.getElementById('statusFilter');
  const searchInput = document.getElementById('searchInput');

  async function loadIncidents() {
    try {
      let data = await apiFetch('/incidents');

      const sev = severityFilter.value;
      const stat = statusFilter.value;
      const search = searchInput.value.toLowerCase();

      if (sev) data = data.filter(i => i.severity === sev);
      if (stat) data = data.filter(i => i.status === stat);
      if (search) data = data.filter(i =>
        i.title.toLowerCase().includes(search) ||
        i.sourceIp.toLowerCase().includes(search) ||
        i.attackType.toLowerCase().includes(search)
      );

      const critical = data.filter(i => i.severity === 'Critical' || i.severity === 'High');
      const medium = data.filter(i => i.severity === 'Medium');
      const resolved = data.filter(i => i.severity === 'Low' || i.status === 'Resolved' || i.status === 'Closed');

      renderGroup('criticalGroup', critical, 'criticalCount');
      renderGroup('mediumGroup', medium, 'mediumCount');
      renderGroup('resolvedGroup', resolved, 'resolvedCount');

      document.getElementById('criticalCount').textContent = `${critical.length} incident${critical.length !== 1 ? 's' : ''}`;
      document.getElementById('mediumCount').textContent = `${medium.length} incident${medium.length !== 1 ? 's' : ''}`;
      document.getElementById('resolvedCount').textContent = `${resolved.length} incident${resolved.length !== 1 ? 's' : ''}`;
    } catch (err) {
      document.getElementById('criticalGroup').innerHTML = '<div class="empty-state">Failed to load incidents</div>';
    }
  }

  function renderGroup(elementId, items, countId) {
    const el = document.getElementById(elementId);
    if (items.length === 0) {
      el.innerHTML = '<div class="group-item" style="justify-content:center;color:var(--text-secondary);cursor:default">No incidents</div>';
      return;
    }
    el.innerHTML = items.map(item => `
      <div class="group-item" data-id="${item.id}">
        <div class="item-main">
          <div class="item-title">${item.title}</div>
          <div class="item-meta">
            ${severityTag(item.severity)}
            ${statusTag(item.status)}
            <span>${item.attackType}</span>
            <span>&#8226;</span>
            <span>${item.sourceIp}</span>
            <span>&#8226;</span>
            <span>${item.assignee}</span>
            <span>&#8226;</span>
            <span>${formatDate(item.detectedAt)}</span>
          </div>
        </div>
        <div class="item-actions">
          <button class="btn btn-secondary btn-sm view-detail" data-id="${item.id}">Details</button>
        </div>
      </div>
    `).join('');

    el.querySelectorAll('.view-detail').forEach(btn => {
      btn.onclick = async (e) => {
        e.stopPropagation();
        const id = btn.dataset.id;
        try {
          const item = await apiFetch(`/incidents/${id}`);
          openModal(`Incident #${item.id}`, [
            { label: 'Title', value: item.title },
            { label: 'Severity', value: severityTag(item.severity) },
            { label: 'Status', value: statusTag(item.status) },
            { label: 'Source IP', value: item.sourceIp },
            { label: 'Attack Type', value: item.attackType },
            { label: 'Assignee', value: item.assignee },
            { label: 'Detected At', value: formatDate(item.detectedAt) },
            { label: 'Rule ID', value: item.ruleId ? `<a href="/rules.html?id=${item.ruleId}" class="clickable">Rule #${item.ruleId}</a>` : 'N/A' },
            { label: 'Resolution Notes', value: item.resolutionNotes || 'None' }
          ]);
        } catch (err) {
          showToast('Failed to load incident details', 'error');
        }
      };
    });
  }

  severityFilter.onchange = loadIncidents;
  statusFilter.onchange = loadIncidents;
  searchInput.oninput = loadIncidents;

  loadIncidents();
});
