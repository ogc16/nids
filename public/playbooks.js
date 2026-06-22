function pbStatusClass(status) {
  return status === 'Active' ? 'tag-active' : 'tag-development';
}

document.addEventListener('DOMContentLoaded', async () => {
  const categoryFilter = document.getElementById('categoryFilter');
  const severityFilter = document.getElementById('severityFilter');

  try {
    const data = await apiFetch('/playbooks');

    document.getElementById('totalPlaybooks').textContent = data.length;
    document.getElementById('activePlaybooks').textContent = data.filter(p => p.status === 'Active').length;
    document.getElementById('draftPlaybooks').textContent = data.filter(p => p.status === 'Draft').length;
    document.getElementById('totalRuns').textContent = data.reduce((sum, p) => sum + (p.runCount || 0), 0);

    const cats = [...new Set(data.map(p => p.category))].sort();
    cats.forEach(c => {
      const opt = document.createElement('option');
      opt.value = c;
      opt.textContent = c;
      categoryFilter.appendChild(opt);
    });

    function render() {
      let filtered = [...data];
      const cat = categoryFilter.value;
      const sev = severityFilter.value;
      if (cat) filtered = filtered.filter(p => p.category === cat);
      if (sev) filtered = filtered.filter(p => p.severity === sev);

      const active = filtered.filter(p => p.status === 'Active');
      const draft = filtered.filter(p => p.status === 'Draft');

      renderGroup('activeGroup', active, 'activeGroupCount');
      renderGroup('draftGroup', draft, 'draftGroupCount');

      document.getElementById('activeGroupCount').textContent = `${active.length} playbook${active.length !== 1 ? 's' : ''}`;
      document.getElementById('draftGroupCount').textContent = `${draft.length} playbook${draft.length !== 1 ? 's' : ''}`;
    }

    function renderGroup(elementId, items, countId) {
      const el = document.getElementById(elementId);
      if (items.length === 0) {
        el.innerHTML = '<div class="group-item" style="justify-content:center;color:var(--text-secondary);cursor:default">No playbooks</div>';
        return;
      }
      el.innerHTML = items.map(item => `
        <div class="group-item" data-id="${item.id}">
          <div class="item-main">
            <div class="item-title">${item.name}</div>
            <div class="item-meta">
              <span class="tag ${pbStatusClass(item.status)}">${item.status}</span>
              <span class="tag tag-${item.severity.toLowerCase()}">${item.severity}</span>
              <span>${item.category}</span>
              <span>&#8226;</span>
              <span>${item.steps.length} steps</span>
              <span>&#8226;</span>
              <span>${item.runCount} run${item.runCount !== 1 ? 's' : ''}</span>
              ${item.lastRun ? `<span>&#8226;</span><span>Last: ${formatDate(item.lastRun)}</span>` : ''}
              <span>&#8226;</span>
              <span>By: ${item.createdBy}</span>
            </div>
          </div>
          <div class="item-actions">
            <button class="btn btn-primary btn-sm edit-pb" data-id="${item.id}">Edit</button>
            <button class="btn btn-secondary btn-sm view-pb" data-id="${item.id}">Details</button>
            ${item.status === 'Active' ? `<button class="btn btn-primary btn-sm run-pb" data-id="${item.id}">Run</button>` : ''}
            <button class="btn btn-danger btn-sm delete-pb" data-id="${item.id}" data-name="${item.name}">Delete</button>
          </div>
        </div>
      `).join('');

      el.querySelectorAll('.view-pb').forEach(btn => {
        btn.onclick = async (e) => {
          e.stopPropagation();
          const id = btn.dataset.id;
          try {
            const item = await apiFetch(`/playbooks/${id}`);
            openModal(`Playbook: ${item.name}`, [
              { label: 'Name', value: item.name },
              { label: 'Category', value: item.category },
              { label: 'Severity', value: `<span class="tag tag-${item.severity.toLowerCase()}">${item.severity}</span>` },
              { label: 'Status', value: `<span class="tag ${pbStatusClass(item.status)}">${item.status}</span>` },
              { label: 'Description', value: item.description },
              { label: 'Steps', value: `<div style="margin-top:4px">${item.steps.map(s =>
                `<div style="padding:4px 0;border-bottom:1px solid rgba(48,54,61,0.3);font-size:12px">
                  <strong>Step ${s.order}:</strong> ${s.action}
                  <span style="color:var(--text-secondary);margin-left:8px">[${s.assignee}, ${s.duration}]</span>
                </div>`
              ).join('')}</div>` },
              { label: 'Triggers On', value: item.triggerOnAttackTypes ? item.triggerOnAttackTypes.join(', ') : 'N/A' },
              { label: 'Run Count', value: `${item.runCount}` },
              { label: 'Last Run', value: item.lastRun ? formatDate(item.lastRun) : 'Never' },
              { label: 'Created', value: formatDate(item.createdAt) }
            ]);
          } catch (err) {
            showToast('Failed to load playbook details', 'error');
          }
        };
      });

      el.querySelectorAll('.run-pb').forEach(btn => {
        btn.onclick = async (e) => {
          e.stopPropagation();
          const id = btn.dataset.id;
          try {
            const item = await apiFetch(`/playbooks/${id}`);
            await apiFetch(`/playbooks/${id}`, {
              method: 'PUT',
              body: JSON.stringify({
                lastRun: new Date().toISOString(),
                runCount: (item.runCount || 0) + 1
              })
            });
            showToast(`Playbook "${item.name}" executed successfully`);
            render();
          } catch (err) {
            showToast('Failed to run playbook', 'error');
          }
        };
      });

      el.querySelectorAll('.delete-pb').forEach(btn => {
        btn.onclick = async (e) => {
          e.stopPropagation();
          const id = btn.dataset.id;
          const name = btn.dataset.name;
          if (!confirm(`Delete playbook "${name}"? This cannot be undone.`)) return;
          try {
            await apiFetch(`/playbooks/${id}`, { method: 'DELETE' });
            showToast(`Playbook "${name}" deleted`);
            setTimeout(() => location.reload(), 1000);
          } catch (err) {
            showToast('Failed to delete playbook', 'error');
          }
        };
      });

      el.querySelectorAll('.edit-pb').forEach(btn => {
        btn.onclick = async (e) => {
          e.stopPropagation();
          const id = btn.dataset.id;
          try {
            const item = await apiFetch(`/playbooks/${id}`);
            const backdrop = document.createElement('div');
            backdrop.className = 'modal-backdrop';
            backdrop.innerHTML = `
              <div class="modal" style="max-width:600px">
                <div class="modal-header">
                  <h3>Edit Playbook: ${item.name}</h3>
                  <button class="modal-close">&times;</button>
                </div>
                <div class="modal-body">
                  <div class="form-group">
                    <label>Name</label>
                    <input type="text" id="editPbName" class="form-control" value="${item.name}">
                  </div>
                  <div class="form-row">
                    <div class="form-group">
                      <label>Category</label>
                      <select id="editPbCategory" class="form-control">
                        <option ${item.category === 'Incident Response' ? 'selected' : ''}>Incident Response</option>
                        <option ${item.category === 'Threat Hunting' ? 'selected' : ''}>Threat Hunting</option>
                        <option ${item.category === 'Forensics' ? 'selected' : ''}>Forensics</option>
                        <option ${item.category === 'Containment' ? 'selected' : ''}>Containment</option>
                        <option ${item.category === 'Eradication' ? 'selected' : ''}>Eradication</option>
                        <option ${item.category === 'Recovery' ? 'selected' : ''}>Recovery</option>
                        <option ${item.category === 'Compliance' ? 'selected' : ''}>Compliance</option>
                        <option ${item.category === 'Enrichment' ? 'selected' : ''}>Enrichment</option>
                      </select>
                    </div>
                    <div class="form-group">
                      <label>Severity</label>
                      <select id="editPbSeverity" class="form-control">
                        <option ${item.severity === 'Critical' ? 'selected' : ''}>Critical</option>
                        <option ${item.severity === 'High' ? 'selected' : ''}>High</option>
                        <option ${item.severity === 'Medium' ? 'selected' : ''}>Medium</option>
                        <option ${item.severity === 'Low' ? 'selected' : ''}>Low</option>
                      </select>
                    </div>
                  </div>
                  <div class="form-row">
                    <div class="form-group">
                      <label>Status</label>
                      <select id="editPbStatus" class="form-control">
                        <option ${item.status === 'Active' ? 'selected' : ''}>Active</option>
                        <option ${item.status === 'Draft' ? 'selected' : ''}>Draft</option>
                      </select>
                    </div>
                    <div class="form-group">
                      <label>Description</label>
                      <input type="text" id="editPbDescription" class="form-control" value="${item.description || ''}">
                    </div>
                  </div>
                  <div class="form-actions" style="margin-top:16px">
                    <button id="saveEditPlaybook" class="btn btn-primary">Save Changes</button>
                    <button class="btn btn-secondary modal-close">Cancel</button>
                  </div>
                </div>
              </div>
            `;
            document.body.appendChild(backdrop);
            backdrop.querySelectorAll('.modal-close').forEach(b => b.onclick = () => backdrop.remove());
            backdrop.onclick = (e) => { if (e.target === backdrop) backdrop.remove(); };

            document.getElementById('saveEditPlaybook').onclick = async () => {
              const updates = {
                name: document.getElementById('editPbName').value,
                category: document.getElementById('editPbCategory').value,
                severity: document.getElementById('editPbSeverity').value,
                status: document.getElementById('editPbStatus').value,
                description: document.getElementById('editPbDescription').value
              };
              try {
                await apiFetch(`/playbooks/${id}`, { method: 'PUT', body: JSON.stringify(updates) });
                showToast('Playbook updated');
                backdrop.remove();
                setTimeout(() => location.reload(), 1000);
              } catch (err) {
                showToast('Failed to update playbook', 'error');
              }
            };
          } catch (err) {
            showToast('Failed to load playbook details', 'error');
          }
        };
      });
    }

    categoryFilter.onchange = render;
    severityFilter.onchange = render;
    render();
  } catch (err) {
    showToast('Failed to load playbooks', 'error');
  }
});
