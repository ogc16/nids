function ruleStatusClass(status) {
  if (status === 'Active') return 'tag-active';
  if (status === 'In Development') return 'tag-development';
  return 'tag-deprecated';
}

function renderRules(data) {
  const active = data.filter(r => r.status === 'Active');
  const dev = data.filter(r => r.status === 'In Development');
  const deprecated = data.filter(r => r.status === 'Deprecated');

  renderRuleGroup('activeGroup', active, 'activeCount');
  renderRuleGroup('devGroup', dev, 'devCount');
  renderRuleGroup('deprecatedGroup', deprecated, 'deprecatedCount');

  document.getElementById('activeCount').textContent = `${active.length} rule${active.length !== 1 ? 's' : ''}`;
  document.getElementById('devCount').textContent = `${dev.length} rule${dev.length !== 1 ? 's' : ''}`;
  document.getElementById('deprecatedCount').textContent = `${deprecated.length} rule${deprecated.length !== 1 ? 's' : ''}`;
}

function renderRuleGroup(elementId, items, countId) {
  const el = document.getElementById(elementId);
  if (items.length === 0) {
    el.innerHTML = '<div class="group-item" style="justify-content:center;color:var(--text-secondary);cursor:default">No rules</div>';
    return;
  }
  el.innerHTML = items.map(item => `
    <div class="group-item" data-id="${item.id}">
      <div class="item-main">
        <div class="item-title">${item.name}</div>
        <div class="item-meta">
          <span class="tag ${ruleStatusClass(item.status)}">${item.status}</span>
          <span class="tag tag-${item.priority.toLowerCase()}">${item.priority}</span>
          <span>${item.protocol}</span>
          <span>&#8226;</span>
          <span>${item.threatCategory}</span>
          <span>&#8226;</span>
          <span>FP: ${item.falsePositiveRate}%</span>
          <span>&#8226;</span>
          <span>Updated: ${formatDateShort(item.lastUpdated)}</span>
        </div>
      </div>
      <div class="item-actions">
        <button class="btn btn-secondary btn-sm view-rule" data-id="${item.id}">Details</button>
      </div>
    </div>
  `).join('');

  el.querySelectorAll('.view-rule').forEach(btn => {
    btn.onclick = async (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      try {
        const item = await apiFetch(`/detection-rules/${id}`);
        openModal(`Rule #${item.id}: ${item.name}`, [
          { label: 'Name', value: item.name },
          { label: 'Status', value: `<span class="tag ${ruleStatusClass(item.status)}">${item.status}</span>` },
          { label: 'Protocol', value: item.protocol },
          { label: 'Threat Category', value: item.threatCategory },
          { label: 'Priority', value: `<span class="tag tag-${item.priority.toLowerCase()}">${item.priority}</span>` },
          { label: 'Last Updated', value: formatDateShort(item.lastUpdated) },
          { label: 'False Positive Rate', value: `${item.falsePositiveRate}%` }
        ]);
      } catch (err) {
        showToast('Failed to load rule details', 'error');
      }
    };
  });
}

document.addEventListener('DOMContentLoaded', async () => {
  const ruleId = getQueryParam('id');

  try {
    const data = await apiFetch('/detection-rules');
    renderRules(data);

    if (ruleId) {
      const item = data.find(r => r.id === parseInt(ruleId));
      if (item) {
        setTimeout(() => {
          const el = document.querySelector(`[data-id="${item.id}"]`);
          if (el) {
            el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            el.style.background = 'rgba(88,166,255,0.1)';
            setTimeout(() => el.style.background = '', 2000);
          }
        }, 100);
      }
    }
  } catch (err) {
    showToast('Failed to load rules', 'error');
  }
});
