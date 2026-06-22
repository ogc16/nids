function qaStatusClass(status) {
  if (status === 'Passed') return 'tag-active';
  if (status === 'Failed') return 'tag-critical';
  if (status === 'In Progress') return 'tag-in-progress';
  return 'tag-todo';
}

document.addEventListener('DOMContentLoaded', async () => {
  const statusFilter = document.getElementById('statusFilter');
  const categoryFilter = document.getElementById('categoryFilter');

  try {
    const data = await apiFetch('/qa-tests');
    const rules = await apiFetch('/detection-rules');

    const categories = [...new Set(data.map(t => t.category))];
    categories.forEach(c => {
      const opt = document.createElement('option');
      opt.value = c;
      opt.textContent = c;
      categoryFilter.appendChild(opt);
    });

    function getRuleName(ruleId) {
      const rule = rules.find(r => r.id === ruleId);
      return rule ? rule.name : 'Unknown Rule';
    }

    function renderTests() {
      let filtered = [...data];
      const status = statusFilter.value;
      const cat = categoryFilter.value;

      if (status) filtered = filtered.filter(t => t.status === status);
      if (cat) filtered = filtered.filter(t => t.category === cat);

      const passed = filtered.filter(t => t.status === 'Passed');
      const failed = filtered.filter(t => t.status === 'Failed');
      const pending = filtered.filter(t => t.status === 'In Progress' || t.status === 'Pending');

      renderQaGroup('passedGroup', passed, 'passedCount');
      renderQaGroup('failedGroup', failed, 'failedCount');
      renderQaGroup('pendingGroup', pending, 'pendingCount');

      document.getElementById('passedCount').textContent = `${passed.length} test${passed.length !== 1 ? 's' : ''}`;
      document.getElementById('failedCount').textContent = `${failed.length} test${failed.length !== 1 ? 's' : ''}`;
      document.getElementById('pendingCount').textContent = `${pending.length} test${pending.length !== 1 ? 's' : ''}`;
    }

    function renderQaGroup(elementId, items, countId) {
      const el = document.getElementById(elementId);
      if (items.length === 0) {
        el.innerHTML = '<div class="group-item" style="justify-content:center;color:var(--text-secondary);cursor:default">No tests</div>';
        return;
      }
      el.innerHTML = items.map(item => `
        <div class="group-item" data-id="${item.id}">
          <div class="item-main">
            <div class="item-title">${item.testName}</div>
            <div class="item-meta">
              <span class="tag ${qaStatusClass(item.status)}">${item.status}</span>
              <span>${item.category}</span>
              <span>&#8226;</span>
              <span>Rule: <a href="/rules.html?id=${item.ruleId}" class="clickable">${getRuleName(item.ruleId)}</a></span>
              <span>&#8226;</span>
              <span>Tester: ${item.tester}</span>
              ${item.testedAt ? `<span>&#8226;</span><span>Tested: ${formatDate(item.testedAt)}</span>` : ''}
            </div>
          </div>
          <div class="item-actions">
            <button class="btn btn-secondary btn-sm view-qa" data-id="${item.id}">Details</button>
            ${item.status === 'Passed' ? `<button class="btn btn-primary btn-sm promote-rule" data-id="${item.id}" data-rule-id="${item.ruleId}">Promote to Active</button>` : ''}
          </div>
        </div>
      `).join('');

      el.querySelectorAll('.view-qa').forEach(btn => {
        btn.onclick = async (e) => {
          e.stopPropagation();
          const id = btn.dataset.id;
          try {
            const item = await apiFetch(`/qa-tests/${id}`);
            const ruleName = getRuleName(item.ruleId);
            openModal(`QA Test #${item.id}`, [
              { label: 'Test Name', value: item.testName },
              { label: 'Status', value: `<span class="tag ${qaStatusClass(item.status)}">${item.status}</span>` },
              { label: 'Category', value: item.category },
              { label: 'Rule', value: `<a href="/rules.html?id=${item.ruleId}" class="clickable">${ruleName}</a>` },
              { label: 'Tester', value: item.tester },
              { label: 'Tested At', value: item.testedAt ? formatDate(item.testedAt) : 'Not yet tested' },
              { label: 'Notes', value: item.notes || 'None' }
            ]);
          } catch (err) {
            showToast('Failed to load test details', 'error');
          }
        };
      });

      el.querySelectorAll('.promote-rule').forEach(btn => {
        btn.onclick = async (e) => {
          e.stopPropagation();
          const ruleId = btn.dataset.ruleId;
          try {
            await apiFetch(`/detection-rules/${ruleId}`, {
              method: 'PUT',
              body: JSON.stringify({ status: 'Active' })
            });
            showToast('Rule promoted to Active via CI/CD pipeline');
            renderTests();
          } catch (err) {
            showToast('Failed to promote rule', 'error');
          }
        };
      });
    }

    statusFilter.onchange = renderTests;
    categoryFilter.onchange = renderTests;
    renderTests();
  } catch (err) {
    showToast('Failed to load QA tests', 'error');
  }
});
