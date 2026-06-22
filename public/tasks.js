function taskStatusClass(status) {
  if (status === 'To Do') return 'tag-todo';
  if (status === 'In Progress') return 'tag-in-progress';
  return 'tag-done';
}

function priorityClass(priority) {
  return `tag-${priority.toLowerCase()}`;
}

document.addEventListener('DOMContentLoaded', async () => {
  const sprintFilter = document.getElementById('sprintFilter');
  const assigneeFilter = document.getElementById('assigneeFilter');

  try {
    const data = await apiFetch('/engineering-tasks');

    const sprints = [...new Set(data.map(t => t.sprint))];
    sprints.forEach(s => {
      const opt = document.createElement('option');
      opt.value = s;
      opt.textContent = s;
      sprintFilter.appendChild(opt);
    });

    const assignees = [...new Set(data.map(t => t.assignee))];
    assignees.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a;
      opt.textContent = a;
      assigneeFilter.appendChild(opt);
    });

    function renderTasks() {
      let filtered = [...data];
      const sprint = sprintFilter.value;
      const assignee = assigneeFilter.value;

      if (sprint) filtered = filtered.filter(t => t.sprint === sprint);
      if (assignee) filtered = filtered.filter(t => t.assignee === assignee);

      const sprintItems = filtered.filter(t => t.status !== 'Done' && (t.sprint === 'Sprint 24' || t.sprint === 'Sprint 25'));
      const backlog = filtered.filter(t => t.status === 'To Do' && !sprintItems.includes(t));
      const done = filtered.filter(t => t.status === 'Done');

      renderTaskGroup('sprintGroup', sprintItems, 'sprintCount');
      renderTaskGroup('backlogGroup', backlog, 'backlogCount');
      renderTaskGroup('doneGroup', done, 'doneCount');

      document.getElementById('sprintCount').textContent = `${sprintItems.length} task${sprintItems.length !== 1 ? 's' : ''}`;
      document.getElementById('backlogCount').textContent = `${backlog.length} task${backlog.length !== 1 ? 's' : ''}`;
      document.getElementById('doneCount').textContent = `${done.length} task${done.length !== 1 ? 's' : ''}`;
    }

    sprintFilter.onchange = renderTasks;
    assigneeFilter.onchange = renderTasks;
    renderTasks();
  } catch (err) {
    showToast('Failed to load tasks', 'error');
  }
});

function renderTaskGroup(elementId, items, countId) {
  const el = document.getElementById(elementId);
  if (items.length === 0) {
    el.innerHTML = '<div class="group-item" style="justify-content:center;color:var(--text-secondary);cursor:default">No tasks</div>';
    return;
  }
  el.innerHTML = items.map(item => `
    <div class="group-item" data-id="${item.id}">
      <div class="item-main">
        <div class="item-title">${item.taskName}</div>
        <div class="item-meta">
          <span class="tag ${taskStatusClass(item.status)}">${item.status}</span>
          <span class="tag ${priorityClass(item.priority)}">${item.priority}</span>
          <span>${item.assignee}</span>
          <span>&#8226;</span>
          <span>${item.sprint}</span>
          <span>&#8226;</span>
          <span>${item.estimatedHours}h est.</span>
          <span>&#8226;</span>
          <span>Due: ${formatDateShort(item.dueDate)}</span>
          ${item.ruleId ? `<span>&#8226;</span><span><a href="/rules?id=${item.ruleId}" class="clickable">Rule #${item.ruleId}</a></span>` : ''}
        </div>
      </div>
      <div class="item-actions">
        <button class="btn btn-secondary btn-sm view-task" data-id="${item.id}">Details</button>
      </div>
    </div>
  `).join('');

  el.querySelectorAll('.view-task').forEach(btn => {
    btn.onclick = async (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      try {
        const item = await apiFetch(`/engineering-tasks/${id}`);
        openModal(`Task #${item.id}`, [
          { label: 'Task Name', value: item.taskName },
          { label: 'Status', value: `<span class="tag ${taskStatusClass(item.status)}">${item.status}</span>` },
          { label: 'Priority', value: `<span class="tag ${priorityClass(item.priority)}">${item.priority}</span>` },
          { label: 'Assignee', value: item.assignee },
          { label: 'Sprint', value: item.sprint },
          { label: 'Estimated Hours', value: `${item.estimatedHours}h` },
          { label: 'Due Date', value: formatDateShort(item.dueDate) },
          { label: 'Related Rule', value: item.ruleId ? `<a href="/rules?id=${item.ruleId}" class="clickable">Rule #${item.ruleId}</a>` : 'N/A' }
        ]);
      } catch (err) {
        showToast('Failed to load task details', 'error');
      }
    };
  });
}
