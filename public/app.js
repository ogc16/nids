const API_BASE = '/api';

async function apiFetch(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  if (res.status === 204) return null;
  return res.json();
}

function showToast(message, type = 'success') {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

function formatDate(dateStr) {
  if (!dateStr) return '-';
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function formatDateShort(dateStr) {
  if (!dateStr) return '-';
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function tagHtml(text, prefix = '') {
  const cls = text.toLowerCase().replace(/\s+/g, '-');
  return `<span class="tag tag-${cls}">${text}</span>`;
}

function severityTag(severity) {
  return tagHtml(severity);
}

function statusTag(status) {
  return tagHtml(status);
}

function openModal(title, rows) {
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';
  backdrop.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <h3>${title}</h3>
        <button class="modal-close">&times;</button>
      </div>
      <div class="modal-body">
        ${rows.map(r => `
          <div class="detail-row">
            <div class="detail-label">${r.label}</div>
            <div class="detail-value">${r.value}</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
  backdrop.querySelector('.modal-close').onclick = () => backdrop.remove();
  backdrop.onclick = (e) => { if (e.target === backdrop) backdrop.remove(); };
  document.body.appendChild(backdrop);
}

function getQueryParam(name) {
  const params = new URLSearchParams(window.location.search);
  return params.get(name);
}

async function loadTableData(tableName, tbodyId, columns, renderRow) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;

  try {
    const data = await apiFetch(`/${tableName}`);
    tbody.innerHTML = data.map(item => `<tr>${renderRow(item)}</tr>`).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="${columns}">Failed to load data</td></tr>`;
  }
}

function connectSSE() {
  const es = new EventSource('/api/events');
  es.addEventListener('traffic-flow', (e) => {
    const flow = JSON.parse(e.data);
    const event = new CustomEvent('new-traffic-flow', { detail: flow });
    document.dispatchEvent(event);
  });
  es.addEventListener('incident-created', (e) => {
    const incident = JSON.parse(e.data);
    const event = new CustomEvent('new-incident', { detail: incident });
    document.dispatchEvent(event);
  });
  es.addEventListener('automation-event', (e) => {
    const auto = JSON.parse(e.data);
    const event = new CustomEvent('new-automation', { detail: auto });
    document.dispatchEvent(event);
  });
  es.onerror = () => { setTimeout(connectSSE, 3000); };
}

document.addEventListener('DOMContentLoaded', () => {
  connectSSE();
});
