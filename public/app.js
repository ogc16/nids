const API_BASE = '/api';

function getCurrentUser() {
  try { return JSON.parse(localStorage.getItem('nids_user')); } catch { return null; }
}

function setCurrentUser(user) {
  if (user) localStorage.setItem('nids_user', JSON.stringify(user));
  else localStorage.removeItem('nids_user');
}

async function apiFetch(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...options.headers };
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, { headers, credentials: 'include', ...options });

  if (res.status === 401 && !path.includes('/auth/login')) {
    setCurrentUser(null);
    if (!window.location.pathname.includes('login')) {
      window.location.href = '/login';
    }
    throw new Error('Authentication required');
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `API error: ${res.status}`);
  }

  if (res.status === 204) return null;

  const data = await res.json();

  if (data && typeof data === 'object' && Array.isArray(data.items) && data.pagination) {
    data.items._pagination = data.pagination;
    return data.items;
  }

  return data;
}

let _loadingEl = null;
let _loadingTimer = null;

function showLoading(msg = 'Fetching data') {
  hideLoading();
  _loadingEl = document.createElement('div');
  _loadingEl.className = 'loading-overlay';
  _loadingEl.innerHTML = `<div class="loading-spinner"></div><div class="loading-text">${msg}&#8230;</div>`;
  document.body.appendChild(_loadingEl);
}

function hideLoading() {
  if (_loadingTimer) { clearTimeout(_loadingTimer); _loadingTimer = null; }
  if (_loadingEl) {
    _loadingEl.classList.add('hidden');
    setTimeout(() => { if (_loadingEl) { _loadingEl.remove(); _loadingEl = null; } }, 300);
  }
}

function showToast(message, type = 'success') {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4500);
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
    document.dispatchEvent(new CustomEvent('new-traffic-flow', { detail: flow }));
  });
  es.addEventListener('incident-created', (e) => {
    document.dispatchEvent(new CustomEvent('new-incident', { detail: JSON.parse(e.data) }));
  });
  es.addEventListener('automation-event', (e) => {
    document.dispatchEvent(new CustomEvent('new-automation', { detail: JSON.parse(e.data) }));
  });
  es.onerror = () => { setTimeout(connectSSE, 3000); };
}

function initCookieBanner() {
  if (localStorage.getItem('cookies_accepted')) return;
  const banner = document.createElement('div');
  banner.className = 'cookie-banner';
  banner.innerHTML = '<p>This site uses cookies for authentication and security purposes. By continuing, you consent to our use of cookies.</p><button class="btn btn-primary" id="cookieAccept">Accept</button>';
  document.body.appendChild(banner);
  document.getElementById('cookieAccept').onclick = () => {
    localStorage.setItem('cookies_accepted', 'true');
    banner.remove();
  };
}

document.addEventListener('DOMContentLoaded', () => {
  if (!window.location.pathname.includes('login')) {
    showLoading('Loading workspace');
    _loadingTimer = setTimeout(hideLoading, 3000);
    connectSSE();
  }

  initCookieBanner();

  // Sidebar toggle on mobile
  const sidebar = document.querySelector('.sidebar');
  if (sidebar) {
    sidebar.addEventListener('click', (e) => {
      if (window.innerWidth <= 768 && e.target === sidebar) {
        sidebar.classList.toggle('open');
      }
    });
  }
});
