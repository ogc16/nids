'use client';

import { useEffect, useState, useCallback } from 'react';

interface Flow {
  id: number;
  timestamp: string;
  srcIp: string;
  destIp: string;
  srcPort: number;
  destPort: number;
  protocol: string;
  bytes: number;
  status: string;
}

interface Stats {
  totalFlows: number;
  suspiciousCount: number;
  blockedCount: number;
  allowedCount: number;
  totalBytes: number;
  uniqueProtocols: number;
}

interface Pagination {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

function formatBytes(b: number) {
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
}

function timeAgo(ts: string) {
  const s = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

export default function NetworkMonitoringPage() {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [pagination, setPagination] = useState<Pagination>({ page: 1, limit: 25, total: 0, totalPages: 0 });
  const [stats, setStats] = useState<Stats | null>(null);
  const [filter, setFilter] = useState('');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);

  const fetchFlows = useCallback(async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams({ page: String(page), limit: '25' });
      if (filter.trim()) params.set('displayFilter', filter.trim());
      const [flowsRes, statsRes] = await Promise.all([
        fetch(`/api/network-traffic?${params}`),
        fetch('/api/network-traffic/stats'),
      ]);
      if (flowsRes.ok) {
        const data = await flowsRes.json();
        setFlows(data.items);
        setPagination(data.pagination);
      }
      if (statsRes.ok) setStats(await statsRes.json());
    } catch {
    } finally {
      setLoading(false);
    }
  }, [page, filter]);

  useEffect(() => { fetchFlows(); }, [fetchFlows]);

  const handleSimulate = async () => {
    setSimulating(true);
    try {
      await fetch('/api/network-traffic/simulate', { method: 'POST' });
      await fetchFlows();
    } finally {
      setSimulating(false);
    }
  };

  const handleFilterKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') { setPage(1); fetchFlows(); }
  };

  const protocolTag = (p: string) => {
    const cls = p.toLowerCase();
    return <span className={`tag tag-${cls}`}>{p}</span>;
  };

  const statusTag = (s: string) => {
    let cls = 'tag-active';
    if (s === 'blocked') cls = 'tag-critical';
    else if (s === 'suspicious') cls = 'tag-investigating';
    else if (s === 'allowed') cls = 'tag-online';
    return <span className={`tag ${cls}`}>{s}</span>;
  };

  return (
    <>
      <div className="page-header">
        <div>
          <h2>Network Traffic Monitoring</h2>
          <div className="subtitle">Real-time packet flow analysis and inspection</div>
        </div>
        <div className="header-actions">
          <button className="btn btn-primary" onClick={handleSimulate} disabled={simulating}>
            {simulating ? 'Simulating...' : 'Simulate Traffic'}
          </button>
        </div>
      </div>

      {stats && (
        <div className="dashboard-grid">
          <div className="stat-card stat-info">
            <div className="stat-label">Total Flows</div>
            <div className="stat-value">{stats.totalFlows}</div>
            <div className="stat-sub">{formatBytes(stats.totalBytes)} total</div>
          </div>
          <div className="stat-card stat-warning">
            <div className="stat-label">Suspicious</div>
            <div className="stat-value">{stats.suspiciousCount}</div>
            <div className="stat-sub">Flagged for review</div>
          </div>
          <div className="stat-card stat-critical">
            <div className="stat-label">Blocked</div>
            <div className="stat-value">{stats.blockedCount}</div>
            <div className="stat-sub">Dropped by policies</div>
          </div>
          <div className="stat-card stat-success">
            <div className="stat-label">Allowed</div>
            <div className="stat-value">{stats.allowedCount}</div>
            <div className="stat-sub">{stats.uniqueProtocols} protocols</div>
          </div>
        </div>
      )}

      <div className="filters-bar">
        <input
          className="filter-input"
          type="text"
          placeholder='Wireshark-style filter e.g. ip.src == 10.0.1.45 || tcp.port == 80'
          value={filter}
          onChange={e => setFilter(e.target.value)}
          onKeyDown={handleFilterKeyDown}
        />
        <button className="btn btn-sm btn-secondary" onClick={() => { setPage(1); fetchFlows(); }}>Apply</button>
        {filter && (
          <button className="btn btn-sm btn-danger" onClick={() => { setFilter(''); setPage(1); }}>Clear</button>
        )}
      </div>

      {loading ? (
        <div style={{ padding: '60px 0', textAlign: 'center', color: 'var(--text-secondary)' }}>Loading flows...</div>
      ) : (
        <div className="data-table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Dest IP</th>
                <th>Src Port</th>
                <th>Dest Port</th>
                <th>Protocol</th>
                <th>Bytes</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {flows.map(f => (
                <tr key={f.id} className={f.status === 'suspicious' ? 'row-suspicious' : f.status === 'blocked' ? 'row-blocked' : ''}>
                  <td>{timeAgo(f.timestamp)}</td>
                  <td>{f.srcIp}</td>
                  <td>{f.destIp}</td>
                  <td>{f.srcPort}</td>
                  <td>{f.destPort}</td>
                  <td>{protocolTag(f.protocol)}</td>
                  <td>{formatBytes(f.bytes)}</td>
                  <td>{statusTag(f.status)}</td>
                </tr>
              ))}
              {flows.length === 0 && (
                <tr><td colSpan={8} style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>No flows match the filter</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      <div className="filters-bar" style={{ justifyContent: 'flex-end', marginTop: 12 }}>
        <span style={{ color: 'var(--text-secondary)', fontSize: 13, marginRight: 8 }}>
          Page {pagination.page} of {pagination.totalPages} ({pagination.total} flows)
        </span>
        <button className="btn btn-sm btn-secondary" disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))}>Previous</button>
        <button className="btn btn-sm btn-secondary" disabled={page >= pagination.totalPages} onClick={() => setPage(p => p + 1)}>Next</button>
      </div>
    </>
  );
}
