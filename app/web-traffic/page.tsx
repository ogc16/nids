'use client';

import { useEffect, useState } from 'react';

interface Summary {
  totalRequests: number;
  errorRate: number;
  uniqueUris: number;
  uniqueHosts: number;
  methodDistribution: { method: string; count: number }[];
  statusCodeGroups: { [key: string]: number };
}

interface TopUriItem {
  uri: string;
  count: number;
}

interface TopHostItem {
  host: string;
  count: number;
}

interface ErrorsData {
  totalErrors: number;
  errorRate: number;
  byUri: { uri: string; total: number; '4xx': number; '5xx': number }[];
  byCode: { code: number; count: number }[];
}

export default function WebTrafficPage() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [topUris, setTopUris] = useState<TopUriItem[]>([]);
  const [topHosts, setTopHosts] = useState<TopHostItem[]>([]);
  const [errors, setErrors] = useState<ErrorsData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch('/api/web-traffic/summary').then(r => r.json()),
      fetch('/api/web-traffic/top-uris').then(r => r.json()),
      fetch('/api/web-traffic/top-hosts').then(r => r.json()),
      fetch('/api/web-traffic/errors').then(r => r.json()),
    ])
      .then(([s, u, h, e]) => {
        setSummary(s);
        setTopUris(u);
        setTopHosts(h);
        setErrors(e);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div style={{ padding: '60px 0', textAlign: 'center', color: 'var(--text-secondary)' }}>
        Loading web traffic data...
      </div>
    );
  }

  const maxMethodCount = Math.max(...(summary?.methodDistribution.map(m => m.count) || [1]), 1);

  return (
    <>
      <div className="page-header">
        <div>
          <h2>Web Traffic Analysis</h2>
          <div className="subtitle">HTTP/HTTPS request monitoring and metrics</div>
        </div>
      </div>

      {summary && (
        <div className="dashboard-grid">
          <div className="stat-card stat-info">
            <div className="stat-label">Total Requests</div>
            <div className="stat-value">{summary.totalRequests}</div>
            <div className="stat-sub">All HTTP/HTTPS requests</div>
          </div>
          <div className="stat-card" style={{ borderLeft: '3px solid var(--accent-red)' }}>
            <div className="stat-label">Error Rate</div>
            <div className="stat-value" style={{ color: summary.errorRate > 5 ? 'var(--accent-red)' : summary.errorRate > 1 ? 'var(--accent-orange)' : 'var(--accent-green)' }}>{summary.errorRate}%</div>
            <div className="stat-sub">4xx / 5xx errors</div>
          </div>
          <div className="stat-card stat-success">
            <div className="stat-label">Unique URIs</div>
            <div className="stat-value">{summary.uniqueUris}</div>
            <div className="stat-sub">Endpoints accessed</div>
          </div>
          <div className="stat-card" style={{ borderLeft: '3px solid var(--accent-purple)' }}>
            <div className="stat-label">Unique Hosts</div>
            <div className="stat-value">{summary.uniqueHosts}</div>
            <div className="stat-sub">Hostnames requested</div>
          </div>
        </div>
      )}

      <div className="charts-row">
        <div className="chart-container">
          <h3>Method Distribution</h3>
          {summary?.methodDistribution.map(m => (
            <div key={m.method} style={{ marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ width: 60, fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>{m.method}</span>
              <div style={{ flex: 1, height: 24, background: 'var(--bg-secondary)', borderRadius: 4, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${(m.count / maxMethodCount) * 100}%`, background: 'var(--accent-blue)', borderRadius: 4, transition: 'width 0.3s' }} />
              </div>
              <span style={{ width: 50, textAlign: 'right', fontSize: 12, color: 'var(--text-secondary)' }}>{m.count}</span>
            </div>
          ))}
          {(!summary?.methodDistribution || summary.methodDistribution.length === 0) && (
            <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 20, textAlign: 'center' }}>No method data available</div>
          )}
        </div>
        <div className="chart-container">
          <h3>Status Code Groups</h3>
          {summary?.statusCodeGroups && Object.entries(summary.statusCodeGroups).length > 0 ? (
            <div style={{ display: 'flex', gap: 12, height: 100, alignItems: 'flex-end', paddingTop: 20 }}>
              {Object.entries(summary.statusCodeGroups).map(([code, count]) => {
                const all = Object.values(summary!.statusCodeGroups);
                const max = Math.max(...all, 1);
                const color = code.startsWith('2') ? 'var(--accent-green)' : code.startsWith('3') ? 'var(--accent-blue)' : code.startsWith('4') ? 'var(--accent-orange)' : 'var(--accent-red)';
                return (
                  <div key={code} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                    <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{count}</span>
                    <div style={{ width: '100%', height: `${(count / max) * 100}%`, background: color, borderRadius: '4px 4px 0 0', minHeight: 4 }} />
                    <span style={{ fontSize: 11, fontWeight: 600 }}>{code}</span>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 20, textAlign: 'center' }}>No status data available</div>
          )}
        </div>
      </div>

      <div className="charts-row">
        <div className="chart-container">
          <h3>Top URIs</h3>
          {topUris.length > 0 ? (
            <div>
              {topUris.slice(0, 10).map(u => (
                <div key={u.uri} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(48,54,61,0.3)', fontSize: 12 }}>
                  <span style={{ color: 'var(--accent-blue)', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{u.uri}</span>
                  <span style={{ color: 'var(--text-secondary)', marginLeft: 12 }}>{u.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 20, textAlign: 'center' }}>No URI data available</div>
          )}
        </div>
        <div className="chart-container">
          <h3>Top Hosts</h3>
          {topHosts.length > 0 ? (
            <div>
              {topHosts.slice(0, 10).map(h => (
                <div key={h.host} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(48,54,61,0.3)', fontSize: 12 }}>
                  <span style={{ fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{h.host}</span>
                  <span style={{ color: 'var(--text-secondary)', marginLeft: 12 }}>{h.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 20, textAlign: 'center' }}>No host data available</div>
          )}
        </div>
      </div>

      <div className="chart-container" style={{ marginBottom: 24 }}>
        <h3>Errors Summary</h3>
        {errors ? (
          <div>
            <div className="dashboard-grid" style={{ marginBottom: 16 }}>
              <div className="stat-card stat-critical">
                <div className="stat-label">Total Errors</div>
                <div className="stat-value">{errors.totalErrors}</div>
                <div className="stat-sub">{errors.errorRate}% of all requests</div>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.8 }}>By Status Code</div>
                {errors.byCode.map(e => (
                  <div key={e.code} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', fontSize: 12, borderBottom: '1px solid rgba(48,54,61,0.2)' }}>
                    <span className="tag" style={{ background: e.code >= 500 ? 'rgba(248,81,73,0.15)' : 'rgba(210,153,34,0.15)', color: e.code >= 500 ? 'var(--accent-red)' : 'var(--accent-orange)' }}>{e.code}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>{e.count}</span>
                  </div>
                ))}
              </div>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.8 }}>By URI</div>
                {errors.byUri.slice(0, 10).map(u => (
                  <div key={u.uri} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', fontSize: 12, borderBottom: '1px solid rgba(48,54,61,0.2)' }}>
                    <span style={{ color: 'var(--accent-blue)', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{u.uri}</span>
                    <span style={{ color: 'var(--text-secondary)', marginLeft: 8 }}>{u.total} ({u['4xx']}x4xx, {u['5xx']}x5xx)</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 20, textAlign: 'center' }}>No error data available</div>
        )}
      </div>
    </>
  );
}
