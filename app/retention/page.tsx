'use client';

import { useEffect, useState } from 'react';

export default function RetentionPage() {
  const [policies, setPolicies] = useState<any[]>([]);
  const [report, setReport] = useState<any>(null);
  const [archives, setArchives] = useState<any[]>([]);
  const [holds, setHolds] = useState<any[]>([]);
  const [forecast, setForecast] = useState<any[]>([]);
  const [newPolicy, setNewPolicy] = useState({ name: '', retentionDays: '90', table: 'network-traffic' });
  const [newHold, setNewHold] = useState({ caseName: '', description: '', affectedTables: '' });
  const [running, setRunning] = useState(false);

  useEffect(() => { loadAll(); }, []);

  async function loadAll() {
    try {
      const [p, r, a, h, f] = await Promise.all([
        fetch('/api/retention/policies').then(r => r.json()),
        fetch('/api/retention/report').then(r => r.json()).catch(() => null),
        fetch('/api/retention/archives').then(r => r.json()).catch(() => []),
        fetch('/api/retention/holds').then(r => r.json()).catch(() => []),
        fetch('/api/retention/storage-forecast?days=90').then(r => r.json()).catch(() => []),
      ]);
      setPolicies(p);
      setReport(r);
      setArchives(a);
      setHolds(h);
      setForecast(f);
    } catch {}
  }

  async function addPolicy() {
    const res = await fetch('/api/retention/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...newPolicy, retentionDays: parseInt(newPolicy.retentionDays) }),
    });
    if (res.ok) { setNewPolicy({ name: '', retentionDays: '90', table: 'network-traffic' }); loadAll(); }
  }

  async function deletePolicy(id: string) {
    await fetch(`/api/retention/policies/${id}`, { method: 'DELETE' });
    loadAll();
  }

  async function runNow() {
    setRunning(true);
    await fetch('/api/retention/run', { method: 'POST' });
    setRunning(false);
    loadAll();
  }

  async function addHold() {
    const res = await fetch('/api/retention/holds', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...newHold, affectedTables: newHold.affectedTables.split(',').map((s: string) => s.trim()) }),
    });
    if (res.ok) { setNewHold({ caseName: '', description: '', affectedTables: '' }); loadAll(); }
  }

  async function deleteHold(id: string) {
    await fetch(`/api/retention/holds/${id}`, { method: 'DELETE' });
    loadAll();
  }

  const maxForecast = forecast.length > 0 ? Math.max(...forecast.map((f: any) => f.size || f.estimatedSize || 0)) : 1;

  return (
    <>
      <div className="page-header">
        <div>
          <h2>Data Retention</h2>
          <div className="subtitle">Manage retention policies, archives, and legal holds</div>
        </div>
        <button className="btn btn-primary" onClick={runNow} disabled={running}>{running ? 'Running...' : 'Run Now'}</button>
      </div>

      {report && (
        <div className="dashboard-grid" style={{ marginBottom: 16 }}>
          <div className="stat-card stat-info"><div className="stat-label">Total Records</div><div className="stat-value">{report.totalRecords || 0}</div></div>
          <div className="stat-card stat-success"><div className="stat-label">Archived</div><div className="stat-value">{report.archived || 0}</div></div>
          <div className="stat-card stat-critical"><div className="stat-label">Purged</div><div className="stat-value">{report.purged || 0}</div></div>
          <div className="stat-card"><div className="stat-label">Policies</div><div className="stat-value">{report.policyCount || policies.length}</div></div>
        </div>
      )}

      <div className="charts-row">
        <div className="card">
          <div className="card-header"><div className="card-title">Policies ({policies.length})</div></div>
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead><tr><th>ID</th><th>Name</th><th>Table</th><th>Retention (days)</th><th>Actions</th></tr></thead>
              <tbody>
                {policies.map((p: any) => (
                  <tr key={p.id}>
                    <td>{p.id}</td>
                    <td>{p.name}</td>
                    <td><span className="tag tag-info">{p.table || p.targetTable}</span></td>
                    <td>{p.retentionDays || p.retention}</td>
                    <td><button className="btn btn-danger btn-sm" onClick={() => deletePolicy(p.id)}>Delete</button></td>
                  </tr>
                ))}
                {policies.length === 0 && <tr><td colSpan={5} style={{ textAlign: 'center', padding: 24, color: 'var(--text-secondary)' }}>No policies defined</td></tr>}
              </tbody>
            </table>
          </div>
          <div style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 8 }}>Add Policy</div>
            <div className="form-row">
              <div className="form-group"><input className="form-control" placeholder="Policy name" value={newPolicy.name} onChange={e => setNewPolicy(p => ({ ...p, name: e.target.value }))} /></div>
              <div className="form-group"><input className="form-control" type="number" placeholder="Retention days" value={newPolicy.retentionDays} onChange={e => setNewPolicy(p => ({ ...p, retentionDays: e.target.value }))} /></div>
              <div className="form-group"><select className="filter-select" value={newPolicy.table} onChange={e => setNewPolicy(p => ({ ...p, table: e.target.value }))}><option>network-traffic</option><option>incidents</option><option>detection-rules</option><option>threat-intel</option><option>engineering-tasks</option></select></div>
              <div className="form-group"><button className="btn btn-primary btn-sm" onClick={addPolicy}>Add</button></div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Legal Holds ({holds.length})</div></div>
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead><tr><th>ID</th><th>Case Name</th><th>Tables</th><th>Actions</th></tr></thead>
              <tbody>
                {holds.map((h: any) => (
                  <tr key={h.id}>
                    <td>{h.id}</td>
                    <td>{h.caseName}</td>
                    <td>{(h.affectedTables || []).join(', ')}</td>
                    <td><button className="btn btn-danger btn-sm" onClick={() => deleteHold(h.id)}>Release</button></td>
                  </tr>
                ))}
                {holds.length === 0 && <tr><td colSpan={4} style={{ textAlign: 'center', padding: 24, color: 'var(--text-secondary)' }}>No legal holds</td></tr>}
              </tbody>
            </table>
          </div>
          <div style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 8 }}>Add Legal Hold</div>
            <div className="form-row">
              <div className="form-group"><input className="form-control" placeholder="Case name" value={newHold.caseName} onChange={e => setNewHold(p => ({ ...p, caseName: e.target.value }))} /></div>
              <div className="form-group"><input className="form-control" placeholder="Affected tables (comma)" value={newHold.affectedTables} onChange={e => setNewHold(p => ({ ...p, affectedTables: e.target.value }))} /></div>
              <div className="form-group"><button className="btn btn-primary btn-sm" onClick={addHold}>Add Hold</button></div>
            </div>
          </div>
        </div>
      </div>

      {archives.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header"><div className="card-title">Archives ({archives.length})</div></div>
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead><tr><th>ID</th><th>Table</th><th>Created</th><th>Size</th></tr></thead>
              <tbody>
                {archives.map((a: any) => (
                  <tr key={a.id}>
                    <td>{a.id}</td>
                    <td><span className="tag tag-info">{a.table}</span></td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{a.createdAt ? new Date(a.createdAt).toLocaleString() : '-'}</td>
                    <td>{a.size ? `${(a.size / 1024).toFixed(1)} KB` : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {forecast.length > 0 && (
        <div className="card">
          <div className="card-header"><div className="card-title">Storage Forecast (90 days)</div></div>
          <div style={{ display: 'flex', gap: 2, alignItems: 'flex-end', height: 100, padding: '8px 0' }}>
            {forecast.map((f: any, i: number) => {
              const val = f.size || f.estimatedSize || 0;
              const pct = maxForecast > 0 ? (val / maxForecast) * 100 : 0;
              return (
                <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <div style={{ width: '100%', height: Math.max(4, pct), background: 'var(--accent-blue)', borderRadius: '2px 2px 0 0', minHeight: 4 }} title={`Day ${f.day || i}: ${(val / 1024 / 1024).toFixed(1)} MB`}></div>
                  {i % 15 === 0 && <span style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 2 }}>d{f.day || i}</span>}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </>
  );
}
