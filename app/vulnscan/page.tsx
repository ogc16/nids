'use client';

import { useEffect, useState } from 'react';

export default function VulnscanPage() {
  const [targets, setTargets] = useState('');
  const [scans, setScans] = useState<any[]>([]);
  const [vulns, setVulns] = useState<any[]>([]);
  const [severityFilter, setSeverityFilter] = useState('');
  const [assetId, setAssetId] = useState('');
  const [assessment, setAssessment] = useState<any>(null);
  const [scanning, setScanning] = useState(false);
  const [assessing, setAssessing] = useState(false);
  const [msg, setMsg] = useState('');

  const fetchVulns = (sev: string) => {
    const params = sev ? `?severity=${sev}` : '';
    fetch(`/api/vulnscan/vulnerabilities${params}`).then(r => r.json()).then(setVulns).catch(() => {});
  };

  useEffect(() => {
    fetch('/api/vulnscan/scans').then(r => r.json()).then(d => setScans(Array.isArray(d) ? d : d.items || [])).catch(() => {});
    fetchVulns('');
  }, []);

  async function handleStartScan() {
    if (!targets.trim()) return;
    setScanning(true);
    setMsg('');
    try {
      const res = await fetch('/api/vulnscan/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targets: targets.split(',').map(t => t.trim()) }),
      });
      if (res.ok) {
        const data = await res.json();
        setMsg(`Scan started (ID: ${data.scanId})`);
        setScans(prev => [data, ...prev]);
      } else {
        const err = await res.json(); setMsg(err.error || 'Scan failed');
      }
    } catch { setMsg('Scan failed'); }
    finally { setScanning(false); }
  }

  async function handleAssess() {
    if (!assetId.trim()) return;
    setAssessing(true);
    setMsg('');
    try {
      const res = await fetch('/api/vulnscan/assess-asset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assetId: assetId }),
      });
      if (res.ok) setAssessment(await res.json());
      else { const err = await res.json(); setMsg(err.error || 'Assessment failed'); }
    } catch { setMsg('Assessment failed'); }
    finally { setAssessing(false); }
  }

  function handleSeverityChange(sev: string) {
    setSeverityFilter(sev);
    fetchVulns(sev);
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2>Vulnerability Scanner</h2>
          <div className="subtitle">Scan, assess, and manage vulnerabilities</div>
        </div>
      </div>

      {msg && (
        <div className="toast" style={{ position: 'static', marginBottom: 16 }}>
          {msg}
        </div>
      )}

      <div className="charts-row">
        <div className="card">
          <div className="card-header"><div className="card-title">New Scan</div></div>
          <div className="form-container">
            <div className="form-group">
              <label>Targets (comma separated IPs/hosts)</label>
              <input className="form-control" value={targets} onChange={e => setTargets(e.target.value)} placeholder="10.0.1.45, 10.0.1.50" />
            </div>
            <button className="btn btn-primary" onClick={handleStartScan} disabled={scanning}>
              {scanning ? 'Scanning...' : 'Start Scan'}
            </button>
          </div>
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Asset Assessment</div></div>
          <div className="form-container">
            <div className="form-group">
              <label>Asset ID</label>
              <input className="form-control" value={assetId} onChange={e => setAssetId(e.target.value)} placeholder="Enter asset ID" />
            </div>
            <button className="btn btn-primary" onClick={handleAssess} disabled={assessing}>
              {assessing ? 'Assessing...' : 'Assess'}
            </button>
            {assessment && (
              <pre style={{ marginTop: 12, background: 'var(--bg-secondary)', padding: 12, borderRadius: 6, fontSize: 12, overflow: 'auto' }}>
                {JSON.stringify(assessment, null, 2)}
              </pre>
            )}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-header">
          <div className="card-title">Vulnerability Database ({vulns.length})</div>
          <div className="header-actions">
            {['', 'Critical', 'High', 'Medium', 'Low'].map(sev => (
              <button key={sev} className={`btn btn-sm ${severityFilter === sev ? 'btn-primary' : 'btn-secondary'}`} onClick={() => handleSeverityChange(sev)}>
                {sev || 'All'}
              </button>
            ))}
          </div>
        </div>
        <div className="data-table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Severity</th>
                <th>Description</th>
                <th>Score</th>
              </tr>
            </thead>
            <tbody>
              {vulns.map((v: any, i: number) => (
                <tr key={i}>
                  <td>{v.id}</td>
                  <td><span className={`tag tag-${v.severity?.toLowerCase()}`}>{v.severity}</span></td>
                  <td>{v.description || v.name}</td>
                  <td>{v.score ?? v.cvss ?? '-'}</td>
                </tr>
              ))}
              {vulns.length === 0 && (
                <tr><td colSpan={4} style={{ textAlign: 'center', padding: 24, color: 'var(--text-secondary)' }}>No vulnerabilities found</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <div className="card-header"><div className="card-title">Scan History ({scans.length})</div></div>
        <div className="data-table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Targets</th>
                <th>Status</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s: any, i: number) => (
                <tr key={i}>
                  <td>{s.scanId || s.id}</td>
                  <td>{Array.isArray(s.targets) ? s.targets.join(', ') : s.targets}</td>
                  <td><span className={`tag ${s.status === 'running' ? 'tag-in-progress' : s.status === 'completed' ? 'tag-done' : 'tag-todo'}`}>{s.status}</span></td>
                  <td>{s.startedAt || s.createdAt ? new Date(s.startedAt || s.createdAt).toLocaleString() : '-'}</td>
                </tr>
              ))}
              {scans.length === 0 && (
                <tr><td colSpan={4} style={{ textAlign: 'center', padding: 24, color: 'var(--text-secondary)' }}>No scans yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
