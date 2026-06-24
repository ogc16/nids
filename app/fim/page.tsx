'use client';

import { useEffect, useState } from 'react';

export default function FimPage() {
  const [baseline, setBaseline] = useState<any>(null);
  const [paths, setPaths] = useState('');
  const [scanResults, setScanResults] = useState<any>(null);
  const [scans, setScans] = useState<any[]>([]);
  const [lastScan, setLastScan] = useState<any>(null);
  const [watching, setWatching] = useState(false);
  const [creating, setCreating] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    fetch('/api/fim/baseline').then(r => r.json()).then(setBaseline).catch(() => {});
    fetch('/api/fim/scans').then(r => r.json()).then(d => setScans(Array.isArray(d) ? d : d.items || [])).catch(() => {});
    fetch('/api/fim/last-scan').then(r => r.json()).then(setLastScan).catch(() => {});
  }, []);

  async function handleCreateBaseline() {
    if (!paths.trim()) return;
    setCreating(true);
    setMsg('');
    try {
      const res = await fetch('/api/fim/baseline', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ paths: paths.split('\n').map(p => p.trim()).filter(Boolean) }),
      });
      if (res.ok) {
        const data = await res.json();
        setBaseline(data.baseline || data);
        setMsg(`Baseline created with ${data.fileCount || (data.baseline || data).length} files`);
      } else {
        const err = await res.json(); setMsg(err.error || 'Failed');
      }
    } catch { setMsg('Failed to create baseline'); }
    finally { setCreating(false); }
  }

  async function handleRunScan() {
    setScanning(true);
    setMsg('');
    try {
      const res = await fetch('/api/fim/scan', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setScanResults(data);
        setMsg('Scan completed');
        fetch('/api/fim/scans').then(r => r.json()).then(d => setScans(Array.isArray(d) ? d : d.items || [])).catch(() => {});
        fetch('/api/fim/last-scan').then(r => r.json()).then(setLastScan).catch(() => {});
      } else {
        const err = await res.json(); setMsg(err.error || 'Scan failed');
      }
    } catch { setMsg('Scan failed'); }
    finally { setScanning(false); }
  }

  async function handleWatchStart() {
    setMsg('');
    try {
      const res = await fetch('/api/fim/watch/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interval: 60 }),
      });
      if (res.ok) { setWatching(true); setMsg('File watcher started'); }
      else { const err = await res.json(); setMsg(err.error || 'Failed'); }
    } catch { setMsg('Failed to start watcher'); }
  }

  async function handleWatchStop() {
    setMsg('');
    try {
      const res = await fetch('/api/fim/watch/stop', { method: 'POST' });
      if (res.ok) { setWatching(false); setMsg('File watcher stopped'); }
      else { const err = await res.json(); setMsg(err.error || 'Failed'); }
    } catch { setMsg('Failed to stop watcher'); }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2>File Integrity Monitoring</h2>
          <div className="subtitle">Baseline, scan, and monitor file changes</div>
        </div>
        <div className="header-actions">
          <button className="btn btn-sm btn-info" onClick={handleWatchStart} disabled={watching}>Start Watcher</button>
          <button className="btn btn-sm btn-danger" onClick={handleWatchStop} disabled={!watching}>Stop Watcher</button>
        </div>
      </div>

      {msg && (
        <div className="toast" style={{ position: 'static', marginBottom: 16 }}>
          {msg}
        </div>
      )}

      <div className="charts-row">
        <div className="card">
          <div className="card-header"><div className="card-title">Create Baseline</div></div>
          <div className="form-container">
            <div className="form-group">
              <label>File/Directory Paths (one per line)</label>
              <textarea className="form-control" rows={4} value={paths} onChange={e => setPaths(e.target.value)} placeholder="C:\app\config.json&#10;C:\app\bin" />
            </div>
            <button className="btn btn-primary" onClick={handleCreateBaseline} disabled={creating}>
              {creating ? 'Creating...' : 'Create Baseline'}
            </button>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Baseline Status</div>
            <button className="btn btn-sm btn-primary" onClick={handleRunScan} disabled={scanning}>
              {scanning ? 'Scanning...' : 'Run Scan'}
            </button>
          </div>
          {baseline ? (
            <div>
              <div style={{ marginBottom: 8 }}><span className="tag tag-active">Baseline exists</span> with {Array.isArray(baseline) ? baseline.length : baseline.fileCount || '?'} entries</div>
              <pre style={{ background: 'var(--bg-secondary)', padding: 12, borderRadius: 6, fontSize: 11, maxHeight: 200, overflow: 'auto' }}>
                {JSON.stringify(baseline, null, 2)}
              </pre>
            </div>
          ) : (
            <div className="empty-state" style={{ padding: 20 }}>
              <div>No baseline created yet</div>
            </div>
          )}
        </div>
      </div>

      {scanResults && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header"><div className="card-title">Scan Results</div></div>
          <pre style={{ background: 'var(--bg-secondary)', padding: 12, borderRadius: 6, fontSize: 12, maxHeight: 300, overflow: 'auto' }}>
            {JSON.stringify(scanResults, null, 2)}
          </pre>
        </div>
      )}

      {lastScan && lastScan.status !== 'no_scans' && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header"><div className="card-title">Last Scan</div></div>
          <pre style={{ background: 'var(--bg-secondary)', padding: 12, borderRadius: 6, fontSize: 12, overflow: 'auto' }}>
            {JSON.stringify(lastScan, null, 2)}
          </pre>
        </div>
      )}

      <div className="card">
        <div className="card-header"><div className="card-title">Scan History ({scans.length})</div></div>
        <div className="data-table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Changes</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s: any, i: number) => (
                <tr key={i}>
                  <td>{s.id || i + 1}</td>
                  <td>{s.timestamp || s.scannedAt ? new Date(s.timestamp || s.scannedAt).toLocaleString() : '-'}</td>
                  <td>{s.changes ?? s.changeCount ?? s.changedFiles ?? '-'}</td>
                  <td><span className={`tag ${s.status === 'completed' ? 'tag-done' : 'tag-in-progress'}`}>{s.status}</span></td>
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
