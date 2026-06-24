'use client';

import { useEffect, useState } from 'react';

export default function SyslogPage() {
  const [status, setStatus] = useState<any>({ running: false });
  const [logs, setLogs] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({});
  const [udpPort, setUdpPort] = useState('514');
  const [tcpPort, setTcpPort] = useState('601');
  const [useUdp, setUseUdp] = useState(true);
  const [useTcp, setUseTcp] = useState(false);
  const [windowsEvents, setWindowsEvents] = useState<any[]>([]);
  const [windowsLogs, setWindowsLogs] = useState<any[]>([]);
  const [logName, setLogName] = useState('Security');
  const [maxEvents, setMaxEvents] = useState('100');

  useEffect(() => {
    fetch('/api/syslog/status').then(r => r.json()).then(setStatus).catch(() => {});
    fetch('/api/syslog/stats').then(r => r.json()).then(setStats).catch(() => {});
    loadLogs();
  }, []);

  async function loadLogs() {
    try { const res = await fetch('/api/syslog/logs?limit=50'); setLogs((await res.json()).items || []); } catch {}
  }

  async function handleStart() {
    const res = await fetch('/api/syslog/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ udpPort: parseInt(udpPort), tcpPort: parseInt(tcpPort), udp: useUdp, tcp: useTcp }),
    });
    if (res.ok) { setStatus({ running: true }); loadLogs(); }
  }

  async function handleStop() {
    await fetch('/api/syslog/stop', { method: 'POST' });
    setStatus({ running: false });
  }

  async function handleClear() {
    await fetch('/api/syslog/clear', { method: 'POST' });
    setLogs([]);
  }

  async function loadWindowsEvents() {
    const res = await fetch(`/api/syslog/windows-events?logName=${logName}&maxEvents=${maxEvents}`);
    setWindowsEvents(await res.json());
  }

  async function loadWindowsLogs() {
    const res = await fetch('/api/syslog/windows-logs');
    setWindowsLogs(await res.json());
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2>Log Collection</h2>
          <div className="subtitle">Syslog server management and Windows Event Log collection</div>
        </div>
      </div>

      <div className="charts-row">
        <div className="card">
          <div className="card-header">
            <div className="card-title">Syslog Server</div>
            <span className={`tag ${status.running ? 'tag-online' : 'tag-offline'}`}>{status.running ? 'Running' : 'Stopped'}</span>
          </div>
          <div className="form-container">
            <div className="form-row">
              <div className="form-group"><label><input type="checkbox" checked={useUdp} onChange={e => setUseUdp(e.target.checked)} /> UDP Port</label><input className="form-control" type="number" value={udpPort} onChange={e => setUdpPort(e.target.value)} disabled={!useUdp} /></div>
              <div className="form-group"><label><input type="checkbox" checked={useTcp} onChange={e => setUseTcp(e.target.checked)} /> TCP Port</label><input className="form-control" type="number" value={tcpPort} onChange={e => setTcpPort(e.target.value)} disabled={!useTcp} /></div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              {!status.running ? <button className="btn btn-primary" onClick={handleStart}>Start Server</button> : <button className="btn btn-danger" onClick={handleStop}>Stop Server</button>}
              <button className="btn btn-secondary" onClick={handleClear}>Clear Logs</button>
            </div>
            {stats.totalLogs !== undefined && (
              <div className="dashboard-grid" style={{ marginTop: 16, marginBottom: 0, gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))' }}>
                <div className="stat-card-small"><div className="stat-value">{stats.totalLogs || 0}</div><div className="stat-label">Total</div></div>
                <div className="stat-card-small"><div className="stat-value" style={{ color: 'var(--accent-orange)' }}>{stats.warnings || 0}</div><div className="stat-label">Warnings</div></div>
                <div className="stat-card-small"><div className="stat-value" style={{ color: 'var(--accent-red)' }}>{stats.errors || 0}</div><div className="stat-label">Errors</div></div>
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Windows Events</div></div>
          <div className="form-container">
            <div className="form-row">
              <div className="form-group"><label>Log Name</label><select className="filter-select" value={logName} onChange={e => setLogName(e.target.value)}><option>Security</option><option>System</option><option>Application</option></select></div>
              <div className="form-group"><label>Max Events</label><input className="form-control" type="number" value={maxEvents} onChange={e => setMaxEvents(e.target.value)} /></div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-primary btn-sm" onClick={loadWindowsEvents}>Fetch Events</button>
              <button className="btn btn-info btn-sm" onClick={loadWindowsLogs}>List Logs</button>
            </div>
            {windowsEvents.length > 0 && (
              <div style={{ marginTop: 12, maxHeight: 200, overflow: 'auto', fontSize: 12 }}>
                {windowsEvents.slice(0, 20).map((e: any, i: number) => (
                  <div key={i} style={{ padding: '4px 0', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                    <span style={{ color: 'var(--accent-blue)' }}>[{e.id || e.EventId}]</span> {e.message || e.Message || JSON.stringify(e)}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header"><div className="card-title">Recent Syslog Messages ({logs.length})</div></div>
        <div className="data-table-wrapper" style={{ maxHeight: 400, overflow: 'auto' }}>
          <table className="data-table">
            <thead><tr><th>Timestamp</th><th>Facility</th><th>Severity</th><th>Host</th><th>Message</th></tr></thead>
            <tbody>
              {logs.map((l: any, i: number) => (
                <tr key={i}>
                  <td style={{ fontSize: 12, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>{l.timestamp ? new Date(l.timestamp).toLocaleString() : '-'}</td>
                  <td><span className="tag tag-info">{l.facility || '-'}</span></td>
                  <td><span className={`tag ${l.severity === 'error' || l.severity === 'crit' ? 'tag-critical' : l.severity === 'warn' ? 'tag-high' : 'tag-active'}`}>{l.severity || 'info'}</span></td>
                  <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{l.host || l.hostname || '-'}</td>
                  <td style={{ fontSize: 12, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{l.message || l.msg || JSON.stringify(l)}</td>
                </tr>
              ))}
              {logs.length === 0 && <tr><td colSpan={5} style={{ textAlign: 'center', padding: 24, color: 'var(--text-secondary)' }}>No syslog messages collected</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
