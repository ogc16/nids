'use client';

import { useEffect, useState, useCallback } from 'react';

interface SystemInfo {
  hostname?: string;
  platform?: string;
  os?: string;
  uptime?: number;
  cpuModel?: string;
  cpuCores?: number;
  cpuUsage?: number;
  totalMemory?: number;
  freeMemory?: number;
  usedMemory?: number;
  memoryPercent?: number;
  totalDisk?: number;
  freeDisk?: number;
  usedDisk?: number;
}

interface Interface {
  name?: string;
  ip?: string;
  mac?: string;
  rxBytes?: number;
  txBytes?: number;
  rxPackets?: number;
  txPackets?: number;
  rxErrors?: number;
  txErrors?: number;
  mtu?: number;
  operstate?: string;
  speed?: number;
}

interface Connection {
  protocol?: string;
  localAddress?: string;
  localPort?: number;
  remoteAddress?: string;
  remotePort?: number;
  state?: string;
  pid?: number;
  processName?: string;
}

interface Port {
  port: number;
  protocol?: string;
  address?: string;
  processName?: string;
  pid?: number;
}

interface Bandwidth {
  interface?: string;
  rxSpeed?: number;
  txSpeed?: number;
  timestamp?: string;
}

interface ArpEntry {
  ip: string;
  mac: string;
  interface?: string;
  vendor?: string;
}

function formatBytes(b: number) {
  if (b >= 1e12) return (b / 1e12).toFixed(1) + ' TB';
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
}

function formatBits(b: number) {
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' Gbps';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' Mbps';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' Kbps';
  return b + ' bps';
}

function formatUptime(s: number) {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${d}d ${h}h ${m}m`;
}

export default function HostMonitoringPage() {
  const [system, setSystem] = useState<SystemInfo | null>(null);
  const [interfaces, setInterfaces] = useState<Interface[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [ports, setPorts] = useState<Port[]>([]);
  const [bandwidth, setBandwidth] = useState<Bandwidth[]>([]);
  const [arp, setArp] = useState<ArpEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [subnet, setSubnet] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [sys, ints, conns, prts, bw, arpTable] = await Promise.all([
        fetch('/api/monitor/system').then(r => r.json()),
        fetch('/api/monitor/interfaces').then(r => r.json()),
        fetch('/api/monitor/connections').then(r => r.json()),
        fetch('/api/monitor/ports').then(r => r.json()),
        fetch('/api/monitor/bandwidth').then(r => r.json()),
        fetch('/api/monitor/arp').then(r => r.json()),
      ]);
      setSystem(sys);
      setInterfaces(Array.isArray(ints) ? ints : []);
      setConnections(Array.isArray(conns) ? conns : []);
      setPorts(Array.isArray(prts) ? prts : []);
      setBandwidth(Array.isArray(bw) ? bw : []);
      setArp(Array.isArray(arpTable) ? arpTable : []);
    } catch {
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const handleScan = async () => {
    if (!subnet.trim()) return;
    setScanning(true);
    setScanResult(null);
    try {
      const res = await fetch('/api/monitor/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subnet: subnet.trim() }),
      });
      if (res.ok) setScanResult(await res.json());
    } catch {
    } finally {
      setScanning(false);
    }
  };

  if (loading) {
    return (
      <div style={{ padding: '60px 0', textAlign: 'center', color: 'var(--text-secondary)' }}>
        Loading host monitoring data...
      </div>
    );
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2>Host Monitoring</h2>
          <div className="subtitle">System health, network interfaces, and active connections</div>
        </div>
      </div>

      {system && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header">
            <div className="card-title">System Information</div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 2 }}>Hostname</div>
              <div style={{ fontSize: 14, fontWeight: 600 }}>{system.hostname || 'N/A'}</div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 2 }}>Platform</div>
              <div style={{ fontSize: 14 }}>{system.platform || system.os || 'N/A'}</div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 2 }}>Uptime</div>
              <div style={{ fontSize: 14 }}>{system.uptime ? formatUptime(system.uptime) : 'N/A'}</div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 2 }}>CPU</div>
              <div style={{ fontSize: 14 }}>{system.cpuModel ? system.cpuModel.split(' ').slice(0, 3).join(' ') : 'N/A'} ({system.cpuCores || '?'} cores)</div>
              {system.cpuUsage != null && (
                <div style={{ marginTop: 4, height: 6, background: 'var(--bg-secondary)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${system.cpuUsage}%`, background: system.cpuUsage > 80 ? 'var(--accent-red)' : system.cpuUsage > 50 ? 'var(--accent-orange)' : 'var(--accent-green)', borderRadius: 3 }} />
                </div>
              )}
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 2 }}>Memory</div>
              <div style={{ fontSize: 14 }}>{system.usedMemory != null && system.totalMemory != null ? `${formatBytes(system.usedMemory)} / ${formatBytes(system.totalMemory)}` : 'N/A'}</div>
              {system.memoryPercent != null && (
                <div style={{ marginTop: 4, height: 6, background: 'var(--bg-secondary)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${system.memoryPercent}%`, background: system.memoryPercent > 80 ? 'var(--accent-red)' : system.memoryPercent > 50 ? 'var(--accent-orange)' : 'var(--accent-green)', borderRadius: 3 }} />
                </div>
              )}
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 2 }}>Disk</div>
              <div style={{ fontSize: 14 }}>{system.usedDisk != null && system.totalDisk != null ? `${formatBytes(system.usedDisk)} / ${formatBytes(system.totalDisk)}` : 'N/A'}</div>
            </div>
          </div>
        </div>
      )}

      <div className="charts-row">
        <div className="chart-container">
          <h3>Network Interfaces</h3>
          {interfaces.length > 0 ? (
            <div className="data-table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Interface</th>
                    <th>IP</th>
                    <th>MAC</th>
                    <th>RX</th>
                    <th>TX</th>
                    <th>State</th>
                  </tr>
                </thead>
                <tbody>
                  {interfaces.map((i, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: 'monospace' }}>{i.name || 'N/A'}</td>
                      <td>{i.ip || 'N/A'}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{i.mac || 'N/A'}</td>
                      <td style={{ fontSize: 12 }}>{i.rxBytes != null ? formatBytes(i.rxBytes) : 'N/A'}</td>
                      <td style={{ fontSize: 12 }}>{i.txBytes != null ? formatBytes(i.txBytes) : 'N/A'}</td>
                      <td><span className={`tag ${i.operstate === 'up' ? 'tag-online' : 'tag-offline'}`}>{i.operstate || 'unknown'}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 20, textAlign: 'center' }}>No interface data available</div>
          )}
        </div>
        <div className="chart-container">
          <h3>Active Connections ({connections.length})</h3>
          {connections.length > 0 ? (
            <div className="data-table-wrapper" style={{ border: 'none', borderRadius: 0, maxHeight: 300, overflowY: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Proto</th>
                    <th>Local</th>
                    <th>Remote</th>
                    <th>State</th>
                    <th>PID</th>
                  </tr>
                </thead>
                <tbody>
                  {connections.slice(0, 50).map((c, idx) => (
                    <tr key={idx}>
                      <td><span className={`tag tag-${(c.protocol || 'tcp').toLowerCase()}`}>{c.protocol || 'TCP'}</span></td>
                      <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{c.localAddress}:{c.localPort}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{c.remoteAddress}:{c.remotePort}</td>
                      <td><span className={`tag ${c.state === 'ESTABLISHED' ? 'tag-online' : c.state === 'LISTEN' ? 'tag-active' : c.state === 'TIME_WAIT' ? 'tag-medium' : ''}`}>{c.state || 'N/A'}</span></td>
                      <td style={{ fontSize: 12 }}>{c.pid || '?'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 20, textAlign: 'center' }}>No connection data available</div>
          )}
        </div>
      </div>

      <div className="charts-row">
        <div className="chart-container">
          <h3>Open Ports</h3>
          {ports.length > 0 ? (
            <div className="data-table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Process</th>
                    <th>PID</th>
                  </tr>
                </thead>
                <tbody>
                  {ports.map((p, idx) => (
                    <tr key={idx}>
                      <td style={{ fontWeight: 600 }}>{p.port}</td>
                      <td><span className={`tag tag-${(p.protocol || 'tcp').toLowerCase()}`}>{p.protocol || 'TCP'}</span></td>
                      <td style={{ fontSize: 12 }}>{p.processName || 'N/A'}</td>
                      <td style={{ fontSize: 12 }}>{p.pid || '?'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 20, textAlign: 'center' }}>No port data available</div>
          )}
        </div>
        <div className="chart-container">
          <h3>Bandwidth Usage</h3>
          {bandwidth.length > 0 ? (
            <div>
              {bandwidth.map((b, idx) => (
                <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                  <span style={{ fontFamily: 'monospace', fontSize: 13 }}>{b.interface || 'N/A'}</span>
                  <div style={{ display: 'flex', gap: 16 }}>
                    <span style={{ fontSize: 12, color: 'var(--accent-blue)' }}>RX: {b.rxSpeed != null ? formatBits(b.rxSpeed) : 'N/A'}</span>
                    <span style={{ fontSize: 12, color: 'var(--accent-orange)' }}>TX: {b.txSpeed != null ? formatBits(b.txSpeed) : 'N/A'}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 20, textAlign: 'center' }}>No bandwidth data available</div>
          )}
        </div>
      </div>

      <div className="charts-row">
        <div className="chart-container">
          <h3>ARP Table</h3>
          {arp.length > 0 ? (
            <div className="data-table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Interface</th>
                    <th>Vendor</th>
                  </tr>
                </thead>
                <tbody>
                  {arp.map((a, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: 'monospace' }}>{a.ip}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{a.mac}</td>
                      <td style={{ fontSize: 12 }}>{a.interface || 'N/A'}</td>
                      <td style={{ fontSize: 12 }}>{a.vendor || 'N/A'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 20, textAlign: 'center' }}>No ARP table data available</div>
          )}
        </div>
        <div className="chart-container">
          <h3>Network Scan</h3>
          <div className="form-group">
            <label>Subnet</label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                className="form-control"
                type="text"
                placeholder="e.g. 192.168.1.0/24"
                value={subnet}
                onChange={e => setSubnet(e.target.value)}
              />
              <button className="btn btn-primary" onClick={handleScan} disabled={scanning || !subnet.trim()} style={{ whiteSpace: 'nowrap' }}>
                {scanning ? 'Scanning...' : 'Scan'}
              </button>
            </div>
          </div>
          {scanResult && (
            <div style={{ marginTop: 12 }}>
              <div className="data-table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>IP</th>
                      <th>Reachable</th>
                      <th>Ping</th>
                      <th>Open Ports</th>
                      <th>OS Hint</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Array.isArray(scanResult) ? scanResult.map((s: any, idx: number) => (
                      <tr key={idx}>
                        <td>{s.ip || 'N/A'}</td>
                        <td><span className={`tag ${s.reachable ? 'tag-online' : 'tag-offline'}`}>{s.reachable ? 'Yes' : 'No'}</span></td>
                        <td style={{ fontSize: 12 }}>{s.pingMs != null ? `${s.pingMs}ms` : 'N/A'}</td>
                        <td style={{ fontSize: 12 }}>{Array.isArray(s.openPorts) ? s.openPorts.map((p: any) => p.port).join(', ') : 'N/A'}</td>
                        <td style={{ fontSize: 12 }}>{s.osHints || 'N/A'}</td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center' }}>
                          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{scanResult.ip || 'N/A'}</div>
                          <div><span className={`tag ${scanResult.reachable ? 'tag-online' : 'tag-offline'}`}>{scanResult.reachable ? 'Reachable' : 'Unreachable'}</span></div>
                          <div style={{ fontSize: 12 }}>Ping: {scanResult.pingMs != null ? `${scanResult.pingMs}ms` : 'N/A'} | Ports: {Array.isArray(scanResult.openPorts) ? scanResult.openPorts.length : 0}</div>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
