'use client';

import { useEffect, useState } from 'react';

export default function PcapAnalysisPage() {
  const [captures, setCaptures] = useState<any[]>([]);
  const [status, setStatus] = useState<any>(null);
  const [interfaces, setInterfaces] = useState<any[]>([]);
  const [selectedIface, setSelectedIface] = useState('');
  const [duration, setDuration] = useState('30');
  const [uploading, setUploading] = useState(false);
  const [capturing, setCapturing] = useState(false);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    fetch('/api/pcap/captures').then(r => r.json()).then(d => setCaptures(d.items || [])).catch(() => {});
    fetch('/api/pcap/status').then(r => r.json()).then(setStatus).catch(() => {});
    fetch('/api/capture/interfaces').then(r => r.json()).then(d => { setInterfaces(d.interfaces || []); if (d.interfaces?.length) setSelectedIface(d.interfaces[0].name || d.interfaces[0]); }).catch(() => {});
  }, []);

  async function handleUpload(e: React.FormEvent) {
    e.preventDefault();
    const input = document.getElementById('pcap-file') as HTMLInputElement;
    if (!input.files?.length) return;
    setUploading(true);
    setMsg('');
    const fd = new FormData();
    fd.append('pcap', input.files[0]);
    try {
      const res = await fetch('/api/pcap/upload', { method: 'POST', body: fd });
      if (res.ok) {
        setMsg('Upload successful');
        const data = await res.json();
        setCaptures(prev => [data, ...prev]);
      } else {
        const err = await res.json(); setMsg(err.error || 'Upload failed');
      }
    } catch { setMsg('Upload failed'); }
    finally { setUploading(false); }
  }

  async function handleStartCapture() {
    if (!selectedIface) return;
    setCapturing(true);
    setMsg('');
    try {
      const res = await fetch('/api/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: selectedIface, duration: parseInt(duration) || 30 }),
      });
      if (res.ok) {
        setMsg('Capture started');
        setCaptures([await res.json(), ...captures]);
      } else {
        const err = await res.json(); setMsg(err.error || 'Capture failed');
      }
    } catch { setMsg('Capture failed'); }
    finally { setCapturing(false); }
  }

  async function handleStopCapture() {
    setMsg('');
    try {
      const res = await fetch('/api/capture/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ captureId: 0 }),
      });
      if (res.ok) setMsg('Capture stopped');
      else { const err = await res.json(); setMsg(err.error || 'Stop failed'); }
    } catch { setMsg('Stop failed'); }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2>PCAP Analysis</h2>
          <div className="subtitle">Upload, capture, and analyze network traffic</div>
        </div>
      </div>

      {msg && (
        <div className="toast" style={{ position: 'static', marginBottom: 16 }}>
          {msg}
        </div>
      )}

      <div className="charts-row">
        <div className="card">
          <div className="card-header"><div className="card-title">Upload PCAP</div></div>
          <form onSubmit={handleUpload} className="form-container">
            <div className="form-group">
              <label>PCAP File (.pcap, .pcapng, .cap)</label>
              <input type="file" id="pcap-file" accept=".pcap,.pcapng,.cap" className="form-control" required />
            </div>
            <button type="submit" className="btn btn-primary" disabled={uploading}>
              {uploading ? 'Uploading...' : 'Upload'}
            </button>
          </form>
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Live Capture</div></div>
          <div className="form-container">
            <div className="form-group">
              <label>Interface</label>
              <select className="form-control filter-select" value={selectedIface} onChange={e => setSelectedIface(e.target.value)}>
                <option value="">-- Select Interface --</option>
                {interfaces.map((iface, i) => (
                  <option key={i} value={iface.name || iface}>{iface.name || iface}</option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label>Duration (seconds)</label>
              <input type="number" className="form-control" value={duration} onChange={e => setDuration(e.target.value)} min="5" max="3600" />
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-primary" onClick={handleStartCapture} disabled={capturing || !selectedIface}>
                {capturing ? 'Starting...' : 'Start Capture'}
              </button>
              <button className="btn btn-danger" onClick={handleStopCapture}>Stop</button>
            </div>
          </div>
        </div>
      </div>

      {status && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header"><div className="card-title">TShark Status</div></div>
          <div style={{ display: 'flex', gap: 24 }}>
            <div><span className="stat-label">Available: </span><strong>{status.tsharkAvailable ? 'Yes' : 'No'}</strong></div>
            <div><span className="stat-label">Path: </span><strong>{status.tsharkPath || 'N/A'}</strong></div>
            <div><span className="stat-label">Capture Count: </span><strong>{status.captureCount}</strong></div>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header"><div className="card-title">Captures ({captures.length})</div></div>
        <div className="data-table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Filename</th>
                <th>Size</th>
                <th>Packets</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {captures.map((c: any, i: number) => (
                <tr key={c.id ?? `capture-${i}`}>
                  <td>{c.id}</td>
                  <td>{c.originalName || c.filename}</td>
                  <td>{c.size ? (c.size / 1024).toFixed(1) + ' KB' : '-'}</td>
                  <td>{c.packets ?? '-'}</td>
                  <td>{c.createdAt ? new Date(c.createdAt).toLocaleString() : '-'}</td>
                </tr>
              ))}
              {captures.length === 0 && (
                <tr><td colSpan={5} style={{ textAlign: 'center', padding: 24, color: 'var(--text-secondary)' }}>No captures yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
