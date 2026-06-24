'use client';

import { useEffect, useState } from 'react';
import { PageHeader, Card, Tag, DataTable, ChartsRow } from '@/components';

export default function AgentsPage() {
  const [agents, setAgents] = useState<any[]>([]);
  const [form, setForm] = useState({ type: 'linux', host: '', port: '22', username: 'root' });
  const [subnet, setSubnet] = useState('');
  const [discovered, setDiscovered] = useState<any[]>([]);
  const [collecting, setCollecting] = useState(false);
  const [serverStatus, setServerStatus] = useState<string | null>(null);
  const [serverPort, setServerPort] = useState('9100');

  useEffect(() => { loadAgents(); }, []);

  async function loadAgents() {
    try { const res = await fetch('/api/agents'); setAgents(await res.json()); } catch {}
  }

  async function handleRegister() {
    const res = await fetch('/api/agents/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...form, port: parseInt(form.port) }),
    });
    if (res.ok) { loadAgents(); setForm({ type: 'linux', host: '', port: '22', username: 'root' }); }
  }

  async function handleDelete(id: string) {
    await fetch(`/api/agents/${id}`, { method: 'DELETE' });
    loadAgents();
  }

  async function handleCollect() {
    setCollecting(true);
    const res = await fetch('/api/agents/collect', { method: 'POST' });
    const data = await res.json();
    alert(`Collection complete: ${JSON.stringify(data)}`);
    setCollecting(false);
  }

  async function handleDiscover() {
    if (!subnet.trim()) return;
    const res = await fetch('/api/agents/discover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subnet }),
    });
    setDiscovered(await res.json());
  }

  async function handleServerStart() {
    const res = await fetch('/api/agents/server/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ port: parseInt(serverPort) }),
    });
    if (res.ok) setServerStatus(`Started on port ${serverPort}`);
  }

  async function handleServerStop() {
    await fetch('/api/agents/server/stop', { method: 'POST' });
    setServerStatus(null);
  }

  const columns = [
    { key: 'id', label: 'ID' },
    { key: 'type', label: 'Type', render: (a: any) => <Tag variant="tag-info">{a.type}</Tag> },
    { key: 'host', label: 'Host', render: (a: any) => <span style={{ fontFamily: 'monospace' }}>{a.host}</span> },
    { key: 'port', label: 'Port' },
    { key: 'username', label: 'Username' },
    { key: 'status', label: 'Status', render: (a: any) => <Tag variant={a.status === 'online' ? 'tag-online' : 'tag-offline'}>{a.status || 'unknown'}</Tag> },
    { key: 'actions', label: 'Actions', render: (a: any) => <button className="btn btn-danger btn-sm" onClick={() => handleDelete(a.id)}>Remove</button> },
  ];

  return (
    <>
      <PageHeader title="Remote Agents" subtitle="Register, discover, and collect data from remote sensors" />

      <ChartsRow>
        <Card title="Register Agent">
          <div className="form-container">
            <div className="form-row">
              <div className="form-group"><label>Type</label><select className="filter-select" value={form.type} onChange={e => setForm(p => ({ ...p, type: e.target.value }))}><option>linux</option><option>windows</option><option>network</option></select></div>
              <div className="form-group"><label>Host</label><input className="form-control" value={form.host} onChange={e => setForm(p => ({ ...p, host: e.target.value }))} placeholder="IP or hostname" /></div>
            </div>
            <div className="form-row">
              <div className="form-group"><label>Port</label><input className="form-control" type="number" value={form.port} onChange={e => setForm(p => ({ ...p, port: e.target.value }))} /></div>
              <div className="form-group"><label>Username</label><input className="form-control" value={form.username} onChange={e => setForm(p => ({ ...p, username: e.target.value }))} /></div>
            </div>
            <button className="btn btn-primary" onClick={handleRegister}>Register Agent</button>
          </div>
        </Card>
        <Card title="Discover Agents">
          <div className="form-container">
            <div className="form-group"><label>Subnet</label><input className="form-control" value={subnet} onChange={e => setSubnet(e.target.value)} placeholder="192.168.1.0/24" /></div>
            <button className="btn btn-primary" onClick={handleDiscover}>Scan Subnet</button>
            {discovered.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <div style={{ fontWeight: 600, marginBottom: 4 }}>Discovered ({discovered.length})</div>
                {discovered.map((d: any, i: number) => <div key={i} style={{ fontSize: 12, padding: '2px 0', color: 'var(--text-secondary)' }}>{d.host || d.ip} — {d.type || 'unknown'}</div>)}
              </div>
            )}
          </div>
        </Card>
      </ChartsRow>

      <Card title="Agent Server" style={{ marginBottom: 16 }}>
        {serverStatus && <div style={{ padding: '0 0 16px', color: 'var(--accent-green)', fontSize: 13 }}>Agent HTTP server: {serverStatus}</div>}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {serverStatus ? (
            <button className="btn btn-danger btn-sm" onClick={handleServerStop}>Stop Server</button>
          ) : (
            <><input className="form-control" style={{ width: 80 }} value={serverPort} onChange={e => setServerPort(e.target.value)} placeholder="Port" /><button className="btn btn-primary btn-sm" onClick={handleServerStart}>Start Server</button></>
          )}
        </div>
      </Card>

      <Card title={`Registered Agents (${agents.length})`}>
        <button className="btn btn-primary btn-sm" style={{ marginBottom: 12 }} onClick={handleCollect} disabled={collecting}>{collecting ? 'Collecting...' : 'Collect from All'}</button>
        <DataTable columns={columns} data={agents} emptyMessage="No agents registered" />
      </Card>
    </>
  );
}
