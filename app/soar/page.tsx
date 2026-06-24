'use client';

import { useEffect, useState } from 'react';

export default function SoarPage() {
  const [builtins, setBuiltins] = useState<any[]>([]);
  const [executions, setExecutions] = useState<any[]>([]);
  const [playbookId, setPlaybookId] = useState('');
  const [context, setContext] = useState('{}');
  const [statusFilter, setStatusFilter] = useState('');
  const [execResult, setExecResult] = useState<any>(null);

  useEffect(() => {
    fetch('/api/soar/playbooks/builtin').then(r => r.json()).then(setBuiltins).catch(() => {});
    loadExecutions();
  }, []);

  async function loadExecutions() {
    const url = statusFilter ? `/api/soar/executions?status=${statusFilter}` : '/api/soar/executions';
    try { const res = await fetch(url); setExecutions(await res.json()); } catch {}
  }

  useEffect(() => { loadExecutions(); }, [statusFilter]);

  async function handleExecute() {
    if (!playbookId.trim()) return;
    let ctx;
    try { ctx = JSON.parse(context); } catch { alert('Invalid JSON context'); return; }
    const res = await fetch('/api/soar/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ playbookId: playbookId.trim(), context: ctx }),
    });
    if (res.ok) { setExecResult(await res.json()); loadExecutions(); }
  }

  async function handleStop(execId: string) {
    await fetch(`/api/soar/stop/${execId}`, { method: 'POST' });
    loadExecutions();
  }

  async function handleClear() {
    await fetch('/api/soar/executions', { method: 'DELETE' });
    setExecutions([]);
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2>SOAR Automation</h2>
          <div className="subtitle">Security Orchestration, Automation, and Response playbook engine</div>
        </div>
      </div>

      <div className="charts-row">
        <div className="card">
          <div className="card-header"><div className="card-title">Execute Playbook</div></div>
          <div className="form-container">
            <div className="form-group"><label>Playbook ID / Name</label><input className="form-control" value={playbookId} onChange={e => setPlaybookId(e.target.value)} placeholder="e.g. c2-containment or 1" /></div>
            <div className="form-group"><label>Context (JSON)</label><textarea className="form-control" rows={4} value={context} onChange={e => setContext(e.target.value)} /></div>
            <button className="btn btn-primary" onClick={handleExecute}>Execute Playbook</button>
            {execResult && <pre style={{ marginTop: 12, background: 'var(--bg-secondary)', padding: 12, borderRadius: 6, fontSize: 12 }}>{JSON.stringify(execResult, null, 2)}</pre>}
          </div>
        </div>
        <div className="card">
          <div className="card-header"><div className="card-title">Built-in Playbooks</div></div>
          <div className="groups-container">
            {builtins.map((pb: any, i: number) => (
              <div key={i} className="group-section">
                <div className="group-header">
                  <span className={`tag tag-${pb.severity?.toLowerCase() || 'info'}`}>{pb.severity || 'Info'}</span>
                  {pb.name}
                </div>
                <div className="group-items">
                  {pb.description && <div style={{ padding: '8px 16px', fontSize: 12, color: 'var(--text-secondary)' }}>{pb.description}</div>}
                  {pb.steps?.map((s: any, j: number) => (
                    <div key={j} className="group-item">
                      <div className="item-main"><div className="item-title">Step {s.order}: {s.action}</div><div className="item-meta">{s.assignee} — {s.duration}</div></div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">Executions ({executions.length})</div>
          <div className="header-actions">
            <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
              <option value="">All</option>
              <option value="running">Running</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="stopped">Stopped</option>
            </select>
            <button className="btn btn-danger btn-sm" onClick={handleClear}>Clear All</button>
          </div>
        </div>
        <div className="data-table-wrapper">
          <table className="data-table">
            <thead><tr><th>ID</th><th>Playbook</th><th>Status</th><th>Started</th><th>Actions</th></tr></thead>
            <tbody>
              {executions.map((e: any) => (
                <tr key={e.id || e.executionId}>
                  <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{e.id || e.executionId}</td>
                  <td>{e.playbook || e.playbookName}</td>
                  <td><span className={`tag ${e.status === 'completed' ? 'tag-done' : e.status === 'running' ? 'tag-in-progress' : e.status === 'failed' ? 'tag-critical' : 'tag-todo'}`}>{e.status}</span></td>
                  <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{e.startedAt ? new Date(e.startedAt).toLocaleString() : '-'}</td>
                  <td>{e.status === 'running' && <button className="btn btn-danger btn-sm" onClick={() => handleStop(e.id || e.executionId)}>Stop</button>}</td>
                </tr>
              ))}
              {executions.length === 0 && <tr><td colSpan={5} style={{ textAlign: 'center', padding: 24, color: 'var(--text-secondary)' }}>No executions</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
