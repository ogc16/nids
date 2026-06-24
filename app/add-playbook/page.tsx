'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function AddPlaybookPage() {
  const router = useRouter();
  const [name, setName] = useState('');
  const [category, setCategory] = useState('Incident Response');
  const [severity, setSeverity] = useState('Medium');
  const [description, setDescription] = useState('');
  const [triggerOnAttackTypes, setTriggerOnAttackTypes] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ success?: boolean; message?: string } | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setResult(null);
    try {
      const res = await fetch('/api/playbooks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim(),
          category,
          severity,
          description: description.trim(),
          triggerOnAttackTypes: triggerOnAttackTypes.split(',').map(t => t.trim()).filter(Boolean),
          status: 'Active',
          steps: [],
          runCount: 0,
        }),
      });
      if (res.ok) {
        setResult({ success: true, message: 'Playbook added successfully' });
        setName(''); setDescription(''); setTriggerOnAttackTypes('');
        setTimeout(() => router.push('/playbooks'), 1500);
      } else {
        const err = await res.json();
        setResult({ success: false, message: err.error || 'Failed to add playbook' });
      }
    } catch {
      setResult({ success: false, message: 'Network error' });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2>Add Playbook</h2>
          <div className="subtitle">Create a new automation playbook</div>
        </div>
      </div>

      {result && (
        <div className={`toast ${result.success ? 'toast-success' : 'toast-error'}`} style={{ position: 'static', marginBottom: 16 }}>
          {result.message}
        </div>
      )}

      <div className="card form-container">
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Playbook Name</label>
            <input className="form-control" value={name} onChange={e => setName(e.target.value)} placeholder="C2 Containment" required />
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Category</label>
              <select className="form-control filter-select" value={category} onChange={e => setCategory(e.target.value)}>
                <option value="Incident Response">Incident Response</option>
                <option value="Threat Hunting">Threat Hunting</option>
                <option value="Forensics">Forensics</option>
                <option value="Remediation">Remediation</option>
              </select>
            </div>
            <div className="form-group">
              <label>Severity</label>
              <select className="form-control filter-select" value={severity} onChange={e => setSeverity(e.target.value)}>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
          </div>
          <div className="form-group">
            <label>Description</label>
            <textarea className="form-control" rows={3} value={description} onChange={e => setDescription(e.target.value)} placeholder="Isolate and investigate C2 communication..." />
          </div>
          <div className="form-group">
            <label>Trigger On Attack Types (comma separated)</label>
            <input className="form-control" value={triggerOnAttackTypes} onChange={e => setTriggerOnAttackTypes(e.target.value)} placeholder="C2 Communication, SQL Injection" />
            <div className="hint">Playbook will be suggested when an incident matches these attack types</div>
          </div>
          <div className="form-actions">
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? 'Adding...' : 'Add Playbook'}
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => router.back()}>Cancel</button>
          </div>
        </form>
      </div>
    </>
  );
}
