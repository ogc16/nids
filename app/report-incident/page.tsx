'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function ReportIncidentPage() {
  const router = useRouter();
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState('Medium');
  const [attackType, setAttackType] = useState('');
  const [sourceIp, setSourceIp] = useState('');
  const [assignee, setAssignee] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ success?: boolean; message?: string } | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setResult(null);
    try {
      const res = await fetch('/api/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: title.trim(),
          description: description.trim(),
          severity,
          attackType: attackType.trim(),
          sourceIp: sourceIp.trim(),
          assignee: assignee.trim(),
          status: 'New',
          csfFunction: 'DE',
          detectedAt: new Date().toISOString(),
        }),
      });
      if (res.ok) {
        setResult({ success: true, message: 'Incident reported successfully' });
        setTitle(''); setDescription(''); setAttackType(''); setSourceIp(''); setAssignee('');
        setTimeout(() => router.push('/incidents'), 1500);
      } else {
        const err = await res.json();
        setResult({ success: false, message: err.error || 'Failed to report incident' });
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
          <h2>Report Incident</h2>
          <div className="subtitle">Create a new security incident</div>
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
            <label>Title</label>
            <input className="form-control" value={title} onChange={e => setTitle(e.target.value)} placeholder="Suspicious activity detected" required />
          </div>
          <div className="form-group">
            <label>Description</label>
            <textarea className="form-control" rows={4} value={description} onChange={e => setDescription(e.target.value)} placeholder="Describe the incident..." />
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Severity</label>
              <select className="form-control filter-select" value={severity} onChange={e => setSeverity(e.target.value)}>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
            <div className="form-group">
              <label>Attack Type</label>
              <input className="form-control" value={attackType} onChange={e => setAttackType(e.target.value)} placeholder="C2 Communication" />
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Source IP</label>
              <input className="form-control" value={sourceIp} onChange={e => setSourceIp(e.target.value)} placeholder="10.0.1.45" />
            </div>
            <div className="form-group">
              <label>Assignee</label>
              <input className="form-control" value={assignee} onChange={e => setAssignee(e.target.value)} placeholder="Alice Chen" />
            </div>
          </div>
          <div className="form-actions">
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? 'Submitting...' : 'Submit Incident'}
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => router.back()}>Cancel</button>
          </div>
        </form>
      </div>
    </>
  );
}
