'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function SubmitRulePage() {
  const router = useRouter();
  const [name, setName] = useState('');
  const [severity, setSeverity] = useState('Medium');
  const [attackType, setAttackType] = useState('');
  const [ruleLogic, setRuleLogic] = useState('');
  const [status, setStatus] = useState('In Development');
  const [csfFunction, setCsfFunction] = useState('DE');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ success?: boolean; message?: string } | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setResult(null);
    try {
      const res = await fetch('/api/detection-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim(),
          severity,
          attackType: attackType.trim(),
          ruleLogic: ruleLogic.trim(),
          status,
          csfFunction,
          lastUpdated: new Date().toISOString().split('T')[0],
        }),
      });
      if (res.ok) {
        setResult({ success: true, message: 'Rule submitted successfully' });
        setName(''); setAttackType(''); setRuleLogic('');
        setTimeout(() => router.push('/rules'), 1500);
      } else {
        const err = await res.json();
        setResult({ success: false, message: err.error || 'Failed to submit rule' });
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
          <h2>Submit Detection Rule</h2>
          <div className="subtitle">Create a new detection rule</div>
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
            <label>Rule Name</label>
            <input className="form-control" value={name} onChange={e => setName(e.target.value)} placeholder="C2 Beaconing Detection" required />
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
          <div className="form-group">
            <label>Rule Logic (Snort/Suricata syntax)</label>
            <textarea className="form-control" rows={5} value={ruleLogic} onChange={e => setRuleLogic(e.target.value)} placeholder="alert tcp any any -> any any (msg:&quot;C2 Beaconing&quot;; threshold:type both, track by_src, count 5, seconds 60;)" />
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Status</label>
              <select className="form-control filter-select" value={status} onChange={e => setStatus(e.target.value)}>
                <option value="In Development">In Development</option>
                <option value="Active">Active</option>
                <option value="Deprecated">Deprecated</option>
              </select>
            </div>
            <div className="form-group">
              <label>CSF Function</label>
              <select className="form-control filter-select" value={csfFunction} onChange={e => setCsfFunction(e.target.value)}>
                <option value="GV">Govern (GV)</option>
                <option value="ID">Identify (ID)</option>
                <option value="PR">Protect (PR)</option>
                <option value="DE">Detect (DE)</option>
                <option value="RS">Respond (RS)</option>
                <option value="RC">Recover (RC)</option>
              </select>
            </div>
          </div>
          <div className="form-actions">
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? 'Submitting...' : 'Submit Rule'}
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => router.back()}>Cancel</button>
          </div>
        </form>
      </div>
    </>
  );
}
