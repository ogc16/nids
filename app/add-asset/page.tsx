'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function AddAssetPage() {
  const router = useRouter();
  const [assetName, setAssetName] = useState('');
  const [ipRange, setIpRange] = useState('');
  const [type, setType] = useState('Server');
  const [riskLevel, setRiskLevel] = useState('Medium');
  const [owner, setOwner] = useState('');
  const [description, setDescription] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ success?: boolean; message?: string } | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setResult(null);
    try {
      const res = await fetch('/api/network-assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          assetName: assetName.trim(),
          ipRange: ipRange.trim(),
          type,
          riskLevel,
          owner: owner.trim(),
          description: description.trim(),
          monitoringStatus: 'Online',
          openIncidentCount: 0,
        }),
      });
      if (res.ok) {
        setResult({ success: true, message: 'Asset added successfully' });
        setAssetName(''); setIpRange(''); setOwner(''); setDescription('');
        setTimeout(() => router.push('/assets'), 1500);
      } else {
        const err = await res.json();
        setResult({ success: false, message: err.error || 'Failed to add asset' });
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
          <h2>Add Network Asset</h2>
          <div className="subtitle">Register a new network asset for monitoring</div>
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
            <label>Asset Name</label>
            <input className="form-control" value={assetName} onChange={e => setAssetName(e.target.value)} placeholder="Core Web Server" required />
          </div>
          <div className="form-group">
            <label>IP Range</label>
            <input className="form-control" value={ipRange} onChange={e => setIpRange(e.target.value)} placeholder="10.0.1.0/24" />
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Type</label>
              <select className="form-control filter-select" value={type} onChange={e => setType(e.target.value)}>
                <option value="Server">Server</option>
                <option value="Firewall">Firewall</option>
                <option value="Workstation">Workstation</option>
                <option value="Network Device">Network Device</option>
                <option value="IoT">IoT</option>
                <option value="Other">Other</option>
              </select>
            </div>
            <div className="form-group">
              <label>Risk Level</label>
              <select className="form-control filter-select" value={riskLevel} onChange={e => setRiskLevel(e.target.value)}>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
          </div>
          <div className="form-group">
            <label>Owner</label>
            <input className="form-control" value={owner} onChange={e => setOwner(e.target.value)} placeholder="Platform Engineering" />
          </div>
          <div className="form-group">
            <label>Description</label>
            <textarea className="form-control" rows={3} value={description} onChange={e => setDescription(e.target.value)} placeholder="Primary web server hosting customer-facing application..." />
          </div>
          <div className="form-actions">
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? 'Adding...' : 'Add Asset'}
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => router.back()}>Cancel</button>
          </div>
        </form>
      </div>
    </>
  );
}
