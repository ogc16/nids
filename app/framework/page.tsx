'use client';

import { useEffect, useState } from 'react';

export default function FrameworkPage() {
  const [csf, setCsf] = useState<any[]>([]);

  useEffect(() => {
    fetch('/api/framework/csf').then(r => r.json()).then(setCsf).catch(() => {});
  }, []);

  return (
    <>
      <div className="page-header">
        <div>
          <h2>NIST Cybersecurity Framework</h2>
          <div className="subtitle">Govern, Identify, Protect, Detect, Respond, Recover</div>
        </div>
      </div>

      <div className="dashboard-grid">
        {csf.map((fn: any) => (
          <div key={fn.id} className="card" style={{ borderTop: `3px solid ${
            fn.id === 'GV' ? 'var(--accent-purple)' :
            fn.id === 'ID' ? 'var(--accent-blue)' :
            fn.id === 'PR' ? 'var(--accent-green)' :
            fn.id === 'DE' ? 'var(--accent-orange)' :
            fn.id === 'RS' ? 'var(--accent-red)' :
            'var(--accent-cyan)'
          }` }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span className={`tag tag-csf-${fn.id.toLowerCase()}`}>{fn.id}</span>
              <strong>{fn.name}</strong>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>{fn.desc}</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <div><span className="stat-label">Incidents</span><div style={{ fontSize: 20, fontWeight: 700, color: 'var(--accent-orange)' }}>{fn.incidentCount || 0}</div></div>
              <div><span className="stat-label">Rules</span><div style={{ fontSize: 20, fontWeight: 700, color: 'var(--accent-blue)' }}>{fn.ruleCount || 0}</div></div>
              <div><span className="stat-label">Playbooks</span><div style={{ fontSize: 20, fontWeight: 700, color: 'var(--accent-cyan)' }}>{fn.playbookCount || 0}</div></div>
              <div><span className="stat-label">Policies</span><div style={{ fontSize: 20, fontWeight: 700, color: 'var(--accent-green)' }}>{fn.policyCount || 0}</div></div>
              <div style={{ gridColumn: '1/-1' }}><span className="stat-label">Standards</span><div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary)' }}>{fn.standardCount || 0}</div></div>
            </div>
          </div>
        ))}
        {csf.length === 0 && (
          <div className="card" style={{ gridColumn: '1/-1', textAlign: 'center', padding: 40 }}>
            <div className="empty-state"><h3>Loading CSF framework...</h3></div>
          </div>
        )}
      </div>
    </>
  );
}
