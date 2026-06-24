'use client';

import { useEffect, useState } from 'react';

export default function SecurityPlanPage() {
  const [policies, setPolicies] = useState<any[]>([]);
  const [standards, setStandards] = useState<any[]>([]);
  const [tab, setTab] = useState('policies');

  useEffect(() => {
    fetch('/api/security-policies').then(r => r.json()).then(d => setPolicies(Array.isArray(d) ? d : d.items || d.policies || [])).catch(() => {});
    fetch('/api/security-standards').then(r => r.json()).then(d => setStandards(Array.isArray(d) ? d : d.items || d.standards || [])).catch(() => {});
  }, []);

  const data = tab === 'policies' ? policies : standards;

  return (
    <>
      <div className="page-header">
        <div>
          <h2>Policies & Standards</h2>
          <div className="subtitle">Security policies and compliance standards</div>
        </div>
      </div>

      <div className="filters-bar">
        <button className={`btn btn-sm ${tab === 'policies' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setTab('policies')}>
          Policies ({policies.length})
        </button>
        <button className={`btn btn-sm ${tab === 'standards' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setTab('standards')}>
          Standards ({standards.length})
        </button>
      </div>

      <div className="data-table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Category</th>
              <th>Status</th>
              <th>Version</th>
              <th>CSF Function</th>
              <th>Created By</th>
            </tr>
          </thead>
          <tbody>
            {data.map((item: any) => (
              <tr key={item.id}>
                <td>{item.id}</td>
                <td className="clickable">{item.name}</td>
                <td><span className="tag">{item.category}</span></td>
                <td><span className={`tag tag-${(item.status || '').toLowerCase().replace(/\s+/g, '-')}`}>{item.status}</span></td>
                <td>{item.version}</td>
                <td>{item.csfFunction ? <span className={`tag tag-csf-${item.csfFunction.toLowerCase()}`}>{item.csfFunction}</span> : '-'}</td>
                <td>{item.createdBy}</td>
              </tr>
            ))}
            {data.length === 0 && (
              <tr><td colSpan={7} style={{ textAlign: 'center', padding: 24, color: 'var(--text-secondary)' }}>No {tab} found</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
