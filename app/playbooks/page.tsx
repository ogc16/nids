'use client';

import { useEffect, useState } from 'react';
import { PageHeader, Tag, DataTable } from '@/components';

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState<any[]>([]);
  const [detail, setDetail] = useState<any>(null);

  useEffect(() => {
    fetch('/api/playbooks').then(r => r.json()).then(d => setPlaybooks(d.items || d)).catch(() => {});
  }, []);

  const columns = [
    { key: 'id', label: 'ID' },
    { key: 'name', label: 'Name', render: (p: any) => <span className="clickable">{p.name}</span> },
    { key: 'category', label: 'Category', render: (p: any) => <Tag variant="tag-info">{p.category}</Tag> },
    { key: 'severity', label: 'Severity', render: (p: any) => <Tag variant={`tag-${p.severity?.toLowerCase()}`}>{p.severity}</Tag> },
    { key: 'status', label: 'Status', render: (p: any) => <Tag variant={p.status === 'Active' ? 'tag-active' : 'tag-deprecated'}>{p.status}</Tag> },
    { key: 'createdBy', label: 'Created By' },
    { key: 'runCount', label: 'Run Count', render: (p: any) => p.runCount || 0 },
    { key: 'lastRun', label: 'Last Run', render: (p: any) => <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{p.lastRun ? new Date(p.lastRun).toLocaleString() : '-'}</span> },
  ];

  return (
    <>
      <PageHeader title="Playbooks" subtitle="Incident response playbooks and runbooks">
        <a href="/add-playbook" className="btn btn-primary">+ Add Playbook</a>
      </PageHeader>

      <DataTable columns={columns} data={playbooks} emptyMessage="No playbooks yet" onRowClick={setDetail} />

      {detail && (
        <div className="modal-backdrop" onClick={() => setDetail(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{detail.name}</h3>
              <button className="modal-close" onClick={() => setDetail(null)}>&times;</button>
            </div>
            <div className="modal-body">
              <div className="detail-row"><div className="detail-label">Category</div><div className="detail-value">{detail.category}</div></div>
              <div className="detail-row"><div className="detail-label">Severity</div><div className="detail-value"><Tag variant={`tag-${detail.severity?.toLowerCase()}`}>{detail.severity}</Tag></div></div>
              <div className="detail-row"><div className="detail-label">Status</div><div className="detail-value"><Tag variant={detail.status === 'Active' ? 'tag-active' : 'tag-deprecated'}>{detail.status}</Tag></div></div>
              <div className="detail-row"><div className="detail-label">Description</div><div className="detail-value">{detail.description}</div></div>
              <div className="detail-row"><div className="detail-label">Created By</div><div className="detail-value">{detail.createdBy}</div></div>
              <div className="detail-row"><div className="detail-label">Run Count</div><div className="detail-value">{detail.runCount || 0}</div></div>
              {detail.triggerOnAttackTypes && (
                <div className="detail-row"><div className="detail-label">Triggers</div><div className="detail-value">{detail.triggerOnAttackTypes.join(', ')}</div></div>
              )}
              {detail.steps && (
                <div className="detail-row"><div className="detail-label">Steps</div><div className="detail-value">
                  {detail.steps.map((s: any, i: number) => (
                    <div key={i} style={{ marginBottom: 4, fontSize: 12 }}>Step {s.order}: {s.action} <span style={{ color: 'var(--text-secondary)' }}>({s.assignee}, {s.duration})</span></div>
                  ))}
                </div></div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
