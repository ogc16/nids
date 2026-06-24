'use client';

import { useEffect, useState } from 'react';
import { PageHeader, StatCard, StatCardSmall, Card, Tag, DataTable } from '@/components';

const FRAMEWORKS = ['pci-dss', 'hipaa', 'gdpr'];
const FW_LABELS: Record<string, string> = { 'pci-dss': 'PCI DSS v4.0', 'hipaa': 'HIPAA Security Rule', 'gdpr': 'GDPR' };

export default function CompliancePage() {
  const [dashboard, setDashboard] = useState<any>({});
  const [controls, setControls] = useState<any>({});
  const [activeFw, setActiveFw] = useState('pci-dss');

  useEffect(() => {
    fetch('/api/compliance/dashboard').then(r => r.json()).then(setDashboard).catch(() => {});
  }, []);

  useEffect(() => {
    fetch(`/api/compliance/${activeFw}/controls`).then(r => r.json()).then(data => setControls(prev => ({ ...prev, [activeFw]: data }))).catch(() => {});
  }, [activeFw]);

  const fw = dashboard[activeFw];

  const columns = [
    { key: 'id', label: 'ID', render: (c: any) => <span style={{ color: 'var(--accent-blue)', fontFamily: 'monospace' }}>{c.id}</span> },
    { key: 'title', label: 'Title', render: (c: any) => c.title || c.name },
    { key: 'status', label: 'Status', render: (c: any) => {
      const v = c.status === 'Compliant' ? 'tag-active' : c.status === 'Non-Compliant' ? 'tag-critical' : 'tag-todo';
      return <Tag variant={v}>{c.status || 'Unknown'}</Tag>;
    }},
    { key: 'description', label: 'Description', render: (c: any) => <span style={{ fontSize: 12, color: 'var(--text-secondary)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const }}>{c.description}</span> },
  ];

  return (
    <>
      <PageHeader title="Compliance Dashboard" subtitle="Regulatory compliance status across frameworks" />

      <div className="dashboard-grid">
        {FRAMEWORKS.map(fwId => {
          const status = dashboard[fwId];
          const compliant = status?.compliant || 0;
          const total = status?.total || 0;
          const pct = total > 0 ? Math.round(compliant / total * 100) : 0;
          return (
            <StatCard
              key={fwId}
              label={FW_LABELS[fwId]}
              value={`${pct}%`}
              sub={`${compliant}/${total} controls compliant`}
              variant={fwId === activeFw ? 'stat-info' : ''}
            />
          );
        })}
      </div>

      {fw && (
        <Card title={`${FW_LABELS[activeFw]} — Compliance Status`} className="mb-16">
          <div className="dashboard-grid" style={{ marginBottom: 0 }}>
            <StatCardSmall label="Compliant" value={fw.compliant || 0} color="var(--accent-green)" />
            <StatCardSmall label="Non-Compliant" value={fw['non-compliant'] || fw.nonCompliant || 0} color="var(--accent-orange)" />
            <StatCardSmall label="N/A" value={fw['not-applicable'] || fw.notApplicable || 0} color="var(--accent-blue)" />
            <StatCardSmall label="Total Controls" value={fw.total || 0} color="var(--text-secondary)" />
          </div>
          {fw.recommendations?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ fontWeight: 600, marginBottom: 8 }}>Recommendations</div>
              {fw.recommendations.map((r: any, i: number) => (
                <div key={i} style={{ padding: '6px 0', borderBottom: '1px solid rgba(48,54,61,0.3)', fontSize: 13 }}>{r.control} — {r.recommendation}</div>
              ))}
            </div>
          )}
        </Card>
      )}

      <Card title={`Controls — ${FW_LABELS[activeFw]}`}>
        <DataTable columns={columns} data={controls[activeFw] || []} emptyMessage="No controls data" />
      </Card>
    </>
  );
}
