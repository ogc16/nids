'use client';

import { useEffect, useState } from 'react';
import { PageHeader, Tag, DataTable, Pagination } from '@/components';

const SEVERITY_TAGS: Record<string, string> = { Critical: 'tag-critical', High: 'tag-high', Medium: 'tag-medium', Low: 'tag-low' };
const STATUS_TAGS: Record<string, string> = { Active: 'tag-active', Deprecated: 'tag-deprecated' };

export default function ThreatIntelPage() {
  const [data, setData] = useState<any[]>([]);
  const [pagination, setPagination] = useState<any>(null);
  const [page, setPage] = useState(1);

  useEffect(() => {
    const params = new URLSearchParams({ page: String(page), limit: '20' });
    fetch(`/api/threat-intel?${params}`)
      .then(r => r.json())
      .then(res => { setData(res.items); setPagination(res.pagination); })
      .catch(() => {});
  }, [page]);

  const columns = [
    { key: 'id', label: 'ID', render: (d: any) => <span className="clickable">{d.id}</span> },
    { key: 'indicator', label: 'Indicator', render: (d: any) => <span className="clickable">{d.indicator}</span> },
    { key: 'type', label: 'Type' },
    { key: 'severity', label: 'Severity', render: (d: any) => <Tag variant={SEVERITY_TAGS[d.severity]}>{d.severity}</Tag> },
    { key: 'confidence', label: 'Confidence', render: (d: any) => `${d.confidence}%` },
    { key: 'status', label: 'Status', render: (d: any) => <Tag variant={STATUS_TAGS[d.status]}>{d.status}</Tag> },
    { key: 'source', label: 'Source' },
    { key: 'firstSeen', label: 'First Seen', render: (d: any) => d.firstSeen || '-' },
  ];

  return (
    <>
      <PageHeader title="Threat Intelligence" subtitle="IOC management and threat feeds" />
      <DataTable columns={columns} data={data} emptyMessage="No threat intelligence data" />
      <Pagination page={pagination?.page || page} totalPages={pagination?.totalPages || 0} onPageChange={setPage} />
    </>
  );
}
