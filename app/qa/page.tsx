'use client';

import { useEffect, useState } from 'react';
import { PageHeader, Tag, DataTable, Pagination } from '@/components';

const STATUS_TAGS: Record<string, string> = { pending: 'tag-todo', in_progress: 'tag-in-progress', passed: 'tag-active', failed: 'tag-critical', blocked: 'tag-deprecated' };

export default function QAPage() {
  const [data, setData] = useState<any[]>([]);
  const [pagination, setPagination] = useState<any>(null);
  const [page, setPage] = useState(1);

  useEffect(() => {
    const params = new URLSearchParams({ page: String(page), limit: '20' });
    fetch(`/api/qa-tests?${params}`)
      .then(r => r.json())
      .then(res => { setData(res.items); setPagination(res.pagination); })
      .catch(() => {});
  }, [page]);

  const columns = [
    { key: 'id', label: 'ID', render: (d: any) => <span className="clickable">{d.id}</span> },
    { key: 'testName', label: 'Test Name', render: (d: any) => <span className="clickable">{d.testName}</span> },
    { key: 'ruleId', label: 'Rule ID', render: (d: any) => d.ruleId || '-' },
    { key: 'status', label: 'Status', render: (d: any) => <Tag variant={STATUS_TAGS[d.status]}>{d.status}</Tag> },
    { key: 'testedBy', label: 'Tested By', render: (d: any) => d.testedBy || '-' },
    { key: 'createdAt', label: 'Created At', render: (d: any) => d.createdAt ? new Date(d.createdAt).toLocaleString() : '-' },
  ];

  return (
    <>
      <PageHeader title="QA &amp; Testing" subtitle="Validate and verify detection rules" />
      <DataTable columns={columns} data={data} emptyMessage="No QA tests found" />
      <Pagination page={pagination?.page || page} totalPages={pagination?.totalPages || 0} onPageChange={setPage} />
    </>
  );
}
