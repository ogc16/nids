'use client';

import { useEffect, useState } from 'react';
import { PageHeader, Tag, FilterBar, DataTable, Pagination } from '@/components';

const STATUS_TAGS: Record<string, string> = { Active: 'tag-active', 'In Development': 'tag-development', Deprecated: 'tag-deprecated' };
const SEVERITY_TAGS: Record<string, string> = { Critical: 'tag-critical', High: 'tag-high', Medium: 'tag-medium', Low: 'tag-low' };
const CSF_TAGS: Record<string, string> = { GV: 'tag-csf-gv', ID: 'tag-csf-id', PR: 'tag-csf-pr', DE: 'tag-csf-de', RS: 'tag-csf-rs', RC: 'tag-csf-rc' };

export default function RulesPage() {
  const [data, setData] = useState<any[]>([]);
  const [pagination, setPagination] = useState<any>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [page, setPage] = useState(1);

  const fetchData = () => {
    const params = new URLSearchParams({ page: String(page), limit: '20' });
    fetch(`/api/detection-rules?${params}`)
      .then(r => r.json())
      .then(res => { setData(res.items); setPagination(res.pagination); })
      .catch(() => {});
  };

  useEffect(() => { fetchData(); }, [page]);

  const filtered = data.filter(d =>
    (!statusFilter || d.status === statusFilter) &&
    (!severityFilter || d.severity === severityFilter)
  );

  const handleFilterChange = (setter: (v: string) => void) => (e: any) => {
    setter(e.target.value);
    setPage(1);
  };

  const columns = [
    { key: 'id', label: 'ID', render: (d: any) => <span className="clickable">{d.id}</span> },
    { key: 'name', label: 'Name', render: (d: any) => <span className="clickable">{d.name}</span> },
    { key: 'status', label: 'Status', render: (d: any) => <Tag variant={STATUS_TAGS[d.status]}>{d.status}</Tag> },
    { key: 'severity', label: 'Severity', render: (d: any) => <Tag variant={SEVERITY_TAGS[d.severity]}>{d.severity}</Tag> },
    { key: 'attackType', label: 'Attack Type' },
    { key: 'csfFunction', label: 'CSF Function', render: (d: any) => <Tag variant={CSF_TAGS[d.csfFunction]}>{d.csfFunction || '-'}</Tag> },
    { key: 'lastUpdated', label: 'Last Updated' },
    { key: 'createdBy', label: 'Created By' },
  ];

  return (
    <>
      <PageHeader title="Detection Rules" subtitle="Manage and deploy detection signatures">
        <a href="/submit-rule" className="btn btn-primary">+ Submit Rule</a>
      </PageHeader>

      <FilterBar>
        <select className="filter-select" value={statusFilter} onChange={handleFilterChange(setStatusFilter)}>
          <option value="">All Statuses</option>
          <option value="Active">Active</option>
          <option value="In Development">In Development</option>
          <option value="Deprecated">Deprecated</option>
        </select>
        <select className="filter-select" value={severityFilter} onChange={handleFilterChange(setSeverityFilter)}>
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </FilterBar>

      <DataTable columns={columns} data={filtered} emptyMessage="No rules found" />

      <Pagination page={pagination?.page || page} totalPages={pagination?.totalPages || 0} onPageChange={setPage} />
    </>
  );
}
