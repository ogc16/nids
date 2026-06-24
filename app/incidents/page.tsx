'use client';

import { useEffect, useState } from 'react';
import { PageHeader, Tag, FilterBar, DataTable, Pagination } from '@/components';

const SEVERITY_TAGS: Record<string, string> = { Critical: 'tag-critical', High: 'tag-high', Medium: 'tag-medium', Low: 'tag-low' };
const STATUS_TAGS: Record<string, string> = { New: 'tag-new', Investigating: 'tag-investigating', Resolved: 'tag-resolved', Closed: 'tag-closed' };

export default function IncidentsPage() {
  const [data, setData] = useState<any[]>([]);
  const [pagination, setPagination] = useState<any>(null);
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage] = useState(1);

  const fetchData = () => {
    const params = new URLSearchParams({ page: String(page), limit: '20' });
    fetch(`/api/incidents?${params}`)
      .then(r => r.json())
      .then(res => { setData(res.items); setPagination(res.pagination); })
      .catch(() => {});
  };

  useEffect(() => { fetchData(); }, [page]);

  const filtered = data.filter(d =>
    (!severityFilter || d.severity === severityFilter) &&
    (!statusFilter || d.status === statusFilter)
  );

  const handleFilterChange = (setter: (v: string) => void) => (e: any) => {
    setter(e.target.value);
    setPage(1);
  };

  const columns = [
    { key: 'id', label: 'ID', render: (d: any) => <span className="clickable">{d.id}</span> },
    { key: 'title', label: 'Title', render: (d: any) => <span className="clickable">{d.title}</span> },
    { key: 'severity', label: 'Severity', render: (d: any) => <Tag variant={SEVERITY_TAGS[d.severity]}>{d.severity}</Tag> },
    { key: 'status', label: 'Status', render: (d: any) => <Tag variant={STATUS_TAGS[d.status]}>{d.status}</Tag> },
    { key: 'attackType', label: 'Attack Type' },
    { key: 'sourceIp', label: 'Source IP' },
    { key: 'assignee', label: 'Assignee' },
    { key: 'detectedAt', label: 'Detected At', render: (d: any) => d.detectedAt ? new Date(d.detectedAt).toLocaleString() : '-' },
  ];

  return (
    <>
      <PageHeader title="Incidents &amp; Alerts" subtitle="Track and manage security incidents">
        <a href="/report-incident" className="btn btn-primary">+ Report Incident</a>
      </PageHeader>

      <FilterBar>
        <select className="filter-select" value={severityFilter} onChange={handleFilterChange(setSeverityFilter)}>
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select className="filter-select" value={statusFilter} onChange={handleFilterChange(setStatusFilter)}>
          <option value="">All Statuses</option>
          <option value="New">New</option>
          <option value="Investigating">Investigating</option>
          <option value="Resolved">Resolved</option>
          <option value="Closed">Closed</option>
        </select>
      </FilterBar>

      <DataTable columns={columns} data={filtered} emptyMessage="No incidents found" />

      <Pagination page={pagination?.page || page} totalPages={pagination?.totalPages || 0} onPageChange={setPage} />
    </>
  );
}
