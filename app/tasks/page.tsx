'use client';

import { useEffect, useState } from 'react';
import { PageHeader, Tag, FilterBar, DataTable, Pagination } from '@/components';

const STATUS_TAGS: Record<string, string> = { 'To Do': 'tag-todo', 'In Progress': 'tag-in-progress', Done: 'tag-done' };
const PRIORITY_TAGS: Record<string, string> = { Critical: 'tag-critical', High: 'tag-high', Medium: 'tag-medium', Low: 'tag-low' };

export default function TasksPage() {
  const [data, setData] = useState<any[]>([]);
  const [pagination, setPagination] = useState<any>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [priorityFilter, setPriorityFilter] = useState('');
  const [page, setPage] = useState(1);

  const fetchData = () => {
    const params = new URLSearchParams({ page: String(page), limit: '20' });
    fetch(`/api/engineering-tasks?${params}`)
      .then(r => r.json())
      .then(res => { setData(res.items); setPagination(res.pagination); })
      .catch(() => {});
  };

  useEffect(() => { fetchData(); }, [page]);

  const filtered = data.filter(d =>
    (!statusFilter || d.status === statusFilter) &&
    (!priorityFilter || d.priority === priorityFilter)
  );

  const handleFilterChange = (setter: (v: string) => void) => (e: any) => {
    setter(e.target.value);
    setPage(1);
  };

  const columns = [
    { key: 'id', label: 'ID', render: (d: any) => <span className="clickable">{d.id}</span> },
    { key: 'taskName', label: 'Task Name', render: (d: any) => <span className="clickable">{d.taskName}</span> },
    { key: 'status', label: 'Status', render: (d: any) => <Tag variant={STATUS_TAGS[d.status]}>{d.status}</Tag> },
    { key: 'priority', label: 'Priority', render: (d: any) => <Tag variant={PRIORITY_TAGS[d.priority]}>{d.priority}</Tag> },
    { key: 'assignee', label: 'Assignee' },
    { key: 'sprint', label: 'Sprint', render: (d: any) => d.sprint || '-' },
    { key: 'ruleId', label: 'Rule ID', render: (d: any) => d.ruleId || '-' },
    { key: 'dueDate', label: 'Due Date', render: (d: any) => d.dueDate ? new Date(d.dueDate).toLocaleDateString() : '-' },
  ];

  return (
    <>
      <PageHeader title="Engineering Tasks" subtitle="Track rule development and deployment tasks" />

      <FilterBar>
        <select className="filter-select" value={statusFilter} onChange={handleFilterChange(setStatusFilter)}>
          <option value="">All Statuses</option>
          <option value="To Do">To Do</option>
          <option value="In Progress">In Progress</option>
          <option value="Done">Done</option>
        </select>
        <select className="filter-select" value={priorityFilter} onChange={handleFilterChange(setPriorityFilter)}>
          <option value="">All Priorities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </FilterBar>

      <DataTable columns={columns} data={filtered} emptyMessage="No tasks found" />

      <Pagination page={pagination?.page || page} totalPages={pagination?.totalPages || 0} onPageChange={setPage} />
    </>
  );
}
