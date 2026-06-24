'use client';

import { useEffect, useState } from 'react';
import { PageHeader, Tag, FilterBar, DataTable, Pagination } from '@/components';

const RISK_TAGS: Record<string, string> = { Critical: 'tag-critical', High: 'tag-high', Medium: 'tag-medium', Low: 'tag-low' };
const HEALTH_CLASSES: Record<string, string> = { Online: 'health-online', Degraded: 'health-degraded', Offline: 'health-offline' };

export default function AssetsPage() {
  const [data, setData] = useState<any[]>([]);
  const [pagination, setPagination] = useState<any>(null);
  const [riskFilter, setRiskFilter] = useState('');
  const [page, setPage] = useState(1);

  const fetchData = () => {
    const params = new URLSearchParams({ page: String(page), limit: '20' });
    fetch(`/api/network-assets?${params}`)
      .then(r => r.json())
      .then(res => { setData(res.items); setPagination(res.pagination); })
      .catch(() => {});
  };

  useEffect(() => { fetchData(); }, [page]);

  const filtered = data.filter(d => !riskFilter || d.riskLevel === riskFilter);

  const handleFilterChange = (setter: (v: string) => void) => (e: any) => {
    setter(e.target.value);
    setPage(1);
  };

  const columns = [
    { key: 'id', label: 'ID', render: (d: any) => <span className="clickable">{d.id}</span> },
    { key: 'assetName', label: 'Asset Name', render: (d: any) => <span className="clickable">{d.assetName}</span> },
    { key: 'ipRange', label: 'IP Range' },
    { key: 'type', label: 'Type' },
    { key: 'riskLevel', label: 'Risk Level', render: (d: any) => <Tag variant={RISK_TAGS[d.riskLevel]}>{d.riskLevel}</Tag> },
    { key: 'monitoringStatus', label: 'Monitoring Status', render: (d: any) => <><span className={`health-dot ${HEALTH_CLASSES[d.monitoringStatus] || ''}`}></span>{d.monitoringStatus}</> },
    { key: 'owner', label: 'Owner' },
    { key: 'openIncidentCount', label: 'Open Incidents' },
  ];

  return (
    <>
      <PageHeader title="Network Assets" subtitle="Monitor and manage network devices">
        <a href="/add-asset" className="btn btn-primary">+ Add Asset</a>
      </PageHeader>

      <FilterBar>
        <select className="filter-select" value={riskFilter} onChange={handleFilterChange(setRiskFilter)}>
          <option value="">All Risk Levels</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </FilterBar>

      <DataTable columns={columns} data={filtered} emptyMessage="No assets found" />

      <Pagination page={pagination?.page || page} totalPages={pagination?.totalPages || 0} onPageChange={setPage} />
    </>
  );
}
