'use client';

import { useEffect, useState } from 'react';
import { Chart as ChartJS, ArcElement, BarElement, CategoryScale, LinearScale, PointElement, LineElement, RadialLinearScale, Filler, Tooltip, Legend } from 'chart.js';
import { Doughnut, Bar, Radar } from 'react-chartjs-2';
import { PageHeader, StatCard, LoadingState, ChartsRow } from '@/components';

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, PointElement, LineElement, RadialLinearScale, Filler, Tooltip, Legend);

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null);

  useEffect(() => {
    fetch('/api/stats')
      .then(r => r.json())
      .then(setStats)
      .catch(() => {});
  }, []);

  if (!stats) return <LoadingState message="Loading workspace&hellip;" spinner />;

  const severityData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{ data: [stats.severityCounts.Critical || 0, stats.severityCounts.High || 0, stats.severityCounts.Medium || 0, stats.severityCounts.Low || 0], backgroundColor: ['#f85149', '#d29922', '#58a6ff', '#3fb950'], borderColor: '#1c2333', borderWidth: 2 }],
  };
  const statusData = {
    labels: ['New', 'Investigating', 'Resolved', 'Closed'],
    datasets: [{ data: [stats.statusCounts.New || 0, stats.statusCounts.Investigating || 0, stats.statusCounts.Resolved || 0, stats.statusCounts.Closed || 0], backgroundColor: ['#58a6ff', '#d29922', '#3fb950', '#8b949e'], borderColor: '#1c2333', borderWidth: 2 }],
  };
  const attackData = {
    labels: Object.keys(stats.attackTypeCounts),
    datasets: [{ label: 'Incidents', data: Object.values(stats.attackTypeCounts), backgroundColor: '#58a6ff', borderRadius: 4 }],
  };
  const riskData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{ label: 'Assets', data: [stats.assetRiskCounts.Critical || 0, stats.assetRiskCounts.High || 0, stats.assetRiskCounts.Medium || 0, stats.assetRiskCounts.Low || 0], backgroundColor: ['#f85149', '#d29922', '#58a6ff', '#3fb950'], borderRadius: 4 }],
  };
  const csfData = {
    labels: ['Govern', 'Identify', 'Protect', 'Detect', 'Respond', 'Recover'],
    datasets: [
      { label: 'Incidents', data: [stats.csfIncidentCounts.GV || 0, stats.csfIncidentCounts.ID || 0, stats.csfIncidentCounts.PR || 0, stats.csfIncidentCounts.DE || 0, stats.csfIncidentCounts.RS || 0, stats.csfIncidentCounts.RC || 0], backgroundColor: 'rgba(88,166,255,0.1)', borderColor: '#58a6ff', borderWidth: 2, pointBackgroundColor: '#58a6ff' },
      { label: 'Rules', data: [stats.csfRuleCounts.GV || 0, stats.csfRuleCounts.ID || 0, stats.csfRuleCounts.PR || 0, stats.csfRuleCounts.DE || 0, stats.csfRuleCounts.RS || 0, stats.csfRuleCounts.RC || 0], backgroundColor: 'rgba(63,185,80,0.1)', borderColor: '#3fb950', borderWidth: 2, pointBackgroundColor: '#3fb950' },
    ],
  };
  const chartOpts = { responsive: true, plugins: { legend: { position: 'bottom' as const, labels: { color: '#8b949e' } } }, scales: { x: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(48,54,61,0.3)' } }, y: { beginAtZero: true, ticks: { color: '#8b949e', stepSize: 1 }, grid: { color: 'rgba(48,54,61,0.3)' } } } };
  const chartOptsNoLegend = { responsive: true, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(48,54,61,0.3)' } }, y: { beginAtZero: true, ticks: { color: '#8b949e', stepSize: 1 }, grid: { color: 'rgba(48,54,61,0.3)' } } } };
  const doughnutOpts = { responsive: true, plugins: { legend: { position: 'bottom' as const, labels: { color: '#8b949e' } } } };
  const radarOpts = { responsive: true, plugins: { legend: { position: 'bottom' as const, labels: { color: '#8b949e' } } }, scales: { r: { beginAtZero: true, ticks: { color: '#8b949e', backdropColor: 'transparent' }, grid: { color: 'rgba(48,54,61,0.3)' }, angleLines: { color: 'rgba(48,54,61,0.3)' }, pointLabels: { color: '#8b949e' } } } };

  return (
    <>
      <PageHeader title="Security Operations Overview" subtitle="Real-time dashboard for NIDS workspace metrics">
        <a href="/report-incident" className="btn btn-primary">+ Report Incident</a>
      </PageHeader>

      <div className="dashboard-grid">
        <StatCard label="Critical Incidents" value={stats.severityCounts.Critical || 0} sub="Requires immediate action" variant="stat-critical" href="/incidents" />
        <StatCard label="Open Incidents" value={stats.openIncidents} sub="Investigating / New" variant="stat-warning" href="/incidents" />
        <StatCard label="Active Rules" value={stats.activeRules} sub="Detection rules deployed" variant="stat-info" href="/rules" />
        <StatCard label="Assets Online" value={(Object.values(stats.assetRiskCounts || {}) as number[]).reduce((a, b) => a + b, 0)} sub="Monitored devices" variant="stat-success" href="/assets" />
      </div>

      <ChartsRow>
        <div className="chart-container"><h3>Incidents by Severity</h3><Doughnut data={severityData} options={doughnutOpts} /></div>
        <div className="chart-container"><h3>Incidents by Status</h3><Doughnut data={statusData} options={doughnutOpts} /></div>
      </ChartsRow>
      <ChartsRow>
        <div className="chart-container"><h3>Attack Type Distribution</h3><Bar data={attackData} options={chartOptsNoLegend} /></div>
        <div className="chart-container"><h3>Asset Risk Levels</h3><Bar data={riskData} options={chartOptsNoLegend} /></div>
      </ChartsRow>
      <ChartsRow>
        <div className="chart-container" style={{ gridColumn: '1/-1', maxWidth: 500, margin: '0 auto' }}>
          <h3>NIST CSF Coverage <span style={{ fontWeight: 400, fontSize: 12, color: 'var(--text-secondary)' }}>— Incidents & Rules by Function</span></h3>
          <Radar data={csfData} options={radarOpts} />
        </div>
      </ChartsRow>

      <div className="dashboard-grid" style={{ marginTop: 8 }}>
        <StatCard label="Network Flows" value={stats.totalTrafficFlows || 0} sub="Total connections monitored" variant="stat-info" />
        <StatCard label="Suspicious Flows" value={stats.suspiciousTrafficFlows || 0} sub="Flagged for review" variant="stat-warning" href="/network-monitoring" />
        <StatCard label="Blocked Flows" value={stats.blockedTrafficFlows || 0} sub="Dropped by policies" variant="stat-critical" href="/network-monitoring" />
        <StatCard label="Quick Link" value={<a href="/network-monitoring" style={{ color: 'var(--accent-cyan)', textDecoration: 'none' }}>View Traffic &rarr;</a>} sub="Open network monitoring board" />
      </div>
    </>
  );
}
