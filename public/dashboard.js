document.addEventListener('DOMContentLoaded', async () => {
  let chartInstances = {};
  let refreshInterval;

  async function loadData() {
    try {
      const stats = await apiFetch('/stats');

      document.querySelector('.stat-card.stat-critical .stat-value').textContent = stats.severityCounts.Critical || 0;
      document.querySelector('.stat-card.stat-warning .stat-value').textContent = stats.openIncidents;
      document.querySelector('.stat-card.stat-info .stat-value').textContent = stats.activeRules;
      const onlineAssets = stats.assetRiskCounts ? Object.values(stats.assetRiskCounts).reduce((a, b) => a + b, 0) : 0;
      document.querySelector('.stat-card.stat-success .stat-value').textContent = onlineAssets;

      document.getElementById('totalFlowsStat').textContent = stats.totalTrafficFlows || 0;
      document.getElementById('suspiciousFlowsStat').textContent = stats.suspiciousTrafficFlows || 0;
      document.getElementById('blockedFlowsStat').textContent = stats.blockedTrafficFlows || 0;

      if (chartInstances.severity) chartInstances.severity.destroy();
      chartInstances.severity = new Chart(document.getElementById('severityChart'), {
        type: 'doughnut',
        data: {
          labels: ['Critical', 'High', 'Medium', 'Low'],
          datasets: [{
            data: [stats.severityCounts.Critical || 0, stats.severityCounts.High || 0, stats.severityCounts.Medium || 0, stats.severityCounts.Low || 0],
            backgroundColor: ['#f85149', '#d29922', '#58a6ff', '#3fb950'],
            borderColor: '#1c2333',
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          plugins: {
            legend: { position: 'bottom', labels: { color: '#8b949e' } }
          }
        }
      });

      if (chartInstances.status) chartInstances.status.destroy();
      chartInstances.status = new Chart(document.getElementById('statusChart'), {
        type: 'doughnut',
        data: {
          labels: ['New', 'Investigating', 'Resolved', 'Closed'],
          datasets: [{
            data: [stats.statusCounts.New || 0, stats.statusCounts.Investigating || 0, stats.statusCounts.Resolved || 0, stats.statusCounts.Closed || 0],
            backgroundColor: ['#58a6ff', '#d29922', '#3fb950', '#8b949e'],
            borderColor: '#1c2333',
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          plugins: {
            legend: { position: 'bottom', labels: { color: '#8b949e' } }
          }
        }
      });

      if (chartInstances.attack) chartInstances.attack.destroy();
      chartInstances.attack = new Chart(document.getElementById('attackChart'), {
        type: 'bar',
        data: {
          labels: Object.keys(stats.attackTypeCounts),
          datasets: [{
            label: 'Incidents',
            data: Object.values(stats.attackTypeCounts),
            backgroundColor: '#58a6ff',
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(48,54,61,0.3)' } },
            y: { beginAtZero: true, ticks: { color: '#8b949e', stepSize: 1 }, grid: { color: 'rgba(48,54,61,0.3)' } }
          }
        }
      });

      if (chartInstances.risk) chartInstances.risk.destroy();
      chartInstances.risk = new Chart(document.getElementById('riskChart'), {
        type: 'bar',
        data: {
          labels: ['Critical', 'High', 'Medium', 'Low'],
          datasets: [{
            label: 'Assets',
            data: [stats.assetRiskCounts.Critical || 0, stats.assetRiskCounts.High || 0, stats.assetRiskCounts.Medium || 0, stats.assetRiskCounts.Low || 0],
            backgroundColor: ['#f85149', '#d29922', '#58a6ff', '#3fb950'],
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(48,54,61,0.3)' } },
            y: { beginAtZero: true, ticks: { color: '#8b949e', stepSize: 1 }, grid: { color: 'rgba(48,54,61,0.3)' } }
          }
        }
      });

      if (chartInstances.csf) chartInstances.csf.destroy();
      chartInstances.csf = new Chart(document.getElementById('csfChart'), {
        type: 'radar',
        data: {
          labels: ['Govern', 'Identify', 'Protect', 'Detect', 'Respond', 'Recover'],
          datasets: [
            {
              label: 'Incidents',
              data: [stats.csfIncidentCounts.GV || 0, stats.csfIncidentCounts.ID || 0, stats.csfIncidentCounts.PR || 0, stats.csfIncidentCounts.DE || 0, stats.csfIncidentCounts.RS || 0, stats.csfIncidentCounts.RC || 0],
              backgroundColor: 'rgba(88,166,255,0.1)',
              borderColor: '#58a6ff',
              borderWidth: 2,
              pointBackgroundColor: '#58a6ff'
            },
            {
              label: 'Rules',
              data: [stats.csfRuleCounts.GV || 0, stats.csfRuleCounts.ID || 0, stats.csfRuleCounts.PR || 0, stats.csfRuleCounts.DE || 0, stats.csfRuleCounts.RS || 0, stats.csfRuleCounts.RC || 0],
              backgroundColor: 'rgba(63,185,80,0.1)',
              borderColor: '#3fb950',
              borderWidth: 2,
              pointBackgroundColor: '#3fb950'
            }
          ]
        },
        options: {
          responsive: true,
          plugins: {
            legend: { position: 'bottom', labels: { color: '#8b949e' } }
          },
          scales: {
            r: {
              beginAtZero: true,
              ticks: { color: '#8b949e', backdropColor: 'transparent' },
              grid: { color: 'rgba(48,54,61,0.3)' },
              angleLines: { color: 'rgba(48,54,61,0.3)' },
              pointLabels: { color: '#8b949e' }
            }
          }
        }
      });
    } catch (err) {
      showToast('Failed to load dashboard data', 'error');
    }
  }

  await loadData();

  refreshInterval = setInterval(loadData, 30000);

  window.addEventListener('beforeunload', () => {
    if (refreshInterval) clearInterval(refreshInterval);
  });
});
