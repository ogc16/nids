document.addEventListener('DOMContentLoaded', async () => {
  try {
    const incidents = await apiFetch('/incidents');
    const resolved = incidents.filter(i => i.status === 'Resolved' && i.cvssScore != null);

    document.getElementById('totalResolved').textContent = resolved.length;

    const scores = resolved.map(i => i.cvssScore);
    const avg = scores.reduce((a, b) => a + b, 0) / scores.length || 0;
    document.getElementById('avgCvss').textContent = avg.toFixed(1);

    const criticalCount = scores.filter(s => s >= 9).length;
    document.getElementById('criticalCvssCount').textContent = criticalCount;

    const avgTime = calculateAvgResolutionTime(resolved);
    document.getElementById('avgResolutionTime').textContent = avgTime;

    const cvssBuckets = { '0-3.9': 0, '4-6.9': 0, '7-8.9': 0, '9-10': 0 };
    resolved.forEach(i => {
      if (i.cvssScore < 4) cvssBuckets['0-3.9']++;
      else if (i.cvssScore < 7) cvssBuckets['4-6.9']++;
      else if (i.cvssScore < 9) cvssBuckets['7-8.9']++;
      else cvssBuckets['9-10']++;
    });

    new Chart(document.getElementById('cvssChart'), {
      type: 'bar',
      data: {
        labels: Object.keys(cvssBuckets),
        datasets: [{
          label: 'Incidents',
          data: Object.values(cvssBuckets),
          backgroundColor: ['#3fb950', '#58a6ff', '#d29922', '#f85149'],
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

    const attackCounts = {};
    resolved.forEach(i => { attackCounts[i.attackType] = (attackCounts[i.attackType] || 0) + 1; });

    new Chart(document.getElementById('attackChart'), {
      type: 'bar',
      data: {
        labels: Object.keys(attackCounts),
        datasets: [{
          label: 'Resolved Incidents',
          data: Object.values(attackCounts),
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

    const tbody = document.getElementById('reportTableBody');
    tbody.innerHTML = resolved.map(i => `
      <tr>
        <td>#${i.id}</td>
        <td>${i.title}</td>
        <td>${severityTag(i.severity)}</td>
        <td>${i.attackType}</td>
        <td><strong>${i.cvssScore.toFixed(1)}</strong></td>
        <td>${formatDate(i.detectedAt)}</td>
        <td style="max-width:300px;white-space:normal">${i.resolutionNotes || 'N/A'}</td>
      </tr>
    `).join('');

  } catch (err) {
    showToast('Failed to load report data', 'error');
  }
});

function calculateAvgResolutionTime(resolved) {
  let totalHours = 0;
  let count = 0;
  resolved.forEach(i => {
    if (i.detectedAt) {
      const detected = new Date(i.detectedAt);
      const resolvedDate = i.resolvedAt ? new Date(i.resolvedAt) : new Date();
      const hours = (resolvedDate - detected) / (1000 * 60 * 60);
      if (hours > 0) { totalHours += hours; count++; }
    }
  });
  if (count === 0) return '-';
  const avg = totalHours / count;
  if (avg < 1) return `${Math.round(avg * 60)}m`;
  if (avg < 24) return `${avg.toFixed(1)}h`;
  return `${(avg / 24).toFixed(1)}d`;
}
