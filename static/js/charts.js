// charts.js — Fetches data from Flask API and renders Chart.js visuals

document.addEventListener('DOMContentLoaded', function () {

  // ── Load Stats Cards ────────────────────────────────────────
  fetch('/api/stats')
    .then(r => r.json())
    .then(data => {
      document.getElementById('totalBreaches').textContent =
        data.total_breaches;
      document.getElementById('totalAffected').textContent =
        Number(data.total_affected).toLocaleString();
      document.getElementById('darkWebHits').textContent =
        data.dark_web_hits;

      // ── Severity Doughnut Chart ────────────────────────────
      const sev = data.severity_breakdown;
      new Chart(document.getElementById('severityChart'), {
        type: 'doughnut',
        data: {
          labels: Object.keys(sev),
          datasets: [{
            data: Object.values(sev),
            backgroundColor: ['#ff7b72','#f0883e','#e3b341','#56d364'],
            borderWidth: 2, borderColor: '#161b22'
          }]
        },
        options: {
          plugins: { legend: { labels: { color: '#c9d1d9' } } }
        }
      });
    });

  // ── Load Breach Bar Chart & Table ───────────────────────────
  fetch('/api/breaches')
    .then(r => r.json())
    .then(breaches => {

      // Bar chart — top breaches by affected count
      const top = breaches.slice(0, 6);
      new Chart(document.getElementById('breachChart'), {
        type: 'bar',
        data: {
          labels: top.map(b => b.source.replace(' Simulation', '')),
          datasets: [{
            label: 'Affected Users',
            data: top.map(b => b.affected_count),
            backgroundColor: '#58a6ff', borderRadius: 6
          }]
        },
        options: {
          plugins: { legend: { labels: { color: '#c9d1d9' } } },
          scales: {
            x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
            y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } }
          }
        }
      });

      // Populate breach table
      const tbody = document.getElementById('breachTableBody');
      breaches.forEach((b, i) => {
        tbody.innerHTML += `
          <tr>
            <td>${i + 1}</td>
            <td>${b.source}</td>
            <td>${b.breach_date}</td>
            <td>${b.data_type}</td>
            <td>${Number(b.affected_count).toLocaleString()}</td>
            <td><span class="badge badge-${b.severity}">${b.severity}</span></td>
          </tr>`;
      });
    });

});