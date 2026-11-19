// Chart.js wrappers for the stats section.
(function () {
  var S = (window.Sentinel = window.Sentinel || {});
  var outcome = null;
  var daily = null;

  function last30Days(rows) {
    var map = {};
    (rows || []).forEach(function (r) { map[r.d] = r.c; });
    var labels = [], values = [];
    var now = new Date();
    for (var i = 29; i >= 0; i--) {
      var d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i));
      var key = d.toISOString().slice(0, 10);
      labels.push(key.slice(5));
      values.push(map[key] || 0);
    }
    return { labels: labels, values: values };
  }

  function renderOutcome(status) {
    var ctx = S.$("outcomeChart");
    if (!ctx || typeof Chart === "undefined") return;
    ctx.setAttribute("role", "img");
    ctx.setAttribute("aria-label", "Outcome mix: vulnerable " + (status.vulnerable || 0) + ", hidden " + (status.hidden || 0) +
      ", safe " + (status.safe || 0) + ", no PHP " + (status.no_php || 0));
    if (outcome) outcome.destroy();
    outcome = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Vulnerable", "Hidden", "Safe", "No PHP", "Error"],
        datasets: [{
          data: [status.vulnerable || 0, status.hidden || 0, status.safe || 0, status.no_php || 0, status.error || 0],
          backgroundColor: ["#f43f5e", "#f59e0b", "#34d399", "#64748b", "#fb7185"],
          borderWidth: 0,
          hoverOffset: 8
        }]
      },
      options: { cutout: "68%", plugins: { legend: { position: "bottom", labels: { color: "#94a3b8", boxWidth: 10, padding: 12 } } } }
    });
  }

  function renderDaily(rows) {
    var ctx = S.$("trendChart");
    if (!ctx || typeof Chart === "undefined") return;
    var series = last30Days(rows);
    var total = series.values.reduce(function (a, b) { return a + b; }, 0);
    ctx.setAttribute("role", "img");
    ctx.setAttribute("aria-label", "Checks per day over the last 30 days, " + total + " in total");
    if (daily) daily.destroy();
    daily = new Chart(ctx, {
      type: "line",
      data: {
        labels: series.labels,
        datasets: [{
          label: "Checks",
          data: series.values,
          borderColor: "#2dd4bf",
          backgroundColor: "rgba(45,212,191,0.12)",
          pointBackgroundColor: "#2dd4bf",
          pointBorderColor: "#042f2e",
          pointRadius: 3,
          pointHoverRadius: 6,
          borderWidth: 3,
          fill: true,
          tension: 0.35
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { backgroundColor: "rgba(15,23,42,0.95)", titleColor: "#fff", bodyColor: "#cbd5e1", borderColor: "rgba(45,212,191,0.3)", borderWidth: 1 }
        },
        scales: {
          x: { ticks: { color: "#94a3b8", maxTicksLimit: 8 }, grid: { color: "rgba(255,255,255,0.04)" } },
          y: { beginAtZero: true, ticks: { color: "#94a3b8", precision: 0 }, grid: { color: "rgba(255,255,255,0.06)" } }
        }
      }
    });
  }

  S.charts = {
    render: function (stats) {
      renderOutcome(stats.status || {});
      renderDaily(stats.daily || []);
    },
    last30Days: last30Days
  };
})();
