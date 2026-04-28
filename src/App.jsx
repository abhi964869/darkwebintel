import { useEffect, useMemo, useState } from "react";

const severityStyles = {
  Critical: "border-rose-400/40 bg-rose-500/10 text-rose-100 shadow-rose-500/10",
  High: "border-orange-400/40 bg-orange-500/10 text-orange-100 shadow-orange-500/10",
  Medium: "border-amber-400/40 bg-amber-500/10 text-amber-100 shadow-amber-500/10",
  Low: "border-emerald-400/40 bg-emerald-500/10 text-emerald-100 shadow-emerald-500/10",
};

const navItems = ["Overview", "Breaches", "Report"];

function StatCard({ label, value, detail, tone = "cyan", delay = 0 }) {
  const tones = {
    cyan: "from-cyan-400/20 to-sky-500/5 text-cyan-200",
    violet: "from-violet-400/20 to-fuchsia-500/5 text-violet-200",
    amber: "from-amber-400/20 to-orange-500/5 text-amber-200",
    emerald: "from-emerald-400/20 to-teal-500/5 text-emerald-200",
  };

  return (
    <section className="reveal-card group relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.055] p-5 shadow-2xl shadow-black/20 backdrop-blur-xl" style={{ animationDelay: `${delay}ms` }}>
      <div className={`absolute inset-x-0 top-0 h-px bg-gradient-to-r ${tones[tone] || tones.cyan}`} />
      <div className="absolute -right-8 -top-8 h-24 w-24 rounded-full bg-white/10 blur-2xl transition-transform duration-500 group-hover:scale-150" />
      <p className="text-xs uppercase tracking-[0.22em] text-slate-400">{label}</p>
      <p className={`mt-3 text-3xl font-semibold ${tones[tone]?.split(" ").at(-1) || "text-cyan-200"}`}>{value}</p>
      {detail && <p className="mt-2 text-sm text-slate-400">{detail}</p>}
    </section>
  );
}

function SeverityBadge({ value }) {
  const classes = severityStyles[value] || "border-slate-500/30 bg-slate-500/10 text-slate-200";
  return (
    <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium shadow-lg ${classes}`}>
      {value || "Unknown"}
    </span>
  );
}

function StatusDot() {
  return (
    <span className="relative flex h-3 w-3">
      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
      <span className="relative inline-flex h-3 w-3 rounded-full bg-emerald-300" />
    </span>
  );
}

function MiniBar({ label, value, max, color }) {
  const width = max ? Math.max(6, Math.round((value / max) * 100)) : 0;
  return (
    <div>
      <div className="mb-2 flex items-center justify-between text-xs text-slate-400">
        <span>{label}</span>
        <span>{value}</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-slate-900/80">
        <div className={`h-full rounded-full ${color} bar-grow`} style={{ "--bar-width": `${width}%` }} />
      </div>
    </div>
  );
}

export default function App() {
  const [stats, setStats] = useState(null);
  const [breaches, setBreaches] = useState([]);
  const [darkStats, setDarkStats] = useState(null);
  const [alerts, setAlerts] = useState(null);
  const [email, setEmail] = useState("");
  const [report, setReport] = useState(null);
  const [message, setMessage] = useState("");
  const [loadingReport, setLoadingReport] = useState(false);

  useEffect(() => {
    Promise.all([
      fetch("/api/stats").then((r) => r.json()),
      fetch("/api/breaches").then((r) => r.json()),
      fetch("/api/darkweb/stats").then((r) => r.json()),
      fetch("/api/alerts/stats").then((r) => r.json()),
    ])
      .then(([statsData, breachData, darkData, alertData]) => {
        setStats(statsData);
        setBreaches(Array.isArray(breachData) ? breachData : []);
        setDarkStats(darkData);
        setAlerts(alertData);
      })
      .catch(() => setMessage("Could not reach the Flask API on port 5000."));
  }, []);

  const totalAffected = useMemo(() => {
    return breaches.reduce((sum, item) => sum + Number(item.affected_count || 0), 0);
  }, [breaches]);

  const maxAffected = useMemo(() => {
    return Math.max(...breaches.map((item) => Number(item.affected_count || 0)), 1);
  }, [breaches]);

  const generateReport = async () => {
    if (!email.includes("@")) {
      setMessage("Enter a valid email address.");
      return;
    }

    setLoadingReport(true);
    setMessage("Generating report...");
    setReport(null);

    try {
      const response = await fetch("/api/report/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Report generation failed.");
      setReport(data);
      setMessage("Report generated successfully.");
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoadingReport(false);
    }
  };

  const severityBreakdown = stats?.severity_breakdown || {};

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#050816] text-slate-100">
      <div className="mesh-bg" />
      <div className="grid-glow" />

      <div className="relative mx-auto max-w-7xl px-4 py-5 sm:px-6 lg:px-8">
        <nav className="sticky top-4 z-20 mb-8 flex items-center justify-between rounded-2xl border border-white/10 bg-slate-950/55 px-4 py-3 shadow-2xl shadow-black/20 backdrop-blur-xl">
          <div className="flex items-center gap-3">
            <div className="logo-pulse flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-300/30 bg-cyan-300/10 text-lg font-black text-cyan-100">
              D
            </div>
            <div>
              <p className="text-sm font-semibold text-white">Dark Intel</p>
              <p className="text-xs text-slate-500">OSINT simulation console</p>
            </div>
          </div>
          <div className="hidden items-center gap-1 rounded-full border border-white/10 bg-white/[0.04] p-1 md:flex">
            {navItems.map((item) => (
              <a key={item} href={`#${item.toLowerCase()}`} className="rounded-full px-4 py-2 text-xs font-medium text-slate-400 transition hover:bg-white/10 hover:text-white">
                {item}
              </a>
            ))}
          </div>
          <a href="/flask" className="hidden rounded-full border border-cyan-300/25 px-4 py-2 text-xs font-semibold text-cyan-100 transition hover:border-cyan-200/60 hover:bg-cyan-300/10 sm:inline-flex">
            Flask UI
          </a>
        </nav>

        <section id="overview" className="hero-enter mb-8 grid gap-6 lg:grid-cols-[1.2fr_0.8fr] lg:items-end">
          <div>
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-emerald-300/20 bg-emerald-300/10 px-3 py-1.5 text-xs font-medium text-emerald-100">
              <StatusDot />
              Local intelligence pipeline active
            </div>
            <h1 className="max-w-4xl text-4xl font-semibold tracking-tight text-white sm:text-6xl">
              Modern threat intelligence, tuned for fast investigation.
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-400">
              Monitor breach exposure, simulated dark web signals, alert activity, and report generation from a single live dashboard.
            </p>
          </div>
          <div className="rounded-3xl border border-white/10 bg-white/[0.055] p-5 shadow-2xl shadow-cyan-950/30 backdrop-blur-xl">
            <div className="mb-4 flex items-center justify-between">
              <p className="text-sm font-medium text-slate-200">Severity Mix</p>
              <span className="rounded-full bg-cyan-300/10 px-3 py-1 text-xs text-cyan-100">Live</span>
            </div>
            <div className="space-y-4">
              <MiniBar label="Critical" value={severityBreakdown.Critical || 0} max={stats?.total_breaches || 1} color="bg-rose-400" />
              <MiniBar label="High" value={severityBreakdown.High || 0} max={stats?.total_breaches || 1} color="bg-orange-400" />
              <MiniBar label="Medium" value={severityBreakdown.Medium || 0} max={stats?.total_breaches || 1} color="bg-amber-300" />
              <MiniBar label="Low" value={severityBreakdown.Low || 0} max={stats?.total_breaches || 1} color="bg-emerald-300" />
            </div>
          </div>
        </section>

        {message && (
          <div className="mb-5 rounded-2xl border border-white/10 bg-white/[0.06] px-4 py-3 text-sm text-slate-300 shadow-xl backdrop-blur-xl">
            {message}
          </div>
        )}

        <section className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <StatCard label="Breaches" value={stats?.total_breaches ?? breaches.length} detail="ingested records" tone="cyan" delay={0} />
          <StatCard label="Affected Users" value={totalAffected.toLocaleString()} detail="total exposed identities" tone="violet" delay={80} />
          <StatCard label="Dark Web Hits" value={stats?.dark_web_hits ?? darkStats?.total_leaks ?? 0} detail="simulated sources" tone="amber" delay={160} />
          <StatCard label="Alerts" value={alerts?.total_alerts ?? 0} detail="logged report alerts" tone="emerald" delay={240} />
        </section>

        <section className="mt-7 grid gap-6 lg:grid-cols-[1fr_380px]">
          <div id="breaches" className="reveal-card rounded-3xl border border-white/10 bg-white/[0.055] shadow-2xl shadow-black/20 backdrop-blur-xl">
            <div className="flex flex-col gap-3 border-b border-white/10 px-5 py-5 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-lg font-semibold text-white">Breach Exposure</h2>
                <p className="text-sm text-slate-500">Highest impact records from the local SQLite dataset.</p>
              </div>
              <span className="rounded-full border border-white/10 bg-slate-950/50 px-3 py-1 text-xs text-slate-300">
                {breaches.length} records
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px] text-left text-sm">
                <thead className="text-xs uppercase tracking-[0.18em] text-slate-500">
                  <tr>
                    <th className="px-5 py-4">Source</th>
                    <th className="px-5 py-4">Date</th>
                    <th className="px-5 py-4">Data Type</th>
                    <th className="px-5 py-4">Exposure</th>
                    <th className="px-5 py-4">Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {breaches.map((item, index) => (
                    <tr key={item.id ?? `${item.source}-${item.breach_date}`} className="table-row-animate border-t border-white/5 transition hover:bg-white/[0.055]" style={{ animationDelay: `${index * 45}ms` }}>
                      <td className="px-5 py-4">
                        <p className="font-medium text-slate-100">{item.source}</p>
                        <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-900">
                          <div className="h-full rounded-full bg-gradient-to-r from-cyan-300 to-violet-300" style={{ width: `${Math.max(8, (Number(item.affected_count || 0) / maxAffected) * 100)}%` }} />
                        </div>
                      </td>
                      <td className="px-5 py-4 text-slate-400">{item.breach_date}</td>
                      <td className="px-5 py-4 text-slate-400">{item.data_type}</td>
                      <td className="px-5 py-4 text-slate-300">{Number(item.affected_count || 0).toLocaleString()}</td>
                      <td className="px-5 py-4"><SeverityBadge value={item.severity} /></td>
                    </tr>
                  ))}
                  {breaches.length === 0 && (
                    <tr>
                      <td className="px-5 py-10 text-center text-slate-500" colSpan={5}>
                        No breach records loaded yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <aside className="space-y-6">
            <section id="report" className="reveal-card rounded-3xl border border-cyan-200/15 bg-cyan-200/[0.06] p-5 shadow-2xl shadow-cyan-950/30 backdrop-blur-xl">
              <div className="mb-5 flex items-start justify-between gap-4">
                <div>
                  <h2 className="text-lg font-semibold text-white">Generate PDF Report</h2>
                  <p className="mt-1 text-sm leading-6 text-slate-400">Run the assessment pipeline and create a downloadable PDF.</p>
                </div>
                <div className="rounded-2xl border border-cyan-200/20 bg-cyan-200/10 px-3 py-2 text-xs font-semibold text-cyan-100">
                  PDF
                </div>
              </div>
              <div className="space-y-3">
                <input
                  className="w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-300/60 focus:ring-4 focus:ring-cyan-300/10"
                  placeholder="name@example.com"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                />
                <button
                  className="button-shine w-full rounded-2xl bg-gradient-to-r from-cyan-300 to-violet-300 px-4 py-3 text-sm font-bold text-slate-950 shadow-xl shadow-cyan-950/30 transition hover:-translate-y-0.5 hover:shadow-cyan-500/20 disabled:cursor-wait disabled:opacity-60"
                  onClick={generateReport}
                  disabled={loadingReport}
                >
                  {loadingReport ? "Generating..." : "Generate Report"}
                </button>
              </div>
              {report && (
                <div className="mt-4 rounded-2xl border border-white/10 bg-slate-950/60 p-4 text-sm report-pop">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <p className="text-xs text-slate-500">Risk</p>
                      <p className="mt-1 font-semibold text-white">{report.risk_label}</p>
                    </div>
                    <div>
                      <p className="text-xs text-slate-500">Score</p>
                      <p className="mt-1 font-semibold text-white">{report.score}</p>
                    </div>
                  </div>
                  <a className="mt-4 inline-flex rounded-full bg-white/10 px-4 py-2 text-xs font-semibold text-cyan-100 transition hover:bg-white/15" href={report.pdf_url} target="_blank" rel="noreferrer">
                    Open PDF
                  </a>
                </div>
              )}
            </section>

            <section className="reveal-card rounded-3xl border border-white/10 bg-white/[0.055] p-5 shadow-2xl shadow-black/20 backdrop-blur-xl">
              <h2 className="text-lg font-semibold text-white">Dark Web Simulation</h2>
              <dl className="mt-4 space-y-3 text-sm">
                <div className="flex justify-between gap-4 rounded-2xl bg-slate-950/45 p-3">
                  <dt className="text-slate-500">Total leaks</dt>
                  <dd className="font-medium text-slate-100">{darkStats?.total_leaks ?? 0}</dd>
                </div>
                <div className="flex justify-between gap-4 rounded-2xl bg-slate-950/45 p-3">
                  <dt className="text-slate-500">Verified leaks</dt>
                  <dd className="font-medium text-slate-100">{darkStats?.verified_leaks ?? 0}</dd>
                </div>
                <div className="rounded-2xl bg-slate-950/45 p-3">
                  <dt className="text-slate-500">Last scan</dt>
                  <dd className="mt-1 text-slate-100">{darkStats?.last_scan ?? "Not yet"}</dd>
                </div>
              </dl>
            </section>
          </aside>
        </section>
      </div>
    </main>
  );
}
