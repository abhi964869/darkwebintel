import { useEffect, useMemo, useState } from "react";

const severityStyles = {
  Critical: "border-rose-400/40 bg-rose-500/10 text-rose-100 shadow-rose-500/10",
  High: "border-orange-400/40 bg-orange-500/10 text-orange-100 shadow-orange-500/10",
  Medium: "border-amber-400/40 bg-amber-500/10 text-amber-100 shadow-amber-500/10",
  Low: "border-emerald-400/40 bg-emerald-500/10 text-emerald-100 shadow-emerald-500/10",
};

const navItems = ["Overview", "Breaches", "Intel", "Archive"];

function classNames(...parts) {
  return parts.filter(Boolean).join(" ");
}

function SeverityBadge({ value }) {
  const classes = severityStyles[value] || "border-slate-500/30 bg-slate-500/10 text-slate-200";
  return <span className={classNames("inline-flex rounded-full border px-2.5 py-1 text-xs font-medium shadow-lg", classes)}>{value || "Unknown"}</span>;
}

function StatusDot() {
  return (
    <span className="relative flex h-3 w-3">
      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
      <span className="relative inline-flex h-3 w-3 rounded-full bg-emerald-300" />
    </span>
  );
}

function StatCard({ label, value, detail, tone = "cyan", delay = 0 }) {
  const tones = {
    cyan: "from-cyan-400/20 to-sky-500/5 text-cyan-200",
    gold: "from-amber-300/20 to-orange-500/5 text-amber-100",
    emerald: "from-emerald-400/20 to-teal-500/5 text-emerald-200",
    rose: "from-rose-400/20 to-red-500/5 text-rose-100",
  };

  return (
    <section className="reveal-card group relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.055] p-5 shadow-2xl shadow-black/20 backdrop-blur-xl" style={{ animationDelay: `${delay}ms` }}>
      <div className={classNames("absolute inset-x-0 top-0 h-px bg-gradient-to-r", tones[tone] || tones.cyan)} />
      <div className="absolute -right-8 -top-8 h-24 w-24 rounded-full bg-white/10 blur-2xl transition-transform duration-500 group-hover:scale-150" />
      <p className="text-xs uppercase tracking-[0.22em] text-slate-400">{label}</p>
      <p className="mt-3 text-3xl font-semibold text-white">{value}</p>
      {detail && <p className="mt-2 text-sm text-slate-400">{detail}</p>}
    </section>
  );
}

function Panel({ title, subtitle, action, children, id }) {
  return (
    <section id={id} className="reveal-card rounded-3xl border border-white/10 bg-white/[0.055] p-5 shadow-2xl shadow-black/20 backdrop-blur-xl">
      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          {subtitle && <p className="mt-1 text-sm text-slate-500">{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function IntelResultCard({ item }) {
  return (
    <a href={item.link} target="_blank" rel="noreferrer" className="block rounded-2xl border border-white/10 bg-slate-950/55 p-4 transition hover:border-cyan-300/30 hover:bg-slate-950/75">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-white">{item.title}</p>
          <p className="mt-1 text-xs text-slate-500">{item.source}</p>
        </div>
        <SeverityBadge value={item.severity} />
      </div>
      <p className="mt-3 text-sm leading-6 text-slate-400">{item.summary || "Open the result to view more details."}</p>
      <p className="mt-3 text-xs text-cyan-200">{item.published_at}</p>
    </a>
  );
}

function HistoryCard({ item }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/45 p-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-white">{item.query_value}</p>
          <p className="mt-1 text-xs text-slate-500">{item.created_at}</p>
        </div>
        <span className="rounded-full bg-white/10 px-3 py-1 text-xs text-slate-300">{item.result_count} results</span>
      </div>
      <div className="mt-3 space-y-2">
        {item.top_results?.map((result, index) => (
          <div key={`${result.link}-${index}`} className="rounded-xl bg-white/[0.03] p-3">
            <p className="text-sm text-slate-200">{result.title}</p>
            <p className="mt-1 text-xs text-slate-500">{result.source}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReportCard({ item }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/45 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-white">{item.created_at}</p>
          <p className="mt-1 text-xs text-slate-500">Saved report</p>
        </div>
        <SeverityBadge value={item.risk_label} />
      </div>
      <p className="mt-3 text-sm text-slate-400">{item.summary}</p>
      <p className="mt-3 text-xs text-cyan-200">Score: {item.score}</p>
    </div>
  );
}

function StoredEmailCard({ item, active, onSelect }) {
  return (
    <button
      onClick={() => onSelect(item.email)}
      className={classNames(
        "w-full rounded-2xl border p-4 text-left transition",
        active ? "border-cyan-300/50 bg-cyan-300/10" : "border-white/10 bg-slate-950/45 hover:bg-slate-950/65",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-white">{item.email}</p>
          <p className="mt-1 text-xs text-slate-500">{item.domain}</p>
        </div>
        <SeverityBadge value={item.last_risk_label || "Low"} />
      </div>
      <div className="mt-3 flex items-center gap-3 text-xs text-slate-400">
        <span>{item.lookup_count} lookups</span>
        <span>{item.report_count} reports</span>
      </div>
      {item.last_summary && <p className="mt-3 text-sm text-slate-400">{item.last_summary}</p>}
    </button>
  );
}

export default function App() {
  const [stats, setStats] = useState(null);
  const [breaches, setBreaches] = useState([]);
  const [darkStats, setDarkStats] = useState(null);
  const [alerts, setAlerts] = useState(null);

  const [storedEmails, setStoredEmails] = useState([]);
  const [selectedEmail, setSelectedEmail] = useState("");
  const [selectedRecords, setSelectedRecords] = useState({ history: [], reports: [] });

  const [liveQuery, setLiveQuery] = useState("gmail.com");
  const [liveIntel, setLiveIntel] = useState(null);
  const [loadingIntel, setLoadingIntel] = useState(false);

  const [email, setEmail] = useState("");
  const [report, setReport] = useState(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [message, setMessage] = useState("");

  const apiFetch = async (path, options = {}) => {
    const headers = new Headers(options.headers || {});
    if (!headers.has("Content-Type") && options.body) {
      headers.set("Content-Type", "application/json");
    }
    const response = await fetch(path, { ...options, headers });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.error || "Request failed.");
    }
    return data;
  };

  const loadPublicData = async () => {
    const [statsData, breachData, darkData, alertData, storedData] = await Promise.all([
      apiFetch("/api/stats"),
      apiFetch("/api/breaches"),
      apiFetch("/api/darkweb/stats"),
      apiFetch("/api/alerts/stats"),
      apiFetch("/api/tracked-emails"),
    ]);
    setStats(statsData);
    setBreaches(Array.isArray(breachData) ? breachData : []);
    setDarkStats(darkData);
    setAlerts(alertData);
    setStoredEmails(storedData.items || []);
    if (!selectedEmail && storedData.items?.length) {
      setSelectedEmail(storedData.items[0].email);
    }
  };

  const loadEmailRecords = async (targetEmail) => {
    if (!targetEmail) {
      setSelectedRecords({ history: [], reports: [] });
      return;
    }
    const data = await apiFetch(`/api/email-records?email=${encodeURIComponent(targetEmail)}`);
    setSelectedRecords({ history: data.history || [], reports: data.reports || [] });
  };

  useEffect(() => {
    loadPublicData().catch(() => setMessage("Could not reach the backend."));
  }, []);

  useEffect(() => {
    if (selectedEmail) {
      loadEmailRecords(selectedEmail).catch(() => setMessage("Could not load stored email records."));
    }
  }, [selectedEmail]);

  useEffect(() => {
    runLiveLookup("gmail.com");
  }, []);

  const totalAffected = useMemo(() => breaches.reduce((sum, item) => sum + Number(item.affected_count || 0), 0), [breaches]);
  const maxAffected = useMemo(() => Math.max(...breaches.map((item) => Number(item.affected_count || 0)), 1), [breaches]);
  const severityBreakdown = stats?.severity_breakdown || {};

  const runLiveLookup = async (queryOverride) => {
    const query = (queryOverride ?? liveQuery).trim();
    if (query.length < 2) {
      setMessage("Enter a valid domain or organization to search.");
      return;
    }

    setLoadingIntel(true);
    try {
      const data = await apiFetch("/api/intel/live", {
        method: "POST",
        body: JSON.stringify({
          query,
          context_email: selectedEmail || email,
        }),
      });
      if (data.status === "error") {
        throw new Error(data.message || "Live internet lookup failed.");
      }
      setLiveIntel(data);
      if (selectedEmail || email) {
        await loadPublicData();
        await loadEmailRecords(selectedEmail || email);
      }
      setMessage(`Loaded ${data.count} live results for ${data.query}.`);
    } catch (error) {
      setMessage(error.message);
      setLiveIntel(null);
    } finally {
      setLoadingIntel(false);
    }
  };

  const generateReport = async () => {
    if (!email.includes("@")) {
      setMessage("Enter a valid email address.");
      return;
    }

    setLoadingReport(true);
    try {
      const data = await apiFetch("/api/report/generate", {
        method: "POST",
        body: JSON.stringify({ email }),
      });
      setReport(data);
      setSelectedEmail(email.toLowerCase());
      await loadPublicData();
      await loadEmailRecords(email.toLowerCase());
      setMessage("Report generated and stored for this email.");
      setLiveQuery(email.split("@")[1]);
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoadingReport(false);
    }
  };

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#050816] text-slate-100">
      <div className="mesh-bg" />
      <div className="grid-glow" />

      <div className="relative mx-auto max-w-7xl px-4 py-5 sm:px-6 lg:px-8">
        <nav className="sticky top-4 z-20 mb-8 flex flex-col gap-4 rounded-2xl border border-white/10 bg-slate-950/55 px-4 py-3 shadow-2xl shadow-black/20 backdrop-blur-xl sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="logo-pulse flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-300/30 bg-cyan-300/10 text-lg font-black text-cyan-100">
              D
            </div>
            <div>
              <p className="text-sm font-semibold text-white">Dark Intel Premium</p>
              <p className="text-xs text-slate-500">No login required • remembers previously used emails</p>
            </div>
          </div>
          <div className="hidden items-center gap-1 rounded-full border border-white/10 bg-white/[0.04] p-1 md:flex">
            {navItems.map((item) => (
              <a key={item} href={`#${item.toLowerCase()}`} className="rounded-full px-4 py-2 text-xs font-medium text-slate-400 transition hover:bg-white/10 hover:text-white">
                {item}
              </a>
            ))}
          </div>
        </nav>

        <section id="overview" className="hero-enter mb-8 grid gap-6 lg:grid-cols-[1.2fr_0.8fr] lg:items-end">
          <div>
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-emerald-300/20 bg-emerald-300/10 px-3 py-1.5 text-xs font-medium text-emerald-100">
              <StatusDot />
              Email memory workspace active
            </div>
            <h1 className="max-w-4xl text-4xl font-semibold tracking-tight text-white sm:text-6xl">
              Save the emails you investigate and reopen their intelligence instantly.
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-400">
              Generate a report for any email, run live internet lookups against it, and the dashboard will keep that email’s saved history and reports ready without asking anyone to sign in.
            </p>
          </div>
          <div className="rounded-3xl border border-white/10 bg-white/[0.055] p-5 shadow-2xl shadow-cyan-950/30 backdrop-blur-xl">
            <div className="mb-4 flex items-center justify-between">
              <p className="text-sm font-medium text-slate-200">Severity Mix</p>
              <span className="rounded-full bg-cyan-300/10 px-3 py-1 text-xs text-cyan-100">Live</span>
            </div>
            <div className="space-y-4">
              {["Critical", "High", "Medium", "Low"].map((level) => (
                <div key={level}>
                  <div className="mb-2 flex items-center justify-between text-xs text-slate-400">
                    <span>{level}</span>
                    <span>{severityBreakdown[level] || 0}</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-slate-900/80">
                    <div
                      className={classNames(
                        "h-full rounded-full bar-grow",
                        level === "Critical" ? "bg-rose-400" : level === "High" ? "bg-orange-400" : level === "Medium" ? "bg-amber-300" : "bg-emerald-300",
                      )}
                      style={{ "--bar-width": `${Math.max(6, Math.round(((severityBreakdown[level] || 0) / (stats?.total_breaches || 1)) * 100))}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {message && <div className="mb-5 rounded-2xl border border-white/10 bg-white/[0.06] px-4 py-3 text-sm text-slate-300 shadow-xl backdrop-blur-xl">{message}</div>}

        <section className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <StatCard label="Breaches" value={stats?.total_breaches ?? breaches.length} detail="ingested records" tone="cyan" delay={0} />
          <StatCard label="Affected Users" value={totalAffected.toLocaleString()} detail="total exposed identities" tone="gold" delay={80} />
          <StatCard label="Tracked Emails" value={storedEmails.length} detail="saved from previous use" tone="emerald" delay={160} />
          <StatCard label="Alerts" value={alerts?.total_alerts ?? 0} detail="logged report alerts" tone="rose" delay={240} />
        </section>

        <section className="mt-7 grid gap-6 lg:grid-cols-[1fr_380px]">
          <Panel id="breaches" title="Breach Exposure" subtitle="Highest impact records from the local SQLite dataset.">
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
                </tbody>
              </table>
            </div>
          </Panel>

          <div className="space-y-6">
            <Panel
              id="intel"
              title="Live Internet Intel"
              subtitle="Search public coverage and attach the results to the selected email."
              action={<span className="rounded-2xl border border-sky-200/20 bg-sky-200/10 px-3 py-2 text-xs font-semibold text-sky-100">Live</span>}
            >
              <div className="space-y-3">
                <input
                  className="w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-sky-300/60 focus:ring-4 focus:ring-sky-300/10"
                  placeholder="gmail.com or microsoft"
                  value={liveQuery}
                  onChange={(event) => setLiveQuery(event.target.value)}
                />
                <button
                  className="w-full rounded-2xl bg-gradient-to-r from-sky-300 to-cyan-300 px-4 py-3 text-sm font-bold text-slate-950 shadow-xl shadow-sky-950/30 transition hover:-translate-y-0.5 hover:shadow-sky-500/20 disabled:cursor-wait disabled:opacity-60"
                  onClick={() => runLiveLookup()}
                  disabled={loadingIntel}
                >
                  {loadingIntel ? "Searching..." : "Search Live Internet"}
                </button>
              </div>
              {liveIntel && (
                <div className="mt-4 rounded-2xl border border-white/10 bg-slate-950/60 p-4 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-xs text-slate-500">Query</p>
                      <p className="mt-1 font-semibold text-white">{liveIntel.query}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-slate-500">Matches</p>
                      <p className="mt-1 font-semibold text-white">{liveIntel.count}</p>
                    </div>
                  </div>
                  <p className="mt-3 text-xs leading-5 text-slate-400">{liveIntel.disclaimer}</p>
                </div>
              )}
            </Panel>

            <Panel title="Generate Report" subtitle="Create a report and store it under the email you enter.">
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
                  {loadingReport ? "Generating..." : "Generate & Store Report"}
                </button>
              </div>
              {report && (
                <div className="mt-4 rounded-2xl border border-white/10 bg-slate-950/60 p-4 text-sm">
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
                  <p className="mt-3 text-sm text-slate-400">{report.summary}</p>
                  <a className="mt-4 inline-flex rounded-full bg-white/10 px-4 py-2 text-xs font-semibold text-cyan-100 transition hover:bg-white/15" href={report.pdf_url} target="_blank" rel="noreferrer">
                    Open PDF
                  </a>
                </div>
              )}
            </Panel>

            <Panel title="Previously Used Emails" subtitle="Select an email to reopen its saved history and reports.">
              <div className="space-y-3">
                {storedEmails.map((item) => (
                  <StoredEmailCard key={item.email} item={item} active={selectedEmail === item.email} onSelect={setSelectedEmail} />
                ))}
                {storedEmails.length === 0 && <p className="text-sm text-slate-500">No emails stored yet. Generate a report first to start the archive.</p>}
              </div>
            </Panel>
          </div>
        </section>

        <section id="archive" className="mt-7 grid gap-6 xl:grid-cols-3">
          <Panel title="Internet Results" subtitle="Current live public intelligence for the active investigation.">
            <div className="space-y-4">
              {liveIntel?.results?.map((item, index) => <IntelResultCard key={`${item.link}-${index}`} item={item} />)}
              {(!liveIntel?.results || liveIntel.results.length === 0) && <p className="text-sm text-slate-500">Run a live search to display current web results.</p>}
            </div>
          </Panel>

          <Panel title="Saved Lookup History" subtitle={selectedEmail ? `Stored searches for ${selectedEmail}` : "Select an email to load its saved searches."}>
            <div className="space-y-4">
              {selectedRecords.history.map((item) => <HistoryCard key={item.id} item={item} />)}
              {selectedRecords.history.length === 0 && <p className="text-sm text-slate-500">No stored internet lookups for this email yet.</p>}
            </div>
          </Panel>

          <Panel title="Saved Reports" subtitle={selectedEmail ? `Stored reports for ${selectedEmail}` : "Select an email to load its saved reports."}>
            <div className="space-y-4">
              {selectedRecords.reports.map((item) => <ReportCard key={item.id} item={item} />)}
              {selectedRecords.reports.length === 0 && <p className="text-sm text-slate-500">No stored reports for this email yet.</p>}
            </div>
          </Panel>
        </section>
      </div>
    </main>
  );
}
