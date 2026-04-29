import { useEffect, useMemo, useState } from "react";

const severityStyles = {
  Critical: "border-rose-400/40 bg-rose-500/10 text-rose-100 shadow-rose-500/10",
  High: "border-orange-400/40 bg-orange-500/10 text-orange-100 shadow-orange-500/10",
  Medium: "border-amber-400/40 bg-amber-500/10 text-amber-100 shadow-amber-500/10",
  Low: "border-emerald-400/40 bg-emerald-500/10 text-emerald-100 shadow-emerald-500/10",
};

const navItems = ["Overview", "Breaches", "Intel", "Reports"];
const TOKEN_KEY = "dark_intel_token";

function classNames(...parts) {
  return parts.filter(Boolean).join(" ");
}

function SeverityBadge({ value }) {
  const classes = severityStyles[value] || "border-slate-500/30 bg-slate-500/10 text-slate-200";
  return <span className={classNames("inline-flex rounded-full border px-2.5 py-1 text-xs font-medium shadow-lg", classes)}>{value || "Unknown"}</span>;
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

function StatusDot() {
  return (
    <span className="relative flex h-3 w-3">
      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
      <span className="relative inline-flex h-3 w-3 rounded-full bg-emerald-300" />
    </span>
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
          <p className="text-sm font-semibold text-white">{item.target_email}</p>
          <p className="mt-1 text-xs text-slate-500">{item.created_at}</p>
        </div>
        <SeverityBadge value={item.risk_label} />
      </div>
      <p className="mt-3 text-sm text-slate-400">{item.summary}</p>
      <p className="mt-3 text-xs text-cyan-200">Score: {item.score}</p>
    </div>
  );
}

function WatchlistCard({ item, onDelete }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/45 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-white">{item.query_value}</p>
          <p className="mt-1 text-xs text-slate-500">{item.query_type} monitored item</p>
        </div>
        <SeverityBadge value={item.latest_severity || "Low"} />
      </div>
      {item.notes && <p className="mt-3 text-sm text-slate-400">{item.notes}</p>}
      <div className="mt-4 flex items-center justify-between">
        <p className="text-xs text-slate-500">Status: {item.latest_status || "pending"}</p>
        <button onClick={() => onDelete(item.id)} className="rounded-full border border-rose-300/20 px-3 py-1 text-xs text-rose-100 transition hover:bg-rose-400/10">
          Remove
        </button>
      </div>
    </div>
  );
}

function AuthScreen({ mode, setMode, form, setForm, onSubmit, error, loading }) {
  return (
    <main className="relative min-h-screen overflow-hidden bg-[#050816] text-slate-100">
      <div className="mesh-bg" />
      <div className="grid-glow" />
      <div className="relative mx-auto flex min-h-screen max-w-6xl items-center px-4 py-10 sm:px-6 lg:px-8">
        <div className="grid w-full gap-10 lg:grid-cols-[1.05fr_0.95fr]">
          <section className="hero-enter">
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-emerald-300/20 bg-emerald-300/10 px-3 py-1.5 text-xs font-medium text-emerald-100">
              <StatusDot />
              Premium cyber intelligence workspace
            </div>
            <h1 className="max-w-3xl text-4xl font-semibold tracking-tight text-white sm:text-6xl">
              Personal threat monitoring with saved user data and live intelligence.
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-400">
              Create an account to monitor domains, store your reports, save internet lookups, and work from a single premium command center.
            </p>
            <div className="mt-8 grid gap-4 sm:grid-cols-3">
              <StatCard label="Accounts" value="Secure" detail="stored in SQLite" tone="cyan" />
              <StatCard label="Monitoring" value="Watchlists" detail="saved per user" tone="gold" delay={80} />
              <StatCard label="Reports" value="Persistent" detail="premium workspace" tone="emerald" delay={160} />
            </div>
          </section>

          <section className="reveal-card rounded-[2rem] border border-white/10 bg-slate-950/70 p-6 shadow-2xl shadow-black/30 backdrop-blur-xl sm:p-8">
            <div className="mb-6 flex items-center justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.25em] text-cyan-200">Dark Intel</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">{mode === "login" ? "Welcome back" : "Create your premium account"}</h2>
              </div>
              <div className="rounded-full border border-white/10 bg-white/[0.04] p-1">
                {["login", "register"].map((item) => (
                  <button
                    key={item}
                    onClick={() => setMode(item)}
                    className={classNames(
                      "rounded-full px-4 py-2 text-xs font-medium capitalize transition",
                      mode === item ? "bg-cyan-300 text-slate-950" : "text-slate-400 hover:text-white",
                    )}
                  >
                    {item}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-4">
              {mode === "register" && (
                <>
                  <input
                    className="w-full rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-300/60 focus:ring-4 focus:ring-cyan-300/10"
                    placeholder="Full name"
                    value={form.full_name}
                    onChange={(event) => setForm((current) => ({ ...current, full_name: event.target.value }))}
                  />
                  <input
                    className="w-full rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-300/60 focus:ring-4 focus:ring-cyan-300/10"
                    placeholder="Company"
                    value={form.company}
                    onChange={(event) => setForm((current) => ({ ...current, company: event.target.value }))}
                  />
                </>
              )}

              <input
                className="w-full rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-300/60 focus:ring-4 focus:ring-cyan-300/10"
                placeholder="Email address"
                value={form.email}
                onChange={(event) => setForm((current) => ({ ...current, email: event.target.value }))}
              />
              <input
                type="password"
                className="w-full rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-300/60 focus:ring-4 focus:ring-cyan-300/10"
                placeholder="Password"
                value={form.password}
                onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
                onKeyDown={(event) => event.key === "Enter" && onSubmit()}
              />
              {error && <p className="rounded-2xl border border-rose-400/20 bg-rose-400/10 px-4 py-3 text-sm text-rose-100">{error}</p>}
              <button
                onClick={onSubmit}
                disabled={loading}
                className="button-shine w-full rounded-2xl bg-gradient-to-r from-cyan-300 to-violet-300 px-4 py-3 text-sm font-bold text-slate-950 shadow-xl shadow-cyan-950/30 transition hover:-translate-y-0.5 hover:shadow-cyan-500/20 disabled:cursor-wait disabled:opacity-60"
              >
                {loading ? "Please wait..." : mode === "login" ? "Sign In" : "Create Premium Account"}
              </button>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || "");
  const [user, setUser] = useState(null);
  const [authMode, setAuthMode] = useState("login");
  const [authForm, setAuthForm] = useState({ full_name: "", company: "", email: "", password: "" });
  const [authError, setAuthError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);

  const [stats, setStats] = useState(null);
  const [breaches, setBreaches] = useState([]);
  const [darkStats, setDarkStats] = useState(null);
  const [alerts, setAlerts] = useState(null);
  const [watchlist, setWatchlist] = useState([]);
  const [history, setHistory] = useState([]);
  const [reports, setReports] = useState([]);

  const [liveQuery, setLiveQuery] = useState("gmail.com");
  const [liveIntel, setLiveIntel] = useState(null);
  const [loadingIntel, setLoadingIntel] = useState(false);

  const [watchlistForm, setWatchlistForm] = useState({ query_value: "", query_type: "domain", notes: "" });
  const [watchlistLoading, setWatchlistLoading] = useState(false);

  const [email, setEmail] = useState("");
  const [report, setReport] = useState(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [message, setMessage] = useState("");

  const apiFetch = async (path, options = {}) => {
    const headers = new Headers(options.headers || {});
    if (!headers.has("Content-Type") && options.body) {
      headers.set("Content-Type", "application/json");
    }
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }

    const response = await fetch(path, { ...options, headers });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.error || "Request failed.");
    }
    return data;
  };

  const loadPublicData = async () => {
    const [statsData, breachData, darkData, alertData] = await Promise.all([
      apiFetch("/api/stats"),
      apiFetch("/api/breaches"),
      apiFetch("/api/darkweb/stats"),
      apiFetch("/api/alerts/stats"),
    ]);
    setStats(statsData);
    setBreaches(Array.isArray(breachData) ? breachData : []);
    setDarkStats(darkData);
    setAlerts(alertData);
  };

  const loadPrivateData = async () => {
    const [watchlistData, historyData, reportsData] = await Promise.all([
      apiFetch("/api/user/watchlist"),
      apiFetch("/api/user/history"),
      apiFetch("/api/user/reports"),
    ]);
    setWatchlist(watchlistData.items || []);
    setHistory(historyData.items || []);
    setReports(reportsData.items || []);
  };

  useEffect(() => {
    loadPublicData().catch(() => setMessage("Could not reach the backend."));
  }, []);

  useEffect(() => {
    if (!token) {
      setUser(null);
      return;
    }

    apiFetch("/api/auth/me")
      .then((data) => {
        setUser(data);
        return loadPrivateData();
      })
      .catch(() => {
        localStorage.removeItem(TOKEN_KEY);
        setToken("");
        setUser(null);
      });
  }, [token]);

  useEffect(() => {
    runLiveLookup("gmail.com");
  }, [token]);

  const totalAffected = useMemo(() => breaches.reduce((sum, item) => sum + Number(item.affected_count || 0), 0), [breaches]);
  const maxAffected = useMemo(() => Math.max(...breaches.map((item) => Number(item.affected_count || 0)), 1), [breaches]);

  const handleAuthSubmit = async () => {
    setAuthError("");
    setAuthLoading(true);
    try {
      const endpoint = authMode === "login" ? "/api/auth/login" : "/api/auth/register";
      const payload = authMode === "login"
        ? { email: authForm.email, password: authForm.password }
        : authForm;
      const data = await apiFetch(endpoint, { method: "POST", body: JSON.stringify(payload), headers: {} });
      localStorage.setItem(TOKEN_KEY, data.token);
      setToken(data.token);
      setUser(data.user);
      setAuthForm({ full_name: "", company: "", email: "", password: "" });
      setMessage(`Welcome, ${data.user.full_name}.`);
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setAuthLoading(false);
    }
  };

  const logout = async () => {
    try {
      await apiFetch("/api/auth/logout", { method: "POST" });
    } catch {
      // no-op
    }
    localStorage.removeItem(TOKEN_KEY);
    setToken("");
    setUser(null);
    setWatchlist([]);
    setHistory([]);
    setReports([]);
    setMessage("Signed out.");
  };

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
        body: JSON.stringify({ query }),
      });
      setLiveIntel(data);
      if (user) {
        await loadPrivateData();
      }
    } catch (error) {
      setMessage(error.message);
      setLiveIntel(null);
    } finally {
      setLoadingIntel(false);
    }
  };

  const addWatchlistItem = async () => {
    if (watchlistForm.query_value.trim().length < 2) {
      setMessage("Watchlist items need at least 2 characters.");
      return;
    }
    setWatchlistLoading(true);
    try {
      await apiFetch("/api/user/watchlist", {
        method: "POST",
        body: JSON.stringify(watchlistForm),
      });
      setWatchlistForm({ query_value: "", query_type: "domain", notes: "" });
      await loadPrivateData();
      setMessage("Watchlist item saved.");
    } catch (error) {
      setMessage(error.message);
    } finally {
      setWatchlistLoading(false);
    }
  };

  const deleteWatchlistItem = async (id) => {
    try {
      await apiFetch(`/api/user/watchlist/${id}`, { method: "DELETE" });
      await loadPrivateData();
      setMessage("Watchlist item removed.");
    } catch (error) {
      setMessage(error.message);
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
      if (user) {
        await loadPrivateData();
      }
      setMessage("Report generated and saved to your workspace.");
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoadingReport(false);
    }
  };

  if (!user) {
    return (
      <AuthScreen
        mode={authMode}
        setMode={setAuthMode}
        form={authForm}
        setForm={setAuthForm}
        onSubmit={handleAuthSubmit}
        error={authError}
        loading={authLoading}
      />
    );
  }

  const severityBreakdown = stats?.severity_breakdown || {};

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
              <p className="text-xs text-slate-500">{user.company || "Independent analyst"} • {user.plan_name}</p>
            </div>
          </div>
          <div className="hidden items-center gap-1 rounded-full border border-white/10 bg-white/[0.04] p-1 md:flex">
            {navItems.map((item) => (
              <a key={item} href={`#${item.toLowerCase()}`} className="rounded-full px-4 py-2 text-xs font-medium text-slate-400 transition hover:bg-white/10 hover:text-white">
                {item}
              </a>
            ))}
          </div>
          <div className="flex items-center gap-3">
            <div className="text-right">
              <p className="text-sm font-medium text-white">{user.full_name}</p>
              <p className="text-xs text-slate-500">{user.email}</p>
            </div>
            <button onClick={logout} className="rounded-full border border-white/10 px-4 py-2 text-xs font-semibold text-cyan-100 transition hover:bg-white/10">
              Sign Out
            </button>
          </div>
        </nav>

        <section id="overview" className="hero-enter mb-8 grid gap-6 lg:grid-cols-[1.2fr_0.8fr] lg:items-end">
          <div>
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-emerald-300/20 bg-emerald-300/10 px-3 py-1.5 text-xs font-medium text-emerald-100">
              <StatusDot />
              Premium workspace active
            </div>
            <h1 className="max-w-4xl text-4xl font-semibold tracking-tight text-white sm:text-6xl">
              Store your users, watchlists, reports, and intelligence in one polished backend.
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-400">
              Your account is backed by SQLite storage and live API routes. Save internet lookups, monitor assets, and keep premium report history without leaving this dashboard.
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
          <StatCard label="Watchlist" value={watchlist.length} detail="assets under monitoring" tone="gold" delay={80} />
          <StatCard label="Lookup History" value={history.length} detail="saved live searches" tone="emerald" delay={160} />
          <StatCard label="Saved Reports" value={reports.length} detail="premium stored reports" tone="rose" delay={240} />
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
              subtitle="Search public web coverage for a company, domain, or provider."
              action={
                <span className="rounded-2xl border border-sky-200/20 bg-sky-200/10 px-3 py-2 text-xs font-semibold text-sky-100">
                  Live
                </span>
              }
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

            <Panel
              title="Watchlist"
              subtitle="Store high-value targets for recurring monitoring."
              action={<span className="rounded-full bg-white/10 px-3 py-1 text-xs text-slate-300">{watchlist.length} items</span>}
            >
              <div className="space-y-3">
                <input
                  className="w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-300/60 focus:ring-4 focus:ring-cyan-300/10"
                  placeholder="example.com"
                  value={watchlistForm.query_value}
                  onChange={(event) => setWatchlistForm((current) => ({ ...current, query_value: event.target.value }))}
                />
                <input
                  className="w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-300/60 focus:ring-4 focus:ring-cyan-300/10"
                  placeholder="Optional notes"
                  value={watchlistForm.notes}
                  onChange={(event) => setWatchlistForm((current) => ({ ...current, notes: event.target.value }))}
                />
                <button
                  className="w-full rounded-2xl bg-gradient-to-r from-cyan-300 to-violet-300 px-4 py-3 text-sm font-bold text-slate-950 shadow-xl shadow-cyan-950/30 transition hover:-translate-y-0.5 hover:shadow-cyan-500/20 disabled:cursor-wait disabled:opacity-60"
                  onClick={addWatchlistItem}
                  disabled={watchlistLoading}
                >
                  {watchlistLoading ? "Saving..." : "Save to Watchlist"}
                </button>
              </div>
              <div className="mt-4 space-y-3">
                {watchlist.slice(0, 3).map((item) => (
                  <WatchlistCard key={item.id} item={item} onDelete={deleteWatchlistItem} />
                ))}
                {watchlist.length === 0 && <p className="text-sm text-slate-500">No watchlist items yet.</p>}
              </div>
            </Panel>

            <Panel title="Generate Premium Report" subtitle="Create a risk report and save it to your account.">
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
                  {loadingReport ? "Generating..." : "Generate & Save Report"}
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
          </div>
        </section>

        <section className="mt-7 grid gap-6 xl:grid-cols-3">
          <Panel title="Internet Results" subtitle="Live public intelligence pulled from the web.">
            <div className="space-y-4">
              {liveIntel?.results?.map((item, index) => <IntelResultCard key={`${item.link}-${index}`} item={item} />)}
              {(!liveIntel?.results || liveIntel.results.length === 0) && <p className="text-sm text-slate-500">Run a live search to display current web results.</p>}
            </div>
          </Panel>

          <Panel title="Saved Lookup History" subtitle="Recent internet lookups stored for this user account.">
            <div className="space-y-4">
              {history.map((item) => <HistoryCard key={item.id} item={item} />)}
              {history.length === 0 && <p className="text-sm text-slate-500">No saved lookup history yet.</p>}
            </div>
          </Panel>

          <Panel id="reports" title="Saved Reports" subtitle="Premium reports attached to your account.">
            <div className="space-y-4">
              {reports.map((item) => <ReportCard key={item.id} item={item} />)}
              {reports.length === 0 && <p className="text-sm text-slate-500">No saved reports yet.</p>}
            </div>
          </Panel>
        </section>
      </div>
    </main>
  );
}
