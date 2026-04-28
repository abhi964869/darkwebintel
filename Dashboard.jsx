// Dashboard.jsx — Main overview page
// Shows stat cards, threat trends chart, category breakdown, and top IOCs

import { useState, useEffect } from "react";
import { dashboardApi } from "../api";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell
} from "recharts";

// ── Severity colour mapping ───────────────────────────────────────────────
const SEV_COLOR = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
};

const CAT_COLORS = ["#6366f1", "#06b6d4", "#f59e0b", "#10b981",
                    "#ec4899", "#8b5cf6", "#f43f5e", "#14b8a6"];

// ── Stat Card ─────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, accent = "#6366f1" }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">{label}</p>
      <p className="text-3xl font-bold" style={{ color: accent }}>{value ?? "—"}</p>
      {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
    </div>
  );
}

export default function Dashboard() {
  const [stats,  setStats]  = useState(null);
  const [trends, setTrends] = useState([]);
  const [cats,   setCats]   = useState([]);
  const [iocs,   setIocs]   = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      dashboardApi.stats(),
      dashboardApi.trends(),
      dashboardApi.categories(),
      dashboardApi.topIocs(),
    ])
      .then(([s, t, c, i]) => {
        setStats(s.data);
        setTrends(t.data.data);
        setCats(c.data.data);
        setIocs(i.data.data);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <p className="text-gray-500 text-sm">Loading dashboard…</p>;
  }

  return (
    <div className="space-y-8 max-w-6xl">
      {/* ── Section header ── */}
      <div>
        <h1 className="text-xl font-semibold text-gray-100">Threat Intelligence Overview</h1>
        <p className="text-sm text-gray-500 mt-1">Real-time dark web monitoring dashboard</p>
      </div>

      {/* ── Stat cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard label="Total Threats"  value={stats?.total_threats} sub="all time" />
        <StatCard label="Critical"       value={stats?.critical}      accent="#ef4444" />
        <StatCard label="High"           value={stats?.high}          accent="#f97316" />
        <StatCard label="Last 24 h"      value={stats?.last_24h}      sub="new threats" accent="#06b6d4" />
        <StatCard label="New Alerts"     value={stats?.new_alerts}    sub="for you" accent="#f59e0b" />
      </div>

      {/* ── Trend chart ── */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h2 className="text-sm font-medium text-gray-300 mb-4">Threats — last 30 days</h2>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={trends} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
            <XAxis dataKey="date" tick={{ fill: "#6b7280", fontSize: 11 }}
                   tickFormatter={d => d.slice(5)} interval="preserveStartEnd" />
            <YAxis tick={{ fill: "#6b7280", fontSize: 11 }} />
            <Tooltip
              contentStyle={{ background: "#111827", border: "1px solid #374151", borderRadius: 8 }}
              labelStyle={{ color: "#d1d5db" }}
              itemStyle={{ color: "#818cf8" }}
            />
            <Line type="monotone" dataKey="count" stroke="#818cf8"
                  strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* ── Categories + Top IOCs ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

        {/* Categories bar chart */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="text-sm font-medium text-gray-300 mb-4">Threats by category</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={cats} layout="vertical" margin={{ left: 20 }}>
              <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 11 }} />
              <YAxis type="category" dataKey="category" width={120}
                     tick={{ fill: "#9ca3af", fontSize: 11 }}
                     tickFormatter={v => v.replace(/_/g, " ")} />
              <Tooltip
                contentStyle={{ background: "#111827", border: "1px solid #374151", borderRadius: 8 }}
                cursor={{ fill: "rgba(255,255,255,0.03)" }}
              />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {cats.map((_, i) => (
                  <Cell key={i} fill={CAT_COLORS[i % CAT_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top IOCs list */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="text-sm font-medium text-gray-300 mb-4">Top Indicators of Compromise</h2>
          <div className="space-y-2 overflow-y-auto max-h-[220px]">
            {iocs.slice(0, 15).map((item, i) => (
              <div key={i} className="flex items-center justify-between text-xs">
                <span className="font-mono text-indigo-400 truncate max-w-[70%]">{item.ioc}</span>
                <span className="ml-2 bg-gray-800 text-gray-400 px-2 py-0.5 rounded-full">
                  {item.count}
                </span>
              </div>
            ))}
            {iocs.length === 0 && (
              <p className="text-gray-600 text-xs">No IOCs yet — run the ingestor first.</p>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
