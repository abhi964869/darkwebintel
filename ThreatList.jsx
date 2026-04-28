// ThreatList.jsx — Paginated, searchable threat feed
import { useState, useEffect, useCallback } from "react";
import { threatApi } from "../api";

const SEV_BADGE = {
  critical: "bg-red-900 text-red-300",
  high:     "bg-orange-900 text-orange-300",
  medium:   "bg-yellow-900 text-yellow-300",
  low:      "bg-green-900 text-green-300",
};

function SeverityBadge({ severity }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${SEV_BADGE[severity] || "bg-gray-800 text-gray-400"}`}>
      {severity}
    </span>
  );
}

function ThreatRow({ threat, onClick }) {
  return (
    <tr className="border-t border-gray-800 hover:bg-gray-800/40 cursor-pointer transition-colors"
        onClick={() => onClick(threat)}>
      <td className="py-3 px-4">
        <p className="text-sm text-gray-200 font-medium line-clamp-1">{threat.title}</p>
        <p className="text-xs text-gray-500 mt-0.5">{threat.source}</p>
      </td>
      <td className="py-3 px-4 hidden md:table-cell">
        <span className="text-xs text-gray-400 bg-gray-800 px-2 py-0.5 rounded">
          {threat.category?.replace(/_/g, " ")}
        </span>
      </td>
      <td className="py-3 px-4"><SeverityBadge severity={threat.severity} /></td>
      <td className="py-3 px-4 text-xs text-gray-500 hidden lg:table-cell">
        {threat.created_at ? new Date(threat.created_at).toLocaleDateString() : "—"}
      </td>
      <td className="py-3 px-4 text-xs text-gray-500 hidden lg:table-cell">
        {threat.iocs?.length || 0} IOCs
      </td>
    </tr>
  );
}

function ThreatDetail({ threat, onClose }) {
  if (!threat) return null;
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4"
         onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-2xl max-h-[85vh] overflow-y-auto p-6"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-4">
          <h2 className="text-base font-medium text-gray-100 pr-4">{threat.title}</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 text-xl leading-none">×</button>
        </div>
        <div className="flex gap-2 mb-4">
          <SeverityBadge severity={threat.severity} />
          <span className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded-full">
            {threat.category?.replace(/_/g, " ")}
          </span>
          <span className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded-full">
            {threat.source}
          </span>
        </div>
        <p className="text-xs text-gray-400 leading-relaxed whitespace-pre-wrap mb-4">{threat.content}</p>
        {threat.iocs?.length > 0 && (
          <div>
            <p className="text-xs text-gray-500 font-medium mb-2 uppercase tracking-wider">IOCs</p>
            <div className="flex flex-wrap gap-2">
              {threat.iocs.map((ioc, i) => (
                <code key={i} className="text-xs bg-gray-800 text-indigo-400 px-2 py-1 rounded">{ioc}</code>
              ))}
            </div>
          </div>
        )}
        {threat.source_url && (
          <p className="text-xs text-gray-600 mt-4 font-mono truncate">{threat.source_url}</p>
        )}
      </div>
    </div>
  );
}

export default function ThreatList() {
  const [threats,  setThreats]  = useState([]);
  const [total,    setTotal]    = useState(0);
  const [page,     setPage]     = useState(1);
  const [loading,  setLoading]  = useState(false);
  const [selected, setSelected] = useState(null);
  const [search,   setSearch]   = useState("");
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");

  const fetchThreats = useCallback(() => {
    setLoading(true);
    const req = search
      ? threatApi.search(search)
      : threatApi.list({ page, limit: 25, severity: severity || undefined, category: category || undefined });

    req
      .then(res => {
        const data = res.data;
        setThreats(data.data || []);
        setTotal(data.total || data.count || 0);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [page, search, severity, category]);

  useEffect(() => { fetchThreats(); }, [fetchThreats]);

  return (
    <div className="max-w-6xl space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-100">Threat Feed</h1>
        <span className="text-xs text-gray-500">{total.toLocaleString()} threats</span>
      </div>

      {/* ── Filters ── */}
      <div className="flex flex-wrap gap-3">
        <input
          type="text"
          placeholder="Search threats…"
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(1); }}
          className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200
                     placeholder-gray-600 focus:outline-none focus:border-indigo-500 flex-1 min-w-[200px]"
        />
        <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(1); }}
                className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-400">
          <option value="">All severities</option>
          {["critical","high","medium","low"].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={category} onChange={e => { setCategory(e.target.value); setPage(1); }}
                className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-400">
          <option value="">All categories</option>
          {["credential_leak","malware_sale","ransomware","data_breach",
            "forum_post","exploit_sale","phishing_kit","zero_day"].map(c => (
            <option key={c} value={c}>{c.replace(/_/g, " ")}</option>
          ))}
        </select>
      </div>

      {/* ── Table ── */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800">
              {["Threat", "Category", "Severity", "Date", "IOCs"].map(h => (
                <th key={h} className="py-3 px-4 text-left text-xs text-gray-500 font-medium uppercase tracking-wider">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading
              ? <tr><td colSpan={5} className="py-8 text-center text-gray-500 text-sm">Loading…</td></tr>
              : threats.length === 0
                ? <tr><td colSpan={5} className="py-8 text-center text-gray-600 text-sm">No threats found. Run the ingestor first.</td></tr>
                : threats.map(t => <ThreatRow key={t.id} threat={t} onClick={setSelected} />)
            }
          </tbody>
        </table>
      </div>

      {/* ── Pagination ── */}
      {!search && (
        <div className="flex items-center justify-between text-xs text-gray-500">
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                  className="px-3 py-1 bg-gray-800 rounded disabled:opacity-30 hover:bg-gray-700">← Prev</button>
          <span>Page {page}</span>
          <button onClick={() => setPage(p => p + 1)} disabled={threats.length < 25}
                  className="px-3 py-1 bg-gray-800 rounded disabled:opacity-30 hover:bg-gray-700">Next →</button>
        </div>
      )}

      <ThreatDetail threat={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
