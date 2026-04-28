// Keywords.jsx — Monitor keywords and IOCs
import { useState, useEffect } from "react";
import { alertApi } from "../api";

const CAT_COLORS = {
  brand:   "bg-purple-900 text-purple-300",
  domain:  "bg-blue-900 text-blue-300",
  email:   "bg-cyan-900 text-cyan-300",
  hash:    "bg-orange-900 text-orange-300",
  general: "bg-gray-800 text-gray-400",
};

export default function Keywords() {
  const [keywords, setKeywords] = useState([]);
  const [form,     setForm]     = useState({ keyword: "", category: "general", is_regex: false });
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");

  const load = () => {
    alertApi.keywords().then(r => setKeywords(r.data.data)).catch(console.error);
  };

  useEffect(() => { load(); }, []);

  const handleAdd = async () => {
    if (!form.keyword.trim()) return;
    setError("");
    setLoading(true);
    try {
      await alertApi.addKeyword(form);
      setForm({ keyword: "", category: "general", is_regex: false });
      load();
    } catch (e) {
      setError(e.response?.data?.error || "Failed to add keyword.");
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm("Remove this keyword?")) return;
    await alertApi.delKeyword(id).catch(console.error);
    load();
  };

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-xl font-semibold text-gray-100">Monitored Keywords / IOCs</h1>

      {/* ── Add form ── */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-5 space-y-4">
        <h2 className="text-sm font-medium text-gray-300">Add keyword</h2>
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Keyword, IP, domain, hash…"
            value={form.keyword}
            onChange={e => setForm(f => ({ ...f, keyword: e.target.value }))}
            onKeyDown={e => e.key === "Enter" && handleAdd()}
            className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm
                       text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-500"
          />
          <select value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value }))}
                  className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-400">
            {["general","brand","domain","email","hash"].map(c => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>
        <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer select-none">
          <input type="checkbox" checked={form.is_regex}
                 onChange={e => setForm(f => ({ ...f, is_regex: e.target.checked }))}
                 className="rounded" />
          Treat as regular expression
        </label>
        {error && <p className="text-xs text-red-400">{error}</p>}
        <button onClick={handleAdd} disabled={loading}
                className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm
                           px-4 py-2 rounded-lg transition-colors">
          {loading ? "Adding…" : "Add keyword"}
        </button>
      </div>

      {/* ── Keyword list ── */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 overflow-hidden">
        {keywords.length === 0 ? (
          <p className="text-gray-600 text-sm text-center py-8">No keywords yet. Add one above.</p>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-800">
                {["Keyword", "Category", "Regex", "Hits", ""].map(h => (
                  <th key={h} className="py-3 px-4 text-left text-xs text-gray-500 uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {keywords.map(k => (
                <tr key={k.id} className="border-t border-gray-800 hover:bg-gray-800/30">
                  <td className="py-3 px-4 font-mono text-sm text-indigo-400">{k.keyword}</td>
                  <td className="py-3 px-4">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${CAT_COLORS[k.category] || CAT_COLORS.general}`}>
                      {k.category}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-xs text-gray-500">{k.is_regex ? "Yes" : "No"}</td>
                  <td className="py-3 px-4 text-sm text-gray-300">{k.hit_count}</td>
                  <td className="py-3 px-4">
                    <button onClick={() => handleDelete(k.id)}
                            className="text-xs text-red-500 hover:text-red-400 transition-colors">
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
