// AlertsPanel.jsx — View and manage alerts
import { useState, useEffect } from "react";
import { alertApi } from "../api";

const SEV_BADGE = {
  critical: "bg-red-900 text-red-300 border border-red-800",
  high:     "bg-orange-900 text-orange-300 border border-orange-800",
  medium:   "bg-yellow-900 text-yellow-300 border border-yellow-800",
  low:      "bg-green-900 text-green-300 border border-green-800",
};

const STATUS_COLOR = {
  new:          "text-indigo-400",
  acknowledged: "text-gray-400",
  dismissed:    "text-gray-600",
};

export default function AlertsPanel() {
  const [alerts,  setAlerts]  = useState([]);
  const [total,   setTotal]   = useState(0);
  const [status,  setStatus]  = useState("new");
  const [loading, setLoading] = useState(false);

  const load = (s = status) => {
    setLoading(true);
    alertApi.list({ status: s, limit: 50 })
      .then(r => { setAlerts(r.data.data); setTotal(r.data.total); })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [status]);

  const ack     = async (id) => { await alertApi.ack(id).catch(console.error);     load(); };
  const dismiss = async (id) => { await alertApi.dismiss(id).catch(console.error); load(); };

  return (
    <div className="max-w-4xl space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-100">Alerts</h1>
        <span className="text-xs text-gray-500">{total} results</span>
      </div>

      {/* ── Status tabs ── */}
      <div className="flex gap-1 bg-gray-900 border border-gray-800 rounded-lg p-1 w-fit">
        {["new", "acknowledged", "dismissed"].map(s => (
          <button key={s} onClick={() => setStatus(s)}
                  className={`px-4 py-1.5 rounded-md text-sm transition-colors capitalize
                    ${status === s ? "bg-indigo-600 text-white" : "text-gray-400 hover:text-gray-200"}`}>
            {s}
          </button>
        ))}
      </div>

      {/* ── Alert cards ── */}
      <div className="space-y-3">
        {loading && <p className="text-gray-500 text-sm">Loading…</p>}
        {!loading && alerts.length === 0 && (
          <div className="rounded-xl border border-gray-800 bg-gray-900 py-12 text-center">
            <p className="text-gray-600 text-sm">No {status} alerts.</p>
            {status === "new" && (
              <p className="text-gray-700 text-xs mt-2">Add keywords and run the ingestor to generate alerts.</p>
            )}
          </div>
        )}
        {alerts.map(alert => (
          <div key={alert.id}
               className="rounded-xl border border-gray-800 bg-gray-900 p-4 flex items-start gap-4">
            {/* Severity badge */}
            <span className={`mt-0.5 text-xs px-2 py-0.5 rounded-full font-medium shrink-0
                              ${SEV_BADGE[alert.severity] || SEV_BADGE.low}`}>
              {alert.severity}
            </span>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-sm text-indigo-400">{alert.keyword}</span>
                <span className={`text-xs ${STATUS_COLOR[alert.status]}`}>· {alert.status}</span>
              </div>
              {alert.context_snippet && (
                <p className="text-xs text-gray-500 font-mono leading-relaxed line-clamp-2 bg-gray-800 rounded px-2 py-1 mt-1">
                  …{alert.context_snippet}…
                </p>
              )}
              <p className="text-xs text-gray-600 mt-2">
                {alert.created_at ? new Date(alert.created_at).toLocaleString() : ""}
                {" · "}Threat ID: <span className="font-mono">{alert.threat_id?.slice(-8)}</span>
              </p>
            </div>

            {/* Actions */}
            {alert.status === "new" && (
              <div className="flex gap-2 shrink-0">
                <button onClick={() => ack(alert.id)}
                        className="text-xs px-3 py-1 bg-indigo-900 text-indigo-300 rounded-lg
                                   hover:bg-indigo-800 transition-colors border border-indigo-800">
                  Acknowledge
                </button>
                <button onClick={() => dismiss(alert.id)}
                        className="text-xs px-3 py-1 bg-gray-800 text-gray-400 rounded-lg
                                   hover:bg-gray-700 transition-colors">
                  Dismiss
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
