// Login.jsx — Authentication screen
import { useState } from "react";
import { authApi } from "../api";

export default function Login({ onLogin }) {
  const [mode,    setMode]    = useState("login");  // "login" | "register"
  const [form,    setForm]    = useState({ username: "", email: "", password: "" });
  const [error,   setError]   = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    setError("");
    setLoading(true);
    try {
      const fn = mode === "login" ? authApi.login : authApi.register;
      const res = await fn(form);
      onLogin(res.data.token, res.data.user);
    } catch (e) {
      setError(e.response?.data?.error || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Logo / title */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-indigo-600 mb-4">
            <svg width="24" height="24" fill="none" stroke="white" strokeWidth="1.5" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round"
                d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>
            </svg>
          </div>
          <h1 className="text-xl font-semibold text-gray-100">Threat Intel Platform</h1>
          <p className="text-sm text-gray-500 mt-1">Dark Web Monitoring</p>
        </div>

        {/* Card */}
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-4">
          {/* Mode toggle */}
          <div className="flex gap-1 bg-gray-800 rounded-lg p-1">
            {["login", "register"].map(m => (
              <button key={m} onClick={() => { setMode(m); setError(""); }}
                      className={`flex-1 py-1.5 rounded-md text-sm capitalize transition-colors
                        ${mode === m ? "bg-indigo-600 text-white" : "text-gray-400 hover:text-gray-200"}`}>
                {m}
              </button>
            ))}
          </div>

          {/* Fields */}
          {mode === "register" && (
            <input type="text" placeholder="Username"
                   value={form.username}
                   onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                   className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2.5 text-sm
                              text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-500" />
          )}
          <input type="email" placeholder="Email address"
                 value={form.email}
                 onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
                 className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2.5 text-sm
                            text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-500" />
          <input type="password" placeholder="Password"
                 value={form.password}
                 onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                 onKeyDown={e => e.key === "Enter" && handleSubmit()}
                 className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2.5 text-sm
                            text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-500" />

          {error && <p className="text-xs text-red-400 bg-red-900/20 border border-red-900 rounded-lg px-3 py-2">{error}</p>}

          <button onClick={handleSubmit} disabled={loading}
                  className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white
                             font-medium py-2.5 rounded-lg text-sm transition-colors">
            {loading ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </div>

        <p className="text-center text-xs text-gray-700 mt-4">
          For academic use only · Simulated data only
        </p>
      </div>
    </div>
  );
}
