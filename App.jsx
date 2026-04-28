// App.jsx — Root Component
// Handles routing and auth state

import { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Dashboard from "./components/Dashboard";
import ThreatList from "./components/ThreatList";
import AlertsPanel from "./components/AlertsPanel";
import Keywords from "./components/Keywords";
import Login from "./components/Login";
import Sidebar from "./components/Sidebar";
import { api } from "./api";

export default function App() {
  const [user, setUser]       = useState(null);
  const [loading, setLoading] = useState(true);

  // Restore session from localStorage on mount
  useEffect(() => {
    const token = localStorage.getItem("jwt_token");
    if (token) {
      api.get("/auth/me")
        .then(res => setUser(res.data))
        .catch(() => localStorage.removeItem("jwt_token"))
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const handleLogin = (token, userData) => {
    localStorage.setItem("jwt_token", token);
    setUser(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem("jwt_token");
    setUser(null);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-950 text-gray-400">
        Loading...
      </div>
    );
  }

  if (!user) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <Router>
      <div className="flex h-screen bg-gray-950 text-gray-100 font-mono">
        {/* ── Sidebar Navigation ── */}
        <Sidebar user={user} onLogout={handleLogout} />

        {/* ── Main Content ── */}
        <main className="flex-1 overflow-auto p-6">
          <Routes>
            <Route path="/"          element={<Dashboard />} />
            <Route path="/threats"   element={<ThreatList />} />
            <Route path="/alerts"    element={<AlertsPanel />} />
            <Route path="/keywords"  element={<Keywords />} />
            <Route path="*"          element={<Navigate to="/" />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}
