// api/index.js — Axios client with JWT interceptor
// All API calls go through this module

import axios from "axios";

const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:5000/api";

export const api = axios.create({ baseURL: BASE_URL });

// ── Request interceptor: attach JWT token ─────────────────────────────────
api.interceptors.request.use(config => {
  const token = localStorage.getItem("jwt_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// ── Response interceptor: handle 401 globally ─────────────────────────────
api.interceptors.response.use(
  res => res,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem("jwt_token");
      window.location.href = "/login";
    }
    return Promise.reject(err);
  }
);

// ── Convenience wrappers ──────────────────────────────────────────────────

export const threatApi = {
  list:   (params) => api.get("/threats", { params }),
  get:    (id)     => api.get(`/threats/${id}`),
  search: (q)      => api.get("/threats/search", { params: { q } }),
  create: (data)   => api.post("/threats", data),
  delete: (id)     => api.delete(`/threats/${id}`),
};

export const alertApi = {
  list:       (params) => api.get("/alerts", { params }),
  ack:        (id)     => api.patch(`/alerts/${id}/ack`),
  dismiss:    (id)     => api.patch(`/alerts/${id}/dismiss`),
  keywords:   ()       => api.get("/alerts/keywords"),
  addKeyword: (data)   => api.post("/alerts/keywords", data),
  delKeyword: (id)     => api.delete(`/alerts/keywords/${id}`),
};

export const dashboardApi = {
  stats:      () => api.get("/dashboard/stats"),
  trends:     () => api.get("/dashboard/trends"),
  categories: () => api.get("/dashboard/categories"),
  topIocs:    () => api.get("/dashboard/top-iocs"),
};

export const authApi = {
  login:    (data) => api.post("/auth/login", data),
  register: (data) => api.post("/auth/register", data),
  me:       ()     => api.get("/auth/me"),
};
