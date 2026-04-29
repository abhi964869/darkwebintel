import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  publicDir: false,
  build: {
    outDir: "public",
    emptyOutDir: true,
  },
  server: {
    host: "127.0.0.1",
    port: 3000,
    proxy: {
      "/api": "http://127.0.0.1:5000",
      "/reports": "http://127.0.0.1:5000",
      "/static": "http://127.0.0.1:5000",
      "/flask": "http://127.0.0.1:5000",
    },
  },
});
