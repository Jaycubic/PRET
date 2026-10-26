import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies /api and /ws to the backend so `npm run dev` works
// standalone against `uvicorn app.main:app --reload` (see README.md).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://0.0.0.0:8443",
      "/ws": { target: "ws://0.0.0.0:8443", ws: true },
    },
  },
  build: {
    // Output straight into the backend's static dir — see README.md
    // "Build & run": the backend serves this directory directly.
    outDir: "../backend/app/static",
    emptyOutDir: true,
  },
});
