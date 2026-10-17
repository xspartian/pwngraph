import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Proxies /api to `pwngraph serve`'s FastAPI backend during `npm run dev`
// (port 5173) so the same relative fetch("/api/...") calls work unmodified
// in dev and in the built app served by FastAPI itself.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
  build: {
    outDir: "dist",
  },
});
