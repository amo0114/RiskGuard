import { resolve } from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// The console is served by the Go binary at /console/ from internal/console/dist (go:embed).
// `npm run dev` proxies the API to a locally running riskguard admin listener.
export default defineConfig({
  base: "/console/",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": resolve(import.meta.dirname, "./src"),
    },
  },
  build: {
    outDir: resolve(import.meta.dirname, "../internal/console/dist"),
    emptyOutDir: true,
    // Inline assets would become data: URLs or <style> blocks; keep everything as files for CSP.
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 1200,
  },
  server: {
    proxy: {
      "/console/api": process.env.RG_ADMIN ?? "http://127.0.0.1:14101",
    },
  },
})
