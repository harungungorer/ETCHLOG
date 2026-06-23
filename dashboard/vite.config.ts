import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
//
// The dashboard calls the API at the relative path /api/v1 by default, so in dev we proxy /api to a
// local etchlog-server on :8080 (run it with the `demo` profile to enable the tamper button). This
// keeps the browser same-origin — no CORS, no API key in the client beyond the demo append call.
// To point at a different server, set VITE_ETCHLOG_BASE_URL (direct mode) instead of the proxy.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
  },
})
