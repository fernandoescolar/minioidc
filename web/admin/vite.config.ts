import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The web is embedded in the minioidc binary (internal/admin/ui/dist) and served
// at <issuer>/admin/, so the URLs of the assets are relative.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: './',
  build: {
    outDir: '../../internal/admin/ui/dist',
    emptyOutDir: true,
  },
  server: {
    // `npm run dev` proxies the API to a local minioidc (log in at http://localhost:8000 first)
    proxy: {
      '/api': { target: 'http://localhost:8000/admin', changeOrigin: true },
    },
  },
})
