import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const api = process.env.VIGIL_API ?? 'http://127.0.0.1:8710'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5190,
    strictPort: true,
    proxy: { '/api': { target: api, changeOrigin: true } },
  },
})
