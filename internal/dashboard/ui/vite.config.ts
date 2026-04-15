/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: '/',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Split vendor chunks for better caching:
    // - react-vendor: react + react-dom (rarely change, cache forever)
    // - flow-vendor: @xyflow/react for routing topology (large, separate)
    // - ui-vendor: lucide, clsx, tailwind-merge, class-variance-authority
    // - app: application code (changes frequently)
    manualChunks(id) {
      if (id.includes('node_modules/react')) {
        return 'react-vendor'
      }
      if (id.includes('node_modules/@xyflow')) {
        return 'flow-vendor'
      }
      if (id.includes('node_modules/lucide') ||
          id.includes('node_modules/clsx') ||
          id.includes('node_modules/tailwind-merge') ||
          id.includes('node_modules/class-variance-authority')) {
        return 'ui-vendor'
      }
      if (id.includes('node_modules')) {
        return 'misc-vendor'
      }
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:9443',
      '/login': 'http://localhost:9443',
      '/logout': 'http://localhost:9443',
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    css: false,
  },
})
