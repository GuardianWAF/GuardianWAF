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
    // esbuild 0.28+ dropped support for transforming destructuring (and other
    // modern syntax) down to pre-2021 browser targets. The Vite 6 default
    // floor (chrome87/edge88/firefox78/safari14) is no longer transpilable.
    // Bumping to es2022 keeps the dev experience modern and satisfies
    // esbuild 0.28+'s stricter transform rules. Dependabot alert #36/#37
    // (GHSA-gv7w-rqvm-qjhr) requires the esbuild bump.
    target: 'es2022',
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
