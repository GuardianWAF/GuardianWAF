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
    // esbuild 0.28+ dropped support for transforming destructuring (and other
    // modern syntax) down to pre-2021 browser targets. Bumping to es2022
    // satisfies the stricter transform rules. Dependabot alert #36 (GHSA-gv7w-rqvm-qjhr)
    // requires the esbuild bump.
    target: 'es2022',
  },
})
