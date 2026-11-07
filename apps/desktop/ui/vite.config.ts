/// <reference types="vitest" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));

// `--mode mock`: in-memory backend with the prototype's demo data (browser dev, smoke tests).
// Default: the Tauri backend. `__MOCK__` is a compile-time constant so the unused backend
// is dropped from the bundle.
export default defineConfig(({ mode }) => ({
  root,
  base: './',
  plugins: [react()],
  define: { __MOCK__: JSON.stringify(mode === 'mock') },
  clearScreen: false,
  server: { port: 1420, strictPort: true, host: '127.0.0.1' },
  build: {
    outDir: mode === 'mock' ? 'dist-mock' : 'dist',
    emptyOutDir: true,
    target: 'es2021',
    sourcemap: false,
    modulePreload: { polyfill: false },
    chunkSizeWarningLimit: 400,
  },
  test: {
    root,
    include: ['tests/**/*.test.ts'],
    environment: 'node',
  },
}));
