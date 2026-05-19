import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';
import { resolve } from 'path';

export default defineConfig({
  plugins: [preact()],
  base: '/app/',
  build: {
    outDir: resolve(__dirname, '../public/app'),
    emptyOutDir: true
  }
});
