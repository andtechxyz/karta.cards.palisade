import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5174,
    allowedHosts: ['activation.karta.cards', 'localhost'],
    proxy: {
      '/api': {
        target: 'http://localhost:3002',
        changeOrigin: false,
        ws: false,
      },
    },
  },
});
