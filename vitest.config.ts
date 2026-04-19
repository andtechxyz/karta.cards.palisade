import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts', 'services/**/*.test.ts', 'packages/**/*.test.ts', 'tests/**/*.test.ts'],
    exclude: ['node_modules/**', 'dist/**', 'frontend/**', 'services/*/frontend/**'],
    setupFiles: ['tests/setup.ts'],
    environment: 'node',
    isolate: true,
    pool: 'forks',
  },
});
