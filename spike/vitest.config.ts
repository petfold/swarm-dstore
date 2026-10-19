import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: { include: ['spike/**/*.spike.ts'], testTimeout: 600_000 },
});
