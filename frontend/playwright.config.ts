import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60000,
  expect: { timeout: 10000 },
  use: {
    baseURL: process.env.OBJECTSHARE_E2E_ORIGIN || 'http://127.0.0.1:8192',
    // Full Chromium in new headless mode; the headless shell paints on its own
    // schedule, which hides first-paint regressions.
    channel: process.env.OBJECTSHARE_BROWSER_CHANNEL || 'chromium',
    viewport: { width: 1440, height: 1000 },
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  reporter: [['list']],
});
