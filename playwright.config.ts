import { defineConfig, devices } from "@playwright/test";
import { existsSync } from "node:fs";

const systemChromium = [
  process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
  process.env.CHROME_BIN,
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/snap/bin/chromium",
  "/usr/bin/microsoft-edge",
  "/usr/bin/microsoft-edge-stable"
].find((candidate): candidate is string => Boolean(candidate && existsSync(candidate)));

const chromiumUse = systemChromium
  ? { ...devices["Desktop Chrome"], launchOptions: { executablePath: systemChromium } }
  : { ...devices["Desktop Chrome"] };

export default defineConfig({
  testDir: "tests/e2e",
  timeout: 30_000,
  expect: {
    timeout: 5_000
  },
  use: {
    baseURL: "http://127.0.0.1:8088",
    trace: "retain-on-failure"
  },
  webServer: {
    command: "npm run build && node server/dist/server.js",
    url: "http://127.0.0.1:8088/api/health",
    reuseExistingServer: true,
    timeout: 120_000
  },
  projects: [
    {
      name: systemChromium ? "system-chromium" : "chromium",
      use: chromiumUse
    }
  ]
});
