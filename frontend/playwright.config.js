// @ts-check
const { defineConfig } = require("@playwright/test");

const PORT = process.env.E2E_PORT || "43210";
const BASE_URL = `http://127.0.0.1:${PORT}`;

/**
 * Browser tests run against `cargo run --example e2e_server`: the real
 * dashboard with fixture peers and a fake WireGuard/firewall runner, so nothing
 * touches the host. The tests share one server and undo what they change.
 */
module.exports = defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 30_000,
  expect: { timeout: 7_000 },
  reporter: process.env.CI ? [["github"], ["list"]] : "list",
  use: {
    baseURL: BASE_URL,
    // Full Chromium rather than the headless shell, which is not on every host.
    channel: "chromium",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "cargo run --quiet --example e2e_server",
    cwd: "..",
    env: { E2E_PORT: PORT },
    url: `${BASE_URL}/login`,
    timeout: 600_000,
    reuseExistingServer: !process.env.CI,
  },
  projects: [
    { name: "setup", testMatch: /auth\.setup\.js/ },
    {
      name: "desktop",
      dependencies: ["setup"],
      testIgnore: /auth\.setup\.js/,
      use: { viewport: { width: 1280, height: 800 }, storageState: "e2e/.auth/session.json" },
    },
    {
      name: "mobile",
      dependencies: ["setup"],
      testIgnore: /auth\.setup\.js/,
      use: {
        viewport: { width: 390, height: 844 },
        deviceScaleFactor: 2,
        hasTouch: true,
        storageState: "e2e/.auth/session.json",
      },
    },
  ],
});
