import { defineConfig } from "@playwright/test";

// Local browser smoke check for the SERVED artifact, not wired into CI.
// static/vendor/ is generated during the Docker build, so point this at a built
// image or run scripts/dev-build.sh before serving locally; a fresh checkout has
// no importmap targets and would fail for the wrong reason.
// tests/image-smoke.conf already gates every served importmap target in CI, which
// needs no browser. This suite adds the checks that need JS execution — console
// cleanliness, shell mount, axe-core on the rendered tree — and deliberately
// stops short of a terminal session, which needs an authenticated kiro-cli.
const baseURL = process.env["PLAYWRIGHT_BASE_URL"] ?? "http://127.0.0.1:9848";

export default defineConfig({
  testDir: "./e2e",
  testMatch: "**/*.e2e.test.ts",
  fullyParallel: false,
  forbidOnly: !!process.env["CI"],
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL,
    headless: true,
    viewport: { width: 1280, height: 800 },
    deviceScaleFactor: 1,
    // A boot failure is exactly what these tests hunt, so capture evidence.
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
