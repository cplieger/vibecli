import { defineConfig } from "@playwright/test";

// Real-browser boot verification for the SERVED page.
//
// WHY THIS REPO AND NOT vibekit
// The design that motivated this named vibekit as the pilot, on the grounds that
// a browser test catches the importmap failure class. Measuring the fleet
// corrected that: vibekit and subflux bundle to a single /app.js via esbuild and
// serve NO importmap, so the class cannot occur there. web-terminal-kiro and
// web-terminal-server are the two repos that serve one, and this app's has three
// entries resolving into /vendor/** trees.
//
// That is exactly how the failure presents: tsc resolves a bare specifier
// against node_modules and stays green, the Docker build succeeds, and the
// browser then cannot remap it, module loading aborts, and the app hangs behind
// its loading overlay. Nothing in CI executes JavaScript today, so a build that
// forgot a vendor copy or renamed a subpath ships silently.
//
// WHY IT POINTS AT A RUNNING SERVER RATHER THAN A STATIC DIRECTORY
// static/vendor/ is gitignored AND dockerignored: it is produced during the
// Docker build by fetching the pinned npm tarballs and compiling them with tsc.
// A fresh checkout therefore has no importmap targets at all, so serving
// static/ from a plain file server would fail for the wrong reason and prove
// nothing. The subject under test has to be the real artifact.
//
// DELIBERATELY NOT WIRED INTO CI (decided 2026-08). The deterministic core of
// the failure class - every served importmap target answers 200 from the built
// image - is a hard gate in tests/image-smoke.conf's smoke_verify(), which
// needs three curls and no browser. What remains here needs JS execution
// (console cleanliness, shell mount, axe-core on the rendered tree) and is a
// local spot check plus ui-qa skill material: in CI it would be report-only
// with no reader, the flakiest check class, taxing every Renovate PR with
// npm ci + a chromium download. Two supported ways to run:
//   - Against the built image:
//         docker run -d -p 9848:9848 --name wtk-e2e <image>
//         PLAYWRIGHT_BASE_URL=http://127.0.0.1:9848 npm run test:e2e
//   - Locally, after scripts/dev-build.sh has produced static/vendor/:
//         go run . &   # or the container
//         npm run test:e2e
//
// SCOPE, STATED HONESTLY
// These tests verify module-graph integrity, console cleanliness, shell mount and
// accessibility of the served page. They do NOT drive a terminal session: that
// needs an authenticated kiro-cli, which CI cannot provide. A session flow stays
// the ui-qa skill's job against the live app.
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
