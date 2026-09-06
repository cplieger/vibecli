// Vitest 4.1 configuration for web-terminal-kiro TypeScript unit tests.
//
// TWO projects, and the DEFAULT is the browser: a test file runs in real
// headless Chromium unless its name opts out. There is no `environment` and no
// per-file environment pragma any more — Browser Mode is a runner, not an
// environment, and it replaces the DOM emulator this suite used to load.
// The browser is where this app's markup actually runs, so a <link> really
// loads, sequential focus navigation really exists, and `disabled` is really
// reflected.
//
// The opt-out is the `.node.test.ts` suffix: reason in the stem, placement in
// the suffix. `app.node.test.ts` is the ONLY file that needs it, and it needs it
// for capabilities no Vite import can express — a recursive walk of two
// dependency `src` trees inside node_modules that TS-parses every file it finds,
// a served-directory listing, a runtime-derived file list, and PNG header bytes.
// Everything the browser half reads arrives as a `?raw` import instead, which is
// resolved at transform time and therefore fails to RESOLVE when an asset is
// renamed, where a filesystem read only threw once the test ran.
//
// The glob is `**/*.node.test.ts`, not `src/**/*.node.test.ts`: this package's
// tests sit at the package ROOT (there is no src/), and a src-anchored glob
// would match nothing, putting the node file in the browser project in silence.
// Verify per-project file counts in the run output after touching either glob.
//
// `extends: true` is load-bearing, not decoration: without it a project inherits
// NOTHING from the options below, so `expect.requireAssertions`, `allowOnly`,
// `mockReset`, `sequence` and the exclusions would all silently stop applying to
// both halves of the suite.
//
// `channel: "chromium"` opts into Chromium's newer headless mode, the real
// browser rather than the separate headless-shell build. CI installs it with
// `npx playwright install --with-deps chromium`; locally it is a one-time
// `npx --no-install playwright install chromium`.
//
// Run: vitest --run (single pass) or vitest (watch mode)
import { playwright } from "@vitest/browser-playwright";
import { configDefaults, defineConfig } from "vitest/config";

// Vitest's defaults (node_modules at any depth, .git); spreading
// configDefaults.exclude avoids narrowing the built-in "**/node_modules/**" to a
// top-level-only glob.
// "**/.stryker-tmp/**" keeps a leftover Stryker sandbox (an interrupted mutation
// run does not clean it up) from double-collecting the suite's test files with
// stale or mutated copies.
// "**/*.e2e.test.ts" is Playwright's namespace (playwright.config.ts testMatch),
// not vitest's: a playwright spec imports @playwright/test, which fails at
// collection under vitest, so without this exclusion the unit gate goes red on a
// file it can never run.
// (Compiled output under ../static needs no entry: include/exclude resolve
// against this directory, so files outside it are never collected.)
const EXCLUDED = [...configDefaults.exclude, "**/.stryker-tmp/**", "**/*.e2e.test.ts"];

// The one file that cannot run in the browser. Spelled once and used twice: the
// node project's include and the browser project's exclude must never disagree,
// or a test runs in both projects or in neither.
const NODE_TESTS = "**/*.node.test.ts";

export default defineConfig({
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: "node",
          environment: "node",
          include: [NODE_TESTS],
        },
      },
      {
        extends: true,
        // The `?raw` imports in app.test.ts read ../static, which sits OUTSIDE
        // this package (the Vite root). Browser Mode serves every module over
        // HTTP, and Vite refuses to serve a path outside the workspace root it
        // infers, so without this the served-markup imports 403 and the whole
        // browser suite fails to import. Spelled as the two directories that are
        // actually read, because setting this option replaces Vite's default
        // rather than adding to it.
        server: { fs: { allow: [".", "../static"] } },
        test: {
          name: "browser",
          // Test files co-located with source, named *.test.ts
          include: ["**/*.test.ts"],
          exclude: [...EXCLUDED, NODE_TESTS],
          browser: {
            enabled: true,
            headless: true,
            provider: playwright({
              launchOptions: {
                channel: "chromium",
              },
            }),
            instances: [{ browser: "chromium" }],
            // Fixed viewport so anything layout-dependent is reproducible; a
            // real browser computes real boxes.
            viewport: { width: 1280, height: 720 },
            // A failure screenshot per failing test is noise in CI and cannot be
            // read from a job log; the assertion diff is the useful artifact.
            screenshotFailures: false,
          },
        },
      },
    ],

    exclude: EXCLUDED,

    // Forbid .only tests unconditionally — not just in CI.
    allowOnly: false,

    // app.test.ts and app.node.test.ts cover web-terminal-kiro's thin bootstrap
    // (the createTerminal() wiring); the terminal
    // logic itself is tested in @cplieger/web-terminal-ui and @cplieger/web-terminal-engine.
    // Deleting, misnaming, or excluding that suite must fail rather than
    // report green with zero tests.
    passWithNoTests: false,

    // Require explicit imports of describe/it/expect from "vitest".
    globals: false,

    // Force every test to call at least one expect(). Catches tests that
    // accidentally pass because they never assert anything.
    expect: {
      requireAssertions: true,
    },

    // Reset/restore all mocks and stubs before each test. mockReset clears call
    // history first, so no separate clearMocks is needed.
    mockReset: true,
    restoreMocks: true,
    unstubEnvs: true,
    unstubGlobals: true,

    // Stop after the first failure in CI; collect full results locally.
    bail: process.env["CI"] ? 1 : 0,

    // Per-test timeout. These small unit tests should never need more than 2s.
    testTimeout: 2000,
    hookTimeout: 5000,

    // Flag tests slower than 100ms — the node half's whole cost is synchronous
    // fixture reads and parses: app.ts, the served directory listing, the icon
    // bytes, and the vendored-graph importmap walk, which recursively reads and
    // TS-parses both @cplieger/web-terminal-{ui,engine} src trees (measured
    // 85–140ms, so it trips this threshold on a loaded machine). No network and
    // no async I/O: anything slower than a fixture read is a logic problem, not a
    // wait. The threshold is left where it is deliberately — the walk's real cost
    // is worth staying visible rather than absorbed by a bigger number. It is a
    // root-only option, so the browser half inherits it and a browser round trip
    // will exceed it routinely; that is reporter annotation, never a failure.
    slowTestThreshold: 100,

    // Reproducible ordering. hooks: "stack" = afterEach/afterAll run in
    // reverse definition order (correct teardown semantics).
    sequence: {
      shuffle: { files: false, tests: false },
      concurrent: false,
      hooks: "stack",
    },

    // Print stack traces with every console.* call in tests.
    printConsoleTrace: true,

    // V8 coverage with AST-accurate remapping. Root-level: coverage is merged
    // across both projects, so the thresholds below are the whole suite's.
    coverage: {
      provider: "v8",
      include: ["**/*.ts"],
      // vitest ships NO built-in coverage exclusions -- coverageConfigDefaults
      // .exclude is [] in both 4.1.11 and 5.0.0, because v4 moved the responsibility to
      // coverage.include (the "**/*.ts" above). So unlike test.exclude, which spreads a
      // genuinely non-empty configDefaults.exclude, this array IS the whole set and
      // every entry has to be spelled here.
      // The "**/" prefixes are load-bearing on vitest 5: it matches these against the
      // root-relative path without picomatch's `contains`, so a bare "*.test.ts" stops
      // reaching e2e/boot.e2e.test.ts and v8 would report that Playwright spec at 0%.
      // "node_modules/**" is equally load-bearing -- this list feeds tinyglobby's
      // `ignore` for untested-file discovery, and "**/*.ts" without it walks the
      // dependency tree.
      // "*.test.ts" also covers "*.node.test.ts", which still ends in ".test.ts".
      // "*.config.ts" covers playwright.config.ts, which the include matched and
      // v8 reported at 0%, holding the 90% thresholds permanently red.
      // "*.d.ts" is not covered by anything else: an ambient declaration file
      // matches the include too, and would re-red the thresholds the same way.
      exclude: ["node_modules/**", "**/*.test.ts", "**/*.d.ts", "**/*.config.ts"],
      reportOnFailure: true,
      reporter: ["text", "text-summary", "lcov"],
      thresholds: {
        // The frontend is a single bootstrap module (app.ts) fully covered
        // by app.test.ts (100% on all axes). 90 locks that in while leaving
        // slack for a future module with an untestable sliver.
        lines: 90,
        functions: 90,
        branches: 90,
        statements: 90,
      },
    },

    chaiConfig: {
      truncateThreshold: 0,
      showDiff: true,
      includeStack: true,
    },
  },
});
