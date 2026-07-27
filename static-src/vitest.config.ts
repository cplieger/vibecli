// Vitest 4.1 configuration for web-terminal-kiro TypeScript unit tests.
// Default environment: node (pure functions, no DOM overhead).
// DOM modules: add `// @vitest-environment happy-dom` at the top of the
// test file to get window/document/localStorage/etc. No browser binary
// needed — happy-dom is a pure JS DOM implementation running in Node.
// Run: vitest --run (single pass) or vitest (watch mode)
import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Default: node. Override per test file with:
    //   // @vitest-environment happy-dom
    environment: "node",

    // threads pool: faster than forks for pure Node.js tests with no native
    // modules.
    pool: "threads",

    // Disable test isolation: the suite is a single self-contained bootstrap
    // test file (app.test.ts resets modules, mocks, and DOM itself), so
    // isolation adds overhead with no benefit.
    isolate: false,

    // Test files co-located with source, named *.test.ts
    include: ["**/*.test.ts"],

    // Vitest's defaults (node_modules at any depth, .git); spreading
    // configDefaults.exclude avoids narrowing the built-in
    // "**/node_modules/**" to a top-level-only glob.
    // "**/.stryker-tmp/**" keeps a leftover Stryker sandbox (an interrupted
    // mutation run does not clean it up) from double-collecting the suite's
    // test files with stale or mutated copies.
    // (Compiled output under ../static needs no entry: include/exclude resolve
    // against this directory, so files outside it are never collected.)
    exclude: [...configDefaults.exclude, "**/.stryker-tmp/**"],

    // Forbid .only tests unconditionally — not just in CI.
    allowOnly: false,

    // app.test.ts covers web-terminal-kiro's thin bootstrap (the createTerminal() wiring); the terminal
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

    // Auto-clean/reset/restore all mocks and stubs before each test.
    clearMocks: true,
    mockReset: true,
    restoreMocks: true,
    unstubEnvs: true,
    unstubGlobals: true,

    // Stop after the first failure in CI; collect full results locally.
    bail: process.env["CI"] ? 1 : 0,

    // Per-test timeout. These small unit tests should never need more than 2s.
    testTimeout: 2000,
    hookTimeout: 5000,

    // Flag tests slower than 100ms — these tests have no I/O.
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

    // Show full diff when a snapshot fails.
    expandSnapshotDiff: true,

    // V8 coverage with AST-accurate remapping.
    coverage: {
      provider: "v8",
      include: ["*.ts"],
      exclude: ["*.test.ts", "*.d.ts"],
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

    experimental: {
      fsModuleCache: true,
      fsModuleCachePath: ".vitest-cache",
    },
  },
});
