import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Boot verification against the served page. What each test defends:
//
//   1. Every importmap specifier resolves. This is the failure class the suite
//      exists for: a vendor copy the Docker build forgot, or a subpath the
//      library renamed, leaves tsc green and the browser dead.
//   2. No uncaught exception or console error during module evaluation.
//   3. The loading overlay clears and the terminal shell actually mounts, so a
//      boot that stalls behind the spinner fails here rather than in a user's
//      browser.
//   4. The page is accessible at the axe-core WCAG-A/AA rule level.
//
// Deliberately NOT here: sending keystrokes, asserting terminal output, or
// exercising a session. Those need an authenticated kiro-cli.

// The server may be answering 503 on /api/health because kiro-cli is still
// installing. That is irrelevant to every assertion below, which is the point of
// the app's bind-first boot: static assets and the shell are reachable regardless.

test.describe("served page boots", () => {
  test("every importmap specifier resolves to a real module", async ({ page, baseURL }) => {
    // Read the importmap the SERVER served rather than the one in the repo, so a
    // build that shipped a different index.html is caught too.
    const res = await page.request.get(`${baseURL}/`);
    expect(res.ok(), "index.html must be served").toBeTruthy();
    const html = await res.text();

    const match = /<script type="importmap">([\s\S]*?)<\/script>/.exec(html);
    const importmapJSON = match?.[1];
    expect(importmapJSON, "the served page must carry an importmap").toBeDefined();
    if (importmapJSON === undefined) {
      return; // unreachable after the expect; narrows the type for tsc
    }

    const imports = JSON.parse(importmapJSON).imports as Record<string, string>;
    const specifiers = Object.keys(imports);
    expect(specifiers.length, "importmap must not be empty").toBeGreaterThan(0);

    for (const [specifier, target] of Object.entries(imports)) {
      const url = new URL(target, baseURL!).toString();
      const probe = await page.request.get(url);
      expect(
        probe.status(),
        `importmap entry "${specifier}" -> ${target} must be served; a missing ` +
          `vendor tree aborts module loading in the browser while tsc and the ` +
          `Docker build both stay green`,
      ).toBe(200);
      const body = await probe.text();
      expect(
        body.length,
        `importmap entry "${specifier}" resolved to an empty body`,
      ).toBeGreaterThan(0);
    }
  });

  test("boots with no console errors and no uncaught exceptions", async ({ page }) => {
    const consoleErrors: string[] = [];
    const pageErrors: string[] = [];
    const failedRequests: string[] = [];

    page.on("console", (msg) => {
      if (msg.type() === "error") {
        consoleErrors.push(msg.text());
      }
    });
    page.on("pageerror", (err) => pageErrors.push(err.message));
    page.on("requestfailed", (req) => {
      // The WebSocket cannot connect without a live kiro-cli session, and the
      // app is designed to survive that. Everything else failing to load is a
      // real defect.
      const url = req.url();
      if (url.startsWith("ws://") || url.startsWith("wss://")) {
        return;
      }
      if (url.includes("/api/")) {
        return;
      }
      failedRequests.push(`${url} (${req.failure()?.errorText ?? "unknown"})`);
    });

    await page.goto("/", { waitUntil: "load" });
    // Wait for a DETERMINISTIC boot outcome rather than a fixed delay: either the
    // library rendered into #terminal, or the watchdog raised its fatal dialog.
    // This wait IS the test's verdict -- every assertion below only reads what the
    // listeners captured before it returned -- so a fixed 1500ms reports "no
    // console errors" about a boot that had not finished on any machine slower
    // than the author's, green for the exact failure class this suite exists for.
    const terminal = page.locator("#terminal");
    const bootFatal = page.locator('#loading[role="alertdialog"]');
    await expect
      .poll(
        async () => (await terminal.innerHTML()).trim() !== "" || (await bootFatal.count()) > 0,
        {
          message: "boot must reach either a mounted shell or the watchdog's fatal dialog",
          timeout: 15_000,
        },
      )
      .toBe(true);

    expect(pageErrors, "uncaught exceptions during boot").toEqual([]);
    expect(failedRequests, "static resources that failed to load").toEqual([]);
    expect(consoleErrors, "console errors during boot").toEqual([]);
  });

  test("the shell mounts and the loading overlay clears", async ({ page }) => {
    await page.goto("/", { waitUntil: "load" });

    const root = page.locator("#terminal");
    await expect(root, "#terminal root must exist").toHaveCount(1);

    // The library mounts its own tree inside #terminal. An empty root after boot
    // means createTerminal never ran or threw.
    await expect
      .poll(async () => (await root.innerHTML()).trim().length, {
        message: "the terminal library must render into #terminal",
        timeout: 15_000,
      })
      .toBeGreaterThan(0);

    // The inline watchdog turns #loading into an alertdialog when a resource
    // died. If that happened, boot failed and the copy explains why.
    const fatal = page.locator('#loading[role="alertdialog"]');
    if ((await fatal.count()) > 0 && (await fatal.isVisible())) {
      throw new Error(
        `the bootstrap watchdog reported a fatal: ${(await fatal.innerText()).trim()}`,
      );
    }

    // ...and the overlay came down, which is the half this test's name promises and
    // nothing asserted. #loading is opaque at z-index 200, so a shell that mounted
    // UNDER a spinner nobody dismissed satisfies the mount poll above while the user
    // stares at an animating bar -- the stuck-loading failure this app has hit twice.
    // The kernel adds "fade" on the first frame and removes the element on
    // transitionend, so either state is a pass. Asserted on the class rather than
    // Playwright visibility, because a faded overlay is opacity:0: still visible to
    // Playwright, already invisible and inert to the user.
    const overlay = page.locator("#loading");
    await expect
      .poll(
        async () =>
          (await overlay.count()) === 0 ||
          ((await overlay.getAttribute("class")) ?? "").includes("fade"),
        {
          message: "the loading overlay must be dismissed once the first frame renders",
          timeout: 15_000,
        },
      )
      .toBe(true);
  });

  // Runtime accessibility. html-validate's :a11y preset already gates the static
  // markup, but it cannot see what the terminal library RENDERS, which is most of
  // this page. The first run of this test found three violations; all three live
  // in @cplieger/web-terminal-ui's rendered tree, not in this app's markup, so
  // they cannot be fixed here.
  //
  // They are baselined by RULE ID rather than suppressed. A rule already on the
  // list is reported and tolerated; anything new fails. That keeps the check
  // meaningful from day one without gating on a defect this repo cannot fix, and
  // it makes the debt visible in test output instead of hiding it behind a
  // disabled assertion. Removing an entry once the library fixes it is the whole
  // maintenance burden.
  //
  // Known, as measured 2026-08-03 against web-terminal-ui's rendered shell:
  //   aria-required-children (critical) - a role whose required children are absent
  //   nested-interactive     (serious)  - an interactive control inside another
  //   color-contrast         (serious)  - two nodes below the AA ratio
  const KNOWN_AXE_RULES = new Set([
    "aria-required-children",
    "nested-interactive",
    "color-contrast",
  ]);

  test("has no NEW axe-core accessibility violations", async ({ page }) => {
    await page.goto("/", { waitUntil: "load" });
    // Audit the RENDERED shell, not the pre-boot page. This scan is the only check
    // on the library's rendered tree, and after a fixed 1500ms on a loaded machine
    // it can still be looking at the loading overlay -- which has no violations, so
    // the audit passes having examined nothing it was written for.
    await expect(page.locator("#terminal > *").first()).toBeAttached({ timeout: 15_000 });

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();

    const describe = (v: (typeof results.violations)[number]) =>
      `${v.id} (${v.impact}): ${v.help} [${v.nodes.length} node(s)]`;

    const known = results.violations.filter((v) => KNOWN_AXE_RULES.has(v.id));
    const fresh = results.violations.filter((v) => !KNOWN_AXE_RULES.has(v.id));

    if (known.length > 0) {
      console.log(
        `known upstream a11y debt (web-terminal-ui):\n  ${known.map(describe).join("\n  ")}`,
      );
    }
    expect(
      fresh.map(describe),
      "NEW axe-core violations; add to KNOWN_AXE_RULES only with a reason, or fix",
    ).toEqual([]);

    // Guard the baseline against rot: if the library fixed one, shrink the list.
    const stale = [...KNOWN_AXE_RULES].filter((id) => !results.violations.some((v) => v.id === id));
    if (stale.length > 0) {
      console.log(`KNOWN_AXE_RULES entries no longer firing (remove them): ${stale.join(", ")}`);
    }
  });
});
