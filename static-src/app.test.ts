// @vitest-environment happy-dom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeEach, describe, expect, it, onTestFinished, vi } from "vitest";

// app.ts imports createTerminal from the UI package and presetAgentTabbed from
// its /presets subpath; mock both. presetAgentTabbed returns a sentinel the
// assertions match against, so we verify app.ts passes the agent preset through.
const { createTerminalMock, presetAgentTabbedMock } = vi.hoisted(() => ({
  createTerminalMock: vi.fn(),
  presetAgentTabbedMock: vi.fn(() => ["preset-features"]),
}));
vi.mock("@cplieger/web-terminal-ui", () => ({ createTerminal: createTerminalMock }));
vi.mock("@cplieger/web-terminal-ui/presets", () => ({
  presetAgentTabbed: presetAgentTabbedMock,
}));

// web-terminal-kiro's purple theme, passed through createTerminal (matches app.ts).
const THEME = {
  "--accent": "hsl(263.1683 100% 80%)",
  "--tab-hover-bg": "hsl(263.1683 100% 80% / 16%)",
  "--tab-active-bg": "hsl(263.1683 100% 80% / 32%)",
  "--tab-active-border": "color-mix(in oklch, var(--tab-active-bg), var(--text) 25%)",
  "--tab-active-fg": "#fff",
  "--status-working": "oklch(78% 0.15 300deg)",
  "--status-done": "oklch(78% 0.15 150deg)",
  "--status-input": "oklch(78% 0.15 95deg)",
};

// The brand accent is declared independently in app.ts's createTerminal
// theme, index.html's pre-JS critical CSS (which cannot read the JS theme),
// index.html's <meta name="theme-color">, and manifest.json's theme_color.
// No shared code home is possible across a TS module, embedded HTML, and a
// static JSON manifest, so the parity test below IS the synchronizing
// mitigation: it pins the two equivalent spellings of one color across all
// four sites.
const ACCENT_HSL = "hsl(263.1683 100% 80%)";
const ACCENT_HEX = "#c099ff";

// Mechanical link between the two spellings of the ONE accent: without this,
// updating the HSL sites alone leaves meta/manifest on the old hex and the
// parity test below still passes.
function hslToHex(hsl: string): string {
  const m = /^hsl\(([\d.]+) ([\d.]+)% ([\d.]+)%\)$/.exec(hsl);
  if (!m) {
    throw new Error(`unparseable hsl: ${hsl}`);
  }
  const h = Number(m[1]);
  const s = Number(m[2]) / 100;
  const l = Number(m[3]) / 100;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const hp = h / 60;
  const x = c * (1 - Math.abs((hp % 2) - 1));
  const [r1, g1, b1]: [number, number, number] =
    hp < 1
      ? [c, x, 0]
      : hp < 2
        ? [x, c, 0]
        : hp < 3
          ? [0, c, x]
          : hp < 4
            ? [0, x, c]
            : hp < 5
              ? [x, 0, c]
              : [c, 0, x];
  const m0 = l - c / 2;
  const to = (v: number) =>
    Math.round((v + m0) * 255)
      .toString(16)
      .padStart(2, "0");
  return `#${to(r1)}${to(g1)}${to(b1)}`;
}

// Read a static asset next to static-src. Resolve from INIT_CWD (set by the
// npm/npx launcher to the real static-src directory) so the fixture is found
// even when the runner changes process.cwd() — Stryker's dry run executes
// inside its .stryker-tmp sandbox, where a cwd-relative read ENOENTs. This is
// the single fixture-location policy for every static asset the suite reads.
function readStaticAsset(name: string): string {
  const sourceRoot = process.env["INIT_CWD"] ?? process.cwd();
  return readFileSync(resolve(sourceRoot, `../static/${name}`), "utf8");
}

// The fatal-overlay alertdialog contract duplicated (by necessity) between
// showFatal (app.ts) and the inline pre-module bootstrap watchdog
// (static/index.html). Both builders are asserted through this single helper
// so the two shapes cannot drift independently: a change to either side that
// breaks the shared shape fails here.
function expectFatalOverlayShape(overlay: HTMLElement): void {
  expect(overlay.getAttribute("role")).toBe("alertdialog");
  expect(overlay.getAttribute("aria-modal")).toBe("true");
  expect(overlay.getAttribute("aria-label")).toBe("Web Terminal for Kiro startup failure");
  expect(overlay.getAttribute("aria-describedby")).toBe("bootstrap-failure-message");
  // The pristine loading bar is always replaced by the dialog content.
  expect(overlay.querySelector(".bar")).toBeNull();
  // ...and so is the pre-JS status announcement: replaceChildren() drops every
  // pristine child, so the live region's "Starting the terminal" text cannot
  // survive next to the failure message.
  expect(overlay.querySelector(".loading-status")).toBeNull();
  const reload = overlay.querySelector("button");
  expect(reload?.type).toBe("button");
  expect(reload?.textContent).toBe("Reload");
  // Initial focus lands on the recovery CTA (the alertdialog pattern's
  // initial focus; Reload is the only actionable element left).
  expect(document.activeElement).toBe(reload);
}

// The inverse of expectFatalOverlayShape: the watchdog stood down, so the
// pristine pre-JS overlay is untouched and #terminal was never inerted. Shared
// by every stand-down test so the negative contract cannot drift or be
// asserted only partially.
function expectPristineOverlayUntouched(overlay: HTMLElement, root: HTMLElement): void {
  expect(overlay.getAttribute("role")).toBe("status");
  expect(overlay.querySelector(".bar")).not.toBeNull();
  expect(overlay.querySelector("button")).toBeNull();
  expect(root.hasAttribute("inert")).toBe(false);
}

// Locate the real inline bootstrap watchdog in static/index.html: the only
// inline <script> that is neither the importmap nor the src-bearing module
// loader. readStaticAsset supplies the shared INIT_CWD fixture-location policy,
// so watchdog discovery cannot drift from the suite's other static reads. Every
// watchdog test obtains the source through this single helper so fixture
// discovery cannot drift per test.
function readWatchdogSource(): string {
  const html = readStaticAsset("index.html");
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)].filter(
    (match) => !/src\s*=/i.test(match[1] ?? "") && !/importmap/i.test(match[1] ?? ""),
  );
  expect(scripts).toHaveLength(1);
  const source = scripts[0]?.[2] ?? "";
  expect(source).toContain("Bootstrap watchdog");
  return source;
}

// Evaluate the inline bootstrap watchdog, capturing the window listener(s) it
// registers and removing them when the calling test finishes: isolate is
// false, so window is shared across this file's tests, and a leaked
// capture-phase error listener would clobber a pristine #loading overlay in
// any later test that fires a window error event. Every watchdog test MUST
// evaluate the script through this helper, never via a bare new Function().
function evaluateWatchdog(source: string): void {
  const registered: Parameters<typeof window.addEventListener>[] = [];
  const originalAddEventListener = window.addEventListener.bind(window);
  const addSpy = vi.spyOn(window, "addEventListener").mockImplementation((...args) => {
    registered.push(args as Parameters<typeof window.addEventListener>);
    originalAddEventListener(...(args as Parameters<typeof window.addEventListener>));
  });
  onTestFinished(() => {
    for (const [type, listener, options] of registered) {
      window.removeEventListener(type, listener, options);
    }
  });
  try {
    new Function(source)();
  } finally {
    addSpy.mockRestore();
  }
}

// index.html's pristine pre-JS #terminal root. booted: createTerminal has
// built its UI inside it (the watchdog's booted-root stand-down).
function appendTerminalRoot({ booted = false } = {}): HTMLElement {
  const root = document.createElement("div");
  root.id = "terminal";
  if (booted) {
    root.appendChild(document.createElement("div")); // the built UI
  }
  document.body.appendChild(root);
  return root;
}

// index.html's pristine pre-JS #loading overlay (role=status, with its two
// children: the aria-hidden .bar and the .loading-status announcement): the
// exact state both showFatal and the watchdog key their behavior on.
// fade: the kernel's first-frame fade-out has begun.
function appendPristineOverlay({ fade = false } = {}): HTMLElement {
  const overlay = document.createElement("div");
  overlay.id = "loading";
  overlay.setAttribute("role", "status");
  overlay.setAttribute("aria-label", "Loading");
  if (fade) {
    overlay.classList.add("fade");
  }
  const bar = document.createElement("div");
  bar.className = "bar";
  overlay.appendChild(bar);
  // index.html's readable content for the role=status region (the bar is
  // aria-hidden); both fatal builders replaceChildren() it away.
  const status = document.createElement("p");
  status.className = "loading-status";
  status.textContent = "Starting the terminal\u2026";
  overlay.appendChild(status);
  document.body.appendChild(overlay);
  return overlay;
}

// The synthetic window "error" event the watchdog keys on: `target` for a
// resource load failure, `error` for an uncaught runtime error. (The
// capture-flag test deliberately dispatches on a real attached element
// instead, so the event can only reach the capture-phase window listener.)
function dispatchWindowError({ target, error }: { target?: unknown; error?: unknown } = {}): void {
  const event = new Event("error");
  if (target !== undefined) {
    Object.defineProperty(event, "target", { value: target });
  }
  if (error !== undefined) {
    Object.defineProperty(event, "error", { value: error });
  }
  window.dispatchEvent(event);
}

describe("web-terminal-kiro bootstrap (app.ts)", () => {
  beforeEach(() => {
    // resetModules so each dynamic import re-runs app.ts top-level code. Mock
    // call history is cleared by the config's clearMocks/mockReset before each
    // test (implementations given to vi.fn persist through mockReset).
    vi.resetModules();
    document.body.replaceChildren();
  });

  it("throws a clear error when the #terminal root element is missing", async () => {
    await expect(import("./app.js")).rejects.toThrow(
      "web-terminal-kiro: missing #terminal root element",
    );
    expect(createTerminalMock).not.toHaveBeenCalled();
  });

  it("builds the terminal with the agent preset and theme when #loading is absent", async () => {
    const root = appendTerminalRoot();

    await import("./app.js");

    expect(createTerminalMock).toHaveBeenCalledTimes(1);
    expect(createTerminalMock).toHaveBeenCalledWith(root, {
      features: ["preset-features"],
      theme: THEME,
    });
  });

  it("passes the #loading element to createTerminal when it is present", async () => {
    const root = appendTerminalRoot();
    const loading = document.createElement("div");
    loading.id = "loading";
    document.body.appendChild(loading);

    await import("./app.js");

    expect(createTerminalMock).toHaveBeenCalledTimes(1);
    expect(createTerminalMock).toHaveBeenCalledWith(root, {
      features: ["preset-features"],
      theme: THEME,
      loading,
    });
  });

  it("surfaces an alert dialog on the #loading overlay when #terminal is missing but #loading exists", async () => {
    const overlay = appendPristineOverlay();

    await expect(import("./app.js")).rejects.toThrow(
      "web-terminal-kiro: missing #terminal root element",
    );

    // The index.html watchdog only acts while the pristine .bar is present;
    // showFatal replacing the children (asserted inside the shape helper) is
    // what stops it from clobbering this message when the rethrown error
    // reaches the window error listener.
    expectFatalOverlayShape(overlay);
    const description = overlay.querySelector("#bootstrap-failure-message");
    expect(description?.textContent).toContain("Web Terminal for Kiro failed to start");
    expect(createTerminalMock).not.toHaveBeenCalled();
  });

  it("offers a working reload action when startup fails", async () => {
    const reload = vi.spyOn(window.location, "reload").mockImplementation(() => undefined);
    const overlay = appendPristineOverlay();

    await expect(import("./app.js")).rejects.toThrow(
      "web-terminal-kiro: missing #terminal root element",
    );

    const reloadButton = overlay.querySelector("button");
    expectFatalOverlayShape(overlay);
    reloadButton?.click();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("reveals the #loading overlay with an error message and rethrows when createTerminal throws", async () => {
    const root = appendTerminalRoot();
    const loading = appendPristineOverlay({ fade: true });
    createTerminalMock.mockImplementationOnce(() => {
      throw new Error("kernel boom");
    });

    await expect(import("./app.js")).rejects.toThrow("kernel boom");

    expect(loading.classList.contains("fade")).toBe(false);
    expectFatalOverlayShape(loading);
    // showFatal backs its aria-modal claim with a real inert on the terminal
    // root; asserted here (the only app.ts failure path where #terminal
    // exists) so a regression cannot hide behind the watchdog test's own
    // inert assertion below.
    expect(root.hasAttribute("inert")).toBe(true);
    const description = loading.querySelector("#bootstrap-failure-message");
    expect(description?.textContent).toContain("Failed to start the terminal");
  });

  it("surfaces the fatal dialog and rethrows when the agent preset fails", async () => {
    const root = appendTerminalRoot();
    const loading = appendPristineOverlay({ fade: true });
    const failure = new Error("preset boom");
    presetAgentTabbedMock.mockImplementationOnce(() => {
      throw failure;
    });

    await expect(import("./app.js")).rejects.toBe(failure);

    expect(createTerminalMock).not.toHaveBeenCalled();
    expect(loading.classList.contains("fade")).toBe(false);
    expectFatalOverlayShape(loading);
    expect(root.hasAttribute("inert")).toBe(true);
    expect(loading.querySelector("#bootstrap-failure-message")?.textContent).toContain(
      "Failed to start the terminal",
    );
  });

  it("rethrows the original error without touching the DOM when createTerminal throws and #loading is absent", async () => {
    appendTerminalRoot();
    createTerminalMock.mockImplementationOnce(() => {
      throw new Error("kernel boom no overlay");
    });

    await expect(import("./app.js")).rejects.toThrow("kernel boom no overlay");
    expect(createTerminalMock).toHaveBeenCalledTimes(1);
    expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  });

  it("builds the same alertdialog shape when the real index.html watchdog fires", () => {
    // Execute the REAL inline bootstrap watchdog from static/index.html (the
    // pre-module, CSP-hashed script that catches /app.js load failures before
    // app.ts can run) against index.html's pristine pre-JS markup, and assert
    // it produces the exact overlay shape showFatal builds — via the same
    // expectFatalOverlayShape helper, so the two builders (which cannot share
    // code) are pinned to one contract from a single source. Mirrors how
    // routes_test.go independently re-extracts the same inline scripts for
    // the CSP hash check.
    const watchdogSource = readWatchdogSource();

    // Recreate index.html's static body: the terminal root plus the pristine
    // loading overlay (role=status, .bar child, no fade).
    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();

    // Evaluate the watchdog (via the leak-guarding helper), then simulate the
    // failure it exists for: a <script> element (e.g. /app.js) firing a
    // NON-bubbling error event on itself, the way real resource load errors
    // fire. Dispatching on the attached element -- not window -- means only
    // the watchdog's capture-phase window listener can see the event, so this
    // test pins the load-bearing `, true` capture flag in index.html: with it
    // removed (bubble phase), the event never reaches the watchdog and this
    // test fails.
    evaluateWatchdog(watchdogSource);
    const scriptEl = document.createElement("script");
    document.body.appendChild(scriptEl);
    scriptEl.dispatchEvent(new Event("error"));

    expectFatalOverlayShape(overlay);
    const description = overlay.querySelector("#bootstrap-failure-message");
    expect(description?.textContent).toContain("Web Terminal for Kiro failed to load");
    // aria-modal made true: the watchdog inerts the terminal root, exactly
    // like showFatal.
    expect(root.hasAttribute("inert")).toBe(true);
    // The watchdog's Reload button must actually reload -- the same contract
    // the app.ts "offers a working reload action" test pins for showFatal. A
    // dead click listener would leave a dead-end recovery CTA on the only
    // actionable element left.
    const reloadSpy = vi.spyOn(window.location, "reload").mockImplementation(() => undefined);
    overlay.querySelector("button")?.click();
    expect(reloadSpy).toHaveBeenCalledTimes(1);
  });

  it("watchdog stands down when the overlay is already fading out (booted terminal)", () => {
    evaluateWatchdog(readWatchdogSource());

    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay({ fade: true }); // first frame rendered; fade-out under way

    const scriptEl = document.createElement("script");
    dispatchWindowError({ target: scriptEl });

    expectPristineOverlayUntouched(overlay, root);
  });

  it("watchdog stands down when the overlay has already been removed after boot", () => {
    evaluateWatchdog(readWatchdogSource());

    // Post-boot steady state: the kernel removed #loading on transitionend, so
    // a later uncaught runtime error reaches the capture-phase listener with no
    // overlay in the document at all. The watchdog must return without touching
    // anything (and without throwing inside the error listener).
    const root = appendTerminalRoot({ booted: true });

    expect(() =>
      dispatchWindowError({ error: new Error("post-boot runtime error") }),
    ).not.toThrow();

    expect(document.getElementById("loading")).toBeNull();
    expect(document.querySelector('[role="alertdialog"]')).toBeNull();
    expect(root.hasAttribute("inert")).toBe(false);
  });

  it("watchdog does not clobber an overlay showFatal already converted", () => {
    evaluateWatchdog(readWatchdogSource());

    appendTerminalRoot();
    // Recreate the post-showFatal overlay: bar replaced by the dialog content.
    const overlay = document.createElement("div");
    overlay.id = "loading";
    overlay.setAttribute("role", "alertdialog");
    overlay.setAttribute("aria-modal", "true");
    const description = document.createElement("p");
    description.id = "bootstrap-failure-message";
    description.textContent = "Web Terminal for Kiro failed to start.";
    const reload = document.createElement("button");
    reload.type = "button";
    reload.textContent = "Reload";
    overlay.replaceChildren(description, reload);
    document.body.appendChild(overlay);

    const scriptEl = document.createElement("script");
    dispatchWindowError({ target: scriptEl });

    // showFatal's branch-specific message survives; the watchdog's generic
    // failed-to-load text never replaces it.
    expect(overlay.querySelector("#bootstrap-failure-message")?.textContent).toBe(
      "Web Terminal for Kiro failed to start.",
    );
  });

  it("watchdog ignores a non-script resource error (e.g. an image failing to load)", () => {
    evaluateWatchdog(readWatchdogSource());

    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();

    const imgEl = document.createElement("img");
    dispatchWindowError({ target: imgEl }); // plain Event: no .error property

    expectPristineOverlayUntouched(overlay, root);
  });

  it("watchdog fires on a failed <link rel=stylesheet> (/style.css)", () => {
    // /style.css is render-critical, not cosmetic: it carries
    // .wt-root.wt-viewport's fixed/inset layout and the .term-output scroll
    // container, so a 404 leaves an unstyled, unusable terminal while /app.js
    // still loads and createTerminal still succeeds -- no throw ever reaches
    // app.ts's catch. The watchdog is the only thing that can surface it.
    evaluateWatchdog(readWatchdogSource());

    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();

    const linkEl = document.createElement("link");
    linkEl.rel = "stylesheet";
    linkEl.href = "/style.css";
    dispatchWindowError({ target: linkEl }); // plain Event: no .error property

    expectFatalOverlayShape(overlay);
    expect(root.hasAttribute("inert")).toBe(true);
  });

  it("watchdog surfaces a stylesheet that failed before the listener was registered", () => {
    // The race the sweep exists for: <link rel=stylesheet> is in <head>, and a
    // classic inline script is blocked while a stylesheet is pending, so for a
    // fast local 404 the UA has already queued (and the parser already run) the
    // link's error task before this end-of-<body> script registers its
    // listener. Resource error events do not bubble and are never replayed, so
    // the listener alone can never see it -- the stylesheet branch would
    // silently never fire in exactly the common case. Here the failed link is
    // already in the document and NO error event is dispatched at all, so only
    // the post-registration sweep can raise the dialog.
    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();
    const linkEl = document.createElement("link");
    linkEl.rel = "stylesheet"; // no href: happy-dom must not attempt a real fetch
    document.head.appendChild(linkEl);
    onTestFinished(() => {
      linkEl.remove(); // beforeEach only clears <body>
    });

    evaluateWatchdog(readWatchdogSource());

    expectFatalOverlayShape(overlay);
    expect(root.hasAttribute("inert")).toBe(true);
  });

  it("does not boot over the watchdog's fatal stylesheet dialog", async () => {
    // The second half of the stylesheet flow the test above stops short of: a
    // failed /style.css does NOT prevent /app.js from evaluating, so app.ts
    // runs with the watchdog's alertdialog already on screen and #terminal
    // inerted. It must recognize that handoff and abort instead of passing the
    // converted overlay to createTerminal as `loading` -- the kernel would
    // fade and REMOVE the only Reload affordance on first frame while nothing
    // un-inerts #terminal, leaving an inert, unstyled, message-less page.
    evaluateWatchdog(readWatchdogSource());

    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();

    const linkEl = document.createElement("link");
    linkEl.rel = "stylesheet";
    linkEl.href = "/style.css";
    dispatchWindowError({ target: linkEl });

    await expect(import("./app.js")).rejects.toThrow(
      "bootstrap watchdog already reported a fatal resource failure",
    );

    expect(createTerminalMock).not.toHaveBeenCalled();
    // The watchdog's recovery UI survives app.ts's pass, inert included.
    expectFatalOverlayShape(overlay);
    expect(overlay.querySelector("#bootstrap-failure-message")?.textContent).toContain(
      "Web Terminal for Kiro failed to load",
    );
    expect(root.hasAttribute("inert")).toBe(true);
  });

  it("watchdog ignores a failed non-stylesheet <link> (e.g. an icon)", () => {
    // Icon and manifest links 404 in the wild; they must never raise the
    // fatal dialog, which is why the guard tests rel, not just the element.
    evaluateWatchdog(readWatchdogSource());

    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();

    const iconEl = document.createElement("link");
    iconEl.rel = "icon";
    iconEl.href = "/icon-192.png";
    dispatchWindowError({ target: iconEl });

    expectPristineOverlayUntouched(overlay, root);
  });

  it("watchdog fires on an uncaught runtime error (module evaluation failure)", () => {
    evaluateWatchdog(readWatchdogSource());

    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();

    // A runtime error surfaces as an error event on window with .error set
    // and a non-element target; recreate that shape.
    dispatchWindowError({ target: window, error: new Error("evaluate boom") });

    expectFatalOverlayShape(overlay);
    expect(overlay.querySelector("#bootstrap-failure-message")?.textContent).toContain(
      "Web Terminal for Kiro failed to load",
    );
    expect(root.hasAttribute("inert")).toBe(true);
  });

  it("watchdog stands down after createTerminal has built UI inside #terminal", () => {
    const watchdogSource = readWatchdogSource();

    // Booted page: createTerminal built its UI inside #terminal; the overlay
    // is still pristine (first frame not yet rendered, no fade).
    const root = appendTerminalRoot({ booted: true });
    const overlay = appendPristineOverlay();

    evaluateWatchdog(watchdogSource);
    dispatchWindowError({ error: new Error("stray runtime error") });

    // The watchdog must NOT hijack a booted terminal's overlay.
    expectPristineOverlayUntouched(overlay, root);
  });

  it("declares one brand accent across app.ts, index.html and manifest.json", () => {
    expect(hslToHex(ACCENT_HSL)).toBe(ACCENT_HEX);
    expect(THEME["--accent"]).toBe(ACCENT_HSL);
    const html = readStaticAsset("index.html");
    // The two declaration sites, asserted individually and bounded to their own
    // rule: a match COUNT cannot distinguish a declaration from the file's own
    // doc comment (which spells the same literal), so a single-site drift would
    // still clear a >= 2 bound. The [^}]* bound keeps each assertion inside the
    // named rule rather than matching the accent later in the stylesheet.
    const escapedAccent = ACCENT_HSL.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    // #loading critical CSS (the pre-JS overlay, which cannot read the JS theme):
    expect(html).toMatch(new RegExp(`#loading\\s*\\{[^}]*--accent:\\s*${escapedAccent}\\s*;`));
    // the no-JS fallback message:
    expect(html).toMatch(
      new RegExp(`\\.noscript-fallback\\s*\\{[^}]*color:\\s*${escapedAccent}\\s*;`),
    );
    // installed-PWA chrome: meta and manifest must agree, in hex form
    expect(html).toContain(`<meta name="theme-color" content="${ACCENT_HEX}">`);
    const manifest: unknown = JSON.parse(readStaticAsset("manifest.json"));
    expect((manifest as { theme_color: string }).theme_color).toBe(ACCENT_HEX);
  });

  it("index.html's pristine overlay satisfies the watchdog's stand-down guards", () => {
    // Why this test exists: the watchdog's stand-down guards read index.html's
    // REAL markup (a .bar child, no .fade) while appendPristineOverlay()
    // re-creates that markup by hand. If index.html's overlay ever loses the
    // .bar (or #terminal ships a pre-JS child), the watchdog silently never
    // fires in production while every watchdog test above still passes against
    // its own fabricated overlay -- so pin the hand-built fixture to the
    // served file here.
    // Drop the external stylesheet link before parsing: happy-dom fetches
    // <link rel=stylesheet> hrefs off a parsed document, which would make this
    // assertion attempt a real HTTP request. The guards below live entirely in
    // the markup.
    const html = readStaticAsset("index.html").replace(
      /<link\b[^>]*rel=["']?stylesheet[^>]*>/gi,
      "",
    );
    const doc = new DOMParser().parseFromString(html, "text/html");
    const overlay = doc.getElementById("loading");
    // The guards the watchdog keys on, read from the served file rather than
    // from appendPristineOverlay()'s hand-built copy.
    expect(overlay?.getAttribute("role")).toBe("status");
    expect(overlay?.querySelector(".bar")).not.toBeNull();
    expect(overlay?.querySelector(".bar")?.getAttribute("aria-hidden")).toBe("true");
    expect(overlay?.querySelector(".loading-status")?.textContent).toContain(
      "Starting the terminal",
    );
    expect(overlay?.classList.contains("fade")).toBe(false);
    // ...and the booted-root guard's pre-JS precondition: #terminal is empty
    // until createTerminal builds into it.
    const terminalRoot = doc.getElementById("terminal");
    expect(terminalRoot).not.toBeNull();
    expect(terminalRoot?.firstElementChild).toBeNull();
  });
});
