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
  const reload = overlay.querySelector("button");
  expect(reload?.type).toBe("button");
  expect(reload?.textContent).toBe("Reload");
  // Initial focus lands on the recovery CTA (the alertdialog pattern's
  // initial focus; Reload is the only actionable element left).
  expect(document.activeElement).toBe(reload);
}

// Locate the real inline bootstrap watchdog in static/index.html: the only
// inline <script> that is neither the importmap nor the src-bearing module
// loader. Resolve from INIT_CWD (set by the npm/npx launcher to the real
// static-src directory) so the fixture is found even when the runner changes
// process.cwd() — Stryker's dry run executes inside its .stryker-tmp sandbox,
// where a cwd-relative read ENOENTs. Every watchdog test obtains the source
// through this single helper so fixture discovery cannot drift per test.
function readWatchdogSource(): string {
  const sourceRoot = process.env["INIT_CWD"] ?? process.cwd();
  const html = readFileSync(resolve(sourceRoot, "../static/index.html"), "utf8");
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
    const root = document.createElement("div");
    root.id = "terminal";
    document.body.appendChild(root);

    await import("./app.js");

    expect(createTerminalMock).toHaveBeenCalledTimes(1);
    expect(createTerminalMock).toHaveBeenCalledWith(root, {
      features: ["preset-features"],
      theme: THEME,
    });
  });

  it("passes the #loading element to createTerminal when it is present", async () => {
    const root = document.createElement("div");
    root.id = "terminal";
    document.body.appendChild(root);
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
    const overlay = document.createElement("div");
    overlay.id = "loading";
    overlay.setAttribute("role", "status"); // mirror index.html's static markup
    overlay.setAttribute("aria-label", "Loading");
    const bar = document.createElement("div");
    bar.className = "bar";
    overlay.appendChild(bar);
    document.body.appendChild(overlay);

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
    const overlay = document.createElement("div");
    overlay.id = "loading";
    overlay.setAttribute("role", "status"); // mirror index.html's static markup
    overlay.setAttribute("aria-label", "Loading");
    const bar = document.createElement("div");
    bar.className = "bar";
    overlay.appendChild(bar);
    document.body.appendChild(overlay);

    await expect(import("./app.js")).rejects.toThrow(
      "web-terminal-kiro: missing #terminal root element",
    );

    const reloadButton = overlay.querySelector("button");
    expectFatalOverlayShape(overlay);
    reloadButton?.click();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("reveals the #loading overlay with an error message and rethrows when createTerminal throws", async () => {
    const root = document.createElement("div");
    root.id = "terminal";
    document.body.appendChild(root);
    const loading = document.createElement("div");
    loading.id = "loading";
    loading.classList.add("fade");
    loading.setAttribute("role", "status"); // mirror index.html's static markup
    loading.setAttribute("aria-label", "Loading");
    const bar = document.createElement("div");
    bar.className = "bar";
    loading.appendChild(bar);
    document.body.appendChild(loading);
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

  it("rethrows the original error without touching the DOM when createTerminal throws and #loading is absent", async () => {
    const root = document.createElement("div");
    root.id = "terminal";
    document.body.appendChild(root);
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
    const root = document.createElement("div");
    root.id = "terminal";
    document.body.appendChild(root);
    const overlay = document.createElement("div");
    overlay.id = "loading";
    overlay.setAttribute("role", "status");
    overlay.setAttribute("aria-label", "Loading");
    const bar = document.createElement("div");
    bar.className = "bar";
    overlay.appendChild(bar);
    document.body.appendChild(overlay);

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

    const root = document.createElement("div");
    root.id = "terminal";
    document.body.appendChild(root);
    const overlay = document.createElement("div");
    overlay.id = "loading";
    overlay.setAttribute("role", "status");
    overlay.setAttribute("aria-label", "Loading");
    overlay.classList.add("fade"); // first frame rendered; fade-out under way
    const bar = document.createElement("div");
    bar.className = "bar";
    overlay.appendChild(bar);
    document.body.appendChild(overlay);

    const scriptEl = document.createElement("script");
    const errorEvent = new Event("error");
    Object.defineProperty(errorEvent, "target", { value: scriptEl });
    window.dispatchEvent(errorEvent);

    expect(overlay.getAttribute("role")).toBe("status");
    expect(overlay.querySelector(".bar")).not.toBeNull();
    expect(overlay.querySelector("button")).toBeNull();
    expect(root.hasAttribute("inert")).toBe(false);
  });

  it("watchdog does not clobber an overlay showFatal already converted", () => {
    evaluateWatchdog(readWatchdogSource());

    const root = document.createElement("div");
    root.id = "terminal";
    document.body.appendChild(root);
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
    const errorEvent = new Event("error");
    Object.defineProperty(errorEvent, "target", { value: scriptEl });
    window.dispatchEvent(errorEvent);

    // showFatal's branch-specific message survives; the watchdog's generic
    // failed-to-load text never replaces it.
    expect(overlay.querySelector("#bootstrap-failure-message")?.textContent).toBe(
      "Web Terminal for Kiro failed to start.",
    );
  });

  it("watchdog ignores a non-script resource error (e.g. an image failing to load)", () => {
    evaluateWatchdog(readWatchdogSource());

    const root = document.createElement("div");
    root.id = "terminal";
    document.body.appendChild(root);
    const overlay = document.createElement("div");
    overlay.id = "loading";
    overlay.setAttribute("role", "status");
    overlay.setAttribute("aria-label", "Loading");
    const bar = document.createElement("div");
    bar.className = "bar";
    overlay.appendChild(bar);
    document.body.appendChild(overlay);

    const imgEl = document.createElement("img");
    const errorEvent = new Event("error"); // plain Event: no .error property
    Object.defineProperty(errorEvent, "target", { value: imgEl });
    window.dispatchEvent(errorEvent);

    expect(overlay.getAttribute("role")).toBe("status");
    expect(overlay.querySelector(".bar")).not.toBeNull();
    expect(overlay.querySelector("button")).toBeNull();
  });

  it("watchdog fires on an uncaught runtime error (module evaluation failure)", () => {
    evaluateWatchdog(readWatchdogSource());

    const root = document.createElement("div");
    root.id = "terminal";
    document.body.appendChild(root);
    const overlay = document.createElement("div");
    overlay.id = "loading";
    overlay.setAttribute("role", "status");
    overlay.setAttribute("aria-label", "Loading");
    const bar = document.createElement("div");
    bar.className = "bar";
    overlay.appendChild(bar);
    document.body.appendChild(overlay);

    // A runtime error surfaces as an error event on window with .error set
    // and a non-element target; recreate that shape.
    const errorEvent = new Event("error");
    Object.defineProperty(errorEvent, "error", { value: new Error("evaluate boom") });
    Object.defineProperty(errorEvent, "target", { value: window });
    window.dispatchEvent(errorEvent);

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
    const root = document.createElement("div");
    root.id = "terminal";
    root.appendChild(document.createElement("div")); // the built UI
    document.body.appendChild(root);
    const overlay = document.createElement("div");
    overlay.id = "loading";
    overlay.setAttribute("role", "status");
    overlay.setAttribute("aria-label", "Loading");
    const bar = document.createElement("div");
    bar.className = "bar";
    overlay.appendChild(bar);
    document.body.appendChild(overlay);

    evaluateWatchdog(watchdogSource);
    const errorEvent = new Event("error");
    Object.defineProperty(errorEvent, "error", { value: new Error("stray runtime error") });
    window.dispatchEvent(errorEvent);

    // The watchdog must NOT hijack a booted terminal's overlay.
    expect(overlay.getAttribute("role")).toBe("status");
    expect(overlay.querySelector(".bar")).not.toBeNull();
    expect(root.hasAttribute("inert")).toBe(false);
  });
});
