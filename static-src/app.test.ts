// The DOM half of this app's suite: runs in the browser project (real headless
// Chromium), with no per-file environment pragma since Browser Mode is a
// runner rather than an environment. Static assets arrive as `?raw` imports so
// assertions read the SHIPPED bytes without a filesystem call. The four checks
// needing a real filesystem live in app.node.test.ts.
import { beforeEach, describe, expect, it, onTestFinished, vi } from "vitest";
// Real, not mocked below: compares the served HTML against what the library ships.
import { STARTUP_FAILURE_COPY } from "@cplieger/web-terminal-ui/startup-copy";
// Also real, from the /style-contract subpath (not the root, which is mocked below).
import {
  LOADING_OVERLAY_CLASSES,
  PUBLIC_THEME_TOKENS,
} from "@cplieger/web-terminal-ui/style-contract";
// SERVED static assets, as text; Vite inlines each at transform time, so a
// renamed or deleted asset fails to RESOLVE instead of throwing at runtime.
import indexHtml from "../static/index.html?raw";
import manifestJson from "../static/manifest.json?raw";
import faviconAlertSvg from "../static/favicon-alert.svg?raw";
import faviconDoneSvg from "../static/favicon-done.svg?raw";
import faviconInputSvg from "../static/favicon-input.svg?raw";
// Two files the UI package's `exports` map does not publish, read as source
// text via relative node_modules paths (a non-exported subpath can't be
// imported by package name).
import kernelSource from "./node_modules/@cplieger/web-terminal-ui/src/kernel/kernel.ts?raw";
import pageCss from "./node_modules/@cplieger/web-terminal-ui/css/page.css?raw";

// app.ts imports createTerminal and presetAgentTabbed; mock both.
// presetAgentTabbedMock returns a sentinel the assertions match against.
const { createTerminalMock, presetAgentTabbedMock, localScrollbackStorageMock } = vi.hoisted(
  () => ({
    createTerminalMock: vi.fn(),
    presetAgentTabbedMock: vi.fn(() => ["preset-features"]),
    // Sentinel: proves the app hands the library's own store through.
    localScrollbackStorageMock: vi.fn(() => ({ kind: "scrollback-store" })),
  }),
);
vi.mock("@cplieger/web-terminal-ui", () => ({
  createTerminal: createTerminalMock,
  localScrollbackStorage: localScrollbackStorageMock,
}));
vi.mock("@cplieger/web-terminal-ui/presets", () => ({
  presetAgentTabbed: presetAgentTabbedMock,
}));

// web-terminal-kiro's purple theme, passed through createTerminal (matches app.ts).
// No --tab-active-border: the library derives the active tab's edge from this
// app's own --tab-active-bg.
const THEME = {
  "--accent": "hsl(263.1683 100% 80%)",
  "--tab-hover-bg": "hsl(263.1683 100% 80% / 16%)",
  "--tab-active-bg": "hsl(263.1683 100% 80% / 32%)",
  "--tab-active-fg": "#fff",
  "--status-working": "#c6a0ff",
  "--status-done": "oklch(78% 0.15 150deg)",
  "--status-input": "oklch(78% 0.15 95deg)",
  "--status-failed": "#dc2626",
};

// The brand accent is declared independently in app.ts's theme, index.html's
// critical CSS, its <meta name="theme-color">, and manifest.json's theme_color.
// No shared code home is possible across a TS module, embedded HTML, and a
// static JSON manifest, so the parity test below pins the two spellings across
// all four sites.
const ACCENT_HSL = "hsl(263.1683 100% 80%)";
const ACCENT_HEX = "#c099ff";

// Mechanical link between the two spellings: without this, updating the HSL
// sites alone leaves meta/manifest on the old hex while the parity test passes.
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
  // Standard HSL->RGB piecewise table, indexed by hue sector.
  const rgbByHueSector: [number, number, number][] = [
    [c, x, 0],
    [x, c, 0],
    [0, c, x],
    [0, x, c],
    [x, 0, c],
    [c, 0, x],
  ];
  const [r1, g1, b1] = rgbByHueSector[Math.min(Math.floor(hp), 5)]!;
  const m0 = l - c / 2;
  const to = (v: number) =>
    Math.round((v + m0) * 255)
      .toString(16)
      .padStart(2, "0");
  return `#${to(r1)}${to(g1)}${to(b1)}`;
}

// The fatal-overlay alertdialog contract of index.html's inline pre-module
// watchdog. It is the last hand-built fatal surface in this app -- the watchdog
// reports "the JS bundle never ran", a rung below `import` by definition.
function expectFatalOverlayShape(overlay: HTMLElement, root: HTMLElement): void {
  expect(overlay.getAttribute("role")).toBe("alertdialog");
  // aria-modal claims the rest of the page is inert; the watchdog makes that
  // true by inerting the terminal root.
  expect(root.hasAttribute("inert")).toBe(true);
  // Set before app.ts can boot; app.ts consumes this token rather than the
  // dialog's ARIA or child shape.
  expect(overlay.hasAttribute("data-bootstrap-fatal")).toBe(true);
  expect(overlay.getAttribute("aria-modal")).toBe("true");
  // Named by a visible title via aria-labelledby (not aria-label), matching
  // web-terminal-ui's renderFatalStartup() so the two fatal-startup dialogs
  // read alike. The stale aria-label must be GONE, not merely overridden.
  expect(overlay.hasAttribute("aria-label")).toBe(false);
  expect(overlay.getAttribute("aria-labelledby")).toBe("bootstrap-failure-title");
  const title = overlay.querySelector("#bootstrap-failure-title");
  expect(title?.tagName).toBe("H2");
  // From the library's exported constant, not restated -- so a wording change
  // on the library side fails here instead of shipping two different words.
  expect(title?.textContent).toBe(STARTUP_FAILURE_COPY.title);
  expect(overlay.getAttribute("aria-describedby")).toBe("bootstrap-failure-message");
  expect(overlay.querySelector(".wt-loading-bar")).toBeNull();
  // ...and any status line the kernel wrote: replaceChildren() drops every
  // child.
  expect(overlay.querySelector(".wt-loading-text")).toBeNull();
  expect(overlay.querySelector(".wt-loading-live")).toBeNull();
  const reload = overlay.querySelector("button");
  expect(reload?.type).toBe("button");
  expect(reload?.textContent).toBe(STARTUP_FAILURE_COPY.reloadLabel);
  // Initial focus lands on the recovery CTA (alertdialog pattern; Reload is
  // the only actionable element left).
  expect(document.activeElement).toBe(reload);
  // ...and Tab is NOT trapped. Reload is the only focusable node in the
  // document, so a trap had nothing to contain. Checked from both the button
  // and <body> since every test in this file shares one window and a leaked
  // trap would swallow Tab for later tests.
  for (const target of [reload, document.body]) {
    const tab = new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true });
    expect(target?.dispatchEvent(tab)).toBe(true);
    expect(tab.defaultPrevented).toBe(false);
  }
  expect(document.activeElement).toBe(reload);
}

// The inverse of expectFatalOverlayShape: the watchdog stood down, so the
// pristine overlay is untouched and #terminal was never inerted.
function expectPristineOverlayUntouched(overlay: HTMLElement, root: HTMLElement): void {
  expect(overlay.getAttribute("role")).toBe("status");
  expect(overlay.querySelector(".wt-loading-bar")).not.toBeNull();
  expect(overlay.querySelector("button")).toBeNull();
  expect(root.hasAttribute("inert")).toBe(false);
}

// Locates the real inline bootstrap watchdog in the served index.html: the
// only inline <script> that is neither the importmap nor the module loader.
function readWatchdogSource(): string {
  // The end tag is matched as `<\/script\b[^>]*>`, not `<\/script\s*>`: an HTML
  // parser also ends a script element at `</script foo>`, so a pattern only
  // tolerating whitespace before `>` reads past a real end tag and swallows
  // the rest of the document. `\b` keeps `</scriptfoo>` out.
  const scripts = [...indexHtml.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\b[^>]*>/gi)].filter(
    (match) => !/src\s*=/i.test(match[1] ?? "") && !/importmap/i.test(match[1] ?? ""),
  );
  expect(scripts).toHaveLength(1);
  const source = scripts[0]?.[2] ?? "";
  expect(source).toContain("Bootstrap watchdog");
  return source;
}

// A stand-in for `window` whose location.reload() can be observed.
//
// In a real browser `window.location.reload` is a non-configurable, non-writable
// OWN property with no Location.prototype.reload to patch, so neither vi.spyOn
// nor Object.defineProperty can reach it. Shadowing the `window` IDENTIFIER for
// one evaluation keeps the assertion just as strong without pretending a
// platform object is patchable.
//
// Every other property forwards to the real window, with functions bound to
// it: a Web API method called with the proxy as its receiver is an illegal
// invocation.
function windowWithObservableReload(reload: () => void): Window {
  const location = { reload };
  const shadow = new Proxy(window, {
    get(target, property): unknown {
      if (property === "location") {
        return location;
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function"
        ? (value as (...args: never[]) => unknown).bind(target)
        : value;
    },
  });
  return shadow;
}

// Evaluates the inline bootstrap watchdog, capturing the window listener(s) it
// registers and removing them when the test finishes: every test in this file
// shares one window, and a leaked capture-phase error listener would clobber a
// pristine #loading overlay in a later test. Every watchdog test must go
// through this helper, never a bare new Function().
//
// `reload` is passed only by the test that clicks the dialog's Reload button;
// see windowWithObservableReload above.
function evaluateWatchdog(source: string, { reload }: { reload?: () => void } = {}): void {
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
    if (reload === undefined) {
      new Function(source)();
    } else {
      new Function("window", source)(windowWithObservableReload(reload));
    }
  } finally {
    addSpy.mockRestore();
  }
}

// index.html's pristine pre-JS #terminal root. booted: createTerminal has
// built its UI inside it.
function appendTerminalRoot({ booted = false } = {}): HTMLElement {
  const root = document.createElement("div");
  root.id = "terminal";
  if (booted) {
    root.appendChild(document.createElement("div")); // the built UI
  }
  document.body.appendChild(root);
  return root;
}

// index.html's pristine pre-JS #loading overlay (role=status, one aria-hidden
// .wt-loading-bar child). fade: the kernel's first-frame fade-out has begun.
function appendPristineOverlay({ fade = false } = {}): HTMLElement {
  const overlay = document.createElement("div");
  overlay.id = "loading";
  overlay.className = "wt-loading";
  overlay.setAttribute("role", "status");
  overlay.setAttribute("aria-label", "Loading");
  if (fade) {
    overlay.classList.add("fade");
  }
  // The overlay's only pre-JS child; web-terminal-ui's kernel writes the
  // progressive status line into this region now. Named wt-loading-bar, not
  // bar, because page.css owns the overlay's appearance and must not claim a
  // name as generic as `.bar` in a host document.
  const bar = document.createElement("div");
  bar.className = "wt-loading-bar";
  bar.setAttribute("aria-hidden", "true");
  overlay.appendChild(bar);
  document.body.appendChild(overlay);
  return overlay;
}

// A <link rel="stylesheet"> in <head>, matching where index.html declares its
// stylesheet. beforeEach only clears <body>, so the link must be removed when
// the test finishes or it leaks to later watchdog tests in this file. Never
// given an href, so .sheet stays null -- the failed state the sweep keys on,
// reached with no network round trip. loaded/disabled: the sweep's two gates.
function appendHeadStylesheet({
  media,
  disabled = false,
  loaded = false,
}: { media?: string; disabled?: boolean; loaded?: boolean } = {}): HTMLLinkElement {
  const link = document.createElement("link");
  link.rel = "stylesheet";
  if (media !== undefined) {
    link.media = media;
  }
  if (disabled) {
    link.disabled = true;
  }
  document.head.appendChild(link);
  if (loaded) {
    // Install a real CSSStyleSheet as an own property, shadowing the
    // prototype accessor -- the only way to reach it since the fixture
    // deliberately has no href to load.
    Object.defineProperty(link, "sheet", { value: new CSSStyleSheet(), configurable: true });
  }
  onTestFinished(() => {
    link.remove();
  });
  return link;
}

// The synthetic window "error" event the watchdog keys on: `target` for a
// resource load failure, `error` for an uncaught runtime error.
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

// Parse the SERVED index.html into a detached Document; nothing in it is
// fetched, since a DOMParser document has no browsing context.
function parseServedDocument(): Document {
  return new DOMParser().parseFromString(indexHtml, "text/html");
}

// index.html's REAL body, scripts removed, mounted into the live document.
// The focusable-inventory test has to enumerate the SERVED markup rather than
// a hand-built subset: a stray link, button, or tabindex is exactly what it
// exists to catch. Scripts are stripped so /app.js doesn't load in a unit test.
function mountServedBody(): void {
  const doc = parseServedDocument();
  for (const script of doc.querySelectorAll("script")) {
    script.remove();
  }
  document.body.innerHTML = doc.body.innerHTML;
}

// Everything the platform can put in the sequential focus order, enumerated by
// CAPABILITY rather than as a list of the elements index.html happens to
// declare today.
const FOCUSABLE_CANDIDATE_SELECTOR = [
  "a[href]",
  "button",
  "input",
  "select",
  "textarea",
  "[tabindex]",
  "[contenteditable]",
].join(",");

// Candidates focusable by SCRIPT but not by Tab, so a `contenteditable` or
// `tabindex` candidate is judged on its own value alone.
const TABBABLE_BY_DEFAULT = "a[href],button,input,select,textarea";

// Whether Tab can actually land on a candidate. Computed explicitly: no
// platform API reads sequential focus order or `inert` reachability directly,
// so the rules live here.
function isTabReachable(el: HTMLElement): boolean {
  // Script-focusable only; never in the tab order.
  if (el.getAttribute("tabindex") === "-1") {
    return false;
  }
  // contenteditable="false" is plain content again.
  if (el.getAttribute("contenteditable") === "false" && !el.matches(TABBABLE_BY_DEFAULT)) {
    return false;
  }
  // A disabled form control takes no focus.
  const disabled =
    (el instanceof HTMLButtonElement ||
      el instanceof HTMLInputElement ||
      el instanceof HTMLSelectElement ||
      el instanceof HTMLTextAreaElement) &&
    el.disabled;
  if (disabled) {
    return false;
  }
  // visibility inherits, so a computed value already accounts for a hidden
  // ancestor and for a descendant overriding it back to visible.
  const visibility = getComputedStyle(el).visibility;
  if (visibility === "hidden" || visibility === "collapse") {
    return false;
  }
  for (let node: HTMLElement | null = el; node !== null; node = node.parentElement) {
    // An inert subtree is unreachable by keyboard.
    if (node.hasAttribute("inert")) {
      return false;
    }
    if (node.hasAttribute("hidden")) {
      return false;
    }
    // <noscript> content is not rendered while scripting is enabled.
    if (node.localName === "noscript") {
      return false;
    }
    // display:none removes the whole subtree; a descendant cannot override it.
    if (getComputedStyle(node).display === "none") {
      return false;
    }
  }
  return true;
}

function tabReachableElements(): HTMLElement[] {
  return [...document.querySelectorAll<HTMLElement>(FOCUSABLE_CANDIDATE_SELECTOR)].filter(
    isTabReachable,
  );
}

// A stable, copy-independent name for a reachable element, so an inventory
// failure names the element that broke the invariant.
function describeReachable(el: HTMLElement): string {
  const self = el.id === "" ? el.localName : `${el.localName}#${el.id}`;
  const host = el.parentElement?.closest("[id]");
  return `${self} in ${host === null || host === undefined ? "<body>" : `#${host.id}`}`;
}

// Import app.ts and RUN its top-level bootstrap, once per call.
//
// The specifier's unique query is load-bearing. Browser Mode's dynamic import
// goes through the browser's own module map, keyed by URL and holding evaluated
// modules for the page's life: `vi.resetModules()` clears the runner's registry
// but can't evict that map, so a bare `import("./app.js")` returns a previous
// test's instance and every assertion about the boot silently observes zero
// calls. A distinct query is a distinct URL, so a fresh evaluation.
// `@vite-ignore` opts out of Vite's variable-dynamic-import rewrite, which
// otherwise resolves against a generated glob map no query matches.
//
// The `.ts` extension is load-bearing too: a statically-analyzable
// `import("./app.js")` is rewritten to the resolved `app.ts` id at transform
// time, but this specifier is built at runtime, so the URL the browser
// requests is what v8 coverage attributes to -- written as `.js`, every
// evaluation is attributed to a nonexistent file and app.ts reports 0%.
//
// Mocked dependencies are unaffected: they resolve through the mock registry
// whatever query the importer carries.
let bootCount = 0;
function importApp(): Promise<unknown> {
  return import(/* @vite-ignore */ `./app.ts?boot=${++bootCount}`);
}

describe("web-terminal-kiro bootstrap (app.ts)", () => {
  beforeEach(() => {
    document.body.replaceChildren();
  });

  it("mounts by SELECTOR and passes the preset as a function, not a call", async () => {
    const root = appendTerminalRoot();

    await importApp();

    expect(createTerminalMock).toHaveBeenCalledTimes(1);
    // A selector means createTerminal resolves #terminal inside its own
    // failure boundary, so a missing element is the library's to report; a
    // preset FUNCTION means the library calls it inside the same boundary, so
    // a throwing preset is too.
    expect(createTerminalMock).toHaveBeenCalledWith("#terminal", {
      features: expect.any(Function),
      persistScrollback: { kind: "scrollback-store" },
      theme: THEME,
    });
    // Passing the function must NOT call it here.
    expect(presetAgentTabbedMock).not.toHaveBeenCalled();
    // ...and calling it must reach the preset with this app's options -- what a
    // bare `expect.any(Function)` would not catch (an arrow dropping
    // attentionIcons would still be a function).
    const passed = createTerminalMock.mock.calls[0]?.[1] as { features: () => unknown };
    passed.features();
    expect(presetAgentTabbedMock).toHaveBeenCalledExactlyOnceWith({ attentionIcons: true });
    expect(root.hasAttribute("inert")).toBe(false);
    expect(root.children).toHaveLength(0);
  });

  it("persists each tab's scrollback through the library's own store", async () => {
    // iOS discards this page's process routinely and the server keeps every
    // session, so without a restored store a reload refills the whole
    // scrollback over the wire line by line, which looked like a crash.
    appendTerminalRoot();

    await importApp();

    expect(localScrollbackStorageMock).toHaveBeenCalledTimes(1);
    expect(localScrollbackStorageMock).toHaveBeenCalledWith();
  });

  it("passes the #loading element to createTerminal when it is present", async () => {
    appendTerminalRoot();
    const loading = document.createElement("div");
    loading.id = "loading";
    document.body.appendChild(loading);

    await importApp();

    expect(createTerminalMock).toHaveBeenCalledTimes(1);
    expect(createTerminalMock).toHaveBeenCalledWith("#terminal", {
      features: expect.any(Function),
      persistScrollback: { kind: "scrollback-store" },
      theme: THEME,
      loading,
    });
  });

  it("boots even with no #terminal in the document, leaving the failure to the library", async () => {
    // The app hands the selector over unconditionally: an unresolvable one is
    // a kernel-init failure the library renders. The app must not get in the way.
    await importApp();

    expect(createTerminalMock).toHaveBeenCalledTimes(1);
    expect(createTerminalMock).toHaveBeenCalledWith("#terminal", expect.anything());
    expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  });

  // The one startup condition this app still decides for itself: the inline
  // watchdog already reported a resource failure this module cannot see (a
  // dead /style.css still lets /app.js evaluate), so booting would hand its
  // live dialog to createTerminal as `loading` and the kernel would fade the
  // Reload button away on first frame.
  it("aborts boot when the watchdog already claimed the overlay, leaving its dialog intact", async () => {
    const overlay = appendPristineOverlay();
    overlay.setAttribute("data-bootstrap-fatal", "");
    const watchdogMessage = document.createElement("p");
    watchdogMessage.textContent = "Watchdog failure";
    overlay.replaceChildren(watchdogMessage);

    await expect(importApp()).rejects.toThrow(
      "bootstrap watchdog already reported a fatal resource failure",
    );

    expect(overlay.firstElementChild).toBe(watchdogMessage);
    expect(overlay.textContent).toBe("Watchdog failure");
    expect(createTerminalMock).not.toHaveBeenCalled();
  });

  it("leaves the kernel's own recovery surface alone and rethrows when createTerminal throws", async () => {
    const root = appendTerminalRoot();
    const loading = appendPristineOverlay({ fade: true });
    // app.ts has no try/catch around createTerminal; the throw propagates untouched.
    createTerminalMock.mockImplementationOnce(() => {
      throw new Error("kernel boom");
    });

    await expect(importApp()).rejects.toThrow("kernel boom");

    // Must not build a second dialog alongside the kernel's own.
    const overlay = document.getElementById("loading");
    expect(overlay).toBe(loading);
    expect(overlay?.hasAttribute("data-bootstrap-fatal")).toBe(false);
    expect(overlay?.getAttribute("role")).not.toBe("alertdialog");
    expect(overlay?.querySelector("button")).toBeNull();
    expect(root.hasAttribute("inert")).toBe(false);
  });

  it("rethrows without touching the DOM when createTerminal throws and #loading is absent", async () => {
    appendTerminalRoot();
    createTerminalMock.mockImplementationOnce(() => {
      throw new Error("kernel boom no overlay");
    });

    await expect(importApp()).rejects.toThrow("kernel boom no overlay");
    expect(createTerminalMock).toHaveBeenCalledTimes(1);
    expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  });

  it("builds the same alertdialog shape when the real index.html watchdog fires", () => {
    // Executes the real inline watchdog against index.html's pristine markup and
    // checks it against STARTUP_FAILURE_COPY, so the one copy this app hand-writes
    // cannot drift from the library's. Mirrors routes_test.go's CSP hash check.
    const watchdogSource = readWatchdogSource();

    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();

    // Dispatching on the attached <script> element, not window, means only the
    // watchdog's capture-phase listener sees it -- pins index.html's `, true` flag.
    // `reload` is passed in here (not spied on later) because the Reload button's
    // handler closes over the `window` of its evaluation; see windowWithObservableReload.
    const reload = vi.fn();
    evaluateWatchdog(watchdogSource, { reload });
    const scriptEl = document.createElement("script");
    document.body.appendChild(scriptEl);
    scriptEl.dispatchEvent(new Event("error"));

    expectFatalOverlayShape(overlay, root);
    const description = overlay.querySelector("#bootstrap-failure-message");
    expect(description?.textContent).toContain("Web Terminal for Kiro failed to load");
    // Names THIS cause specifically -- a prefix-only assertion can't tell the
    // program-load message from the runtime-error one.
    expect(description?.textContent).toContain(
      "failed to load its program (/app.js or a module it imports)",
    );
    overlay.querySelector("button")?.click();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  // GUARDS A DELIBERATE DECISION. index.html's watchdog does NOT trap Tab
  // (expectFatalOverlayShape pins that), which is only safe because the dialog's
  // Reload button is the only tab-reachable element in the page while it is
  // shown -- index.html declares no other focusable element, and the terminal's
  // hidden text input cannot exist in this state. Adding any focusable element
  // outside the dialog silently breaks that reasoning. If this test fails: either
  // restore the invariant or add a real focus trap; do not weaken the assertion.
  it("fatal dialog leaves Reload as the ONLY tab-reachable element in the document (no-Tab-trap invariant)", () => {
    // The SERVED body, not a hand-built subset: only the real file can catch
    // the markup edit this test exists for.
    mountServedBody();
    const overlay = document.getElementById("loading");
    const root = document.getElementById("terminal");
    evaluateWatchdog(readWatchdogSource());
    const scriptEl = document.createElement("script");
    document.body.appendChild(scriptEl);
    scriptEl.dispatchEvent(new Event("error"));

    // Precondition: the watchdog reached the fatal state against the served
    // markup and inerted #terminal, or the inventory below asserts over the
    // pristine pre-JS page where no Reload button exists.
    expect(overlay?.getAttribute("role")).toBe("alertdialog");
    expect(root?.hasAttribute("inert")).toBe(true);

    const reachable = tabReachableElements();
    expect(
      reachable.map(describeReachable),
      "a tab-reachable element outside the fatal dialog breaks index.html's no-Tab-trap decision",
    ).toEqual(["button in #loading"]);
    expect(reachable[0]).toBe(overlay?.querySelector("button"));
    // The one reachable element is the one that already holds focus.
    expect(reachable[0]).toBe(document.activeElement);

    // Bait to prove the enumerator can see elements outside the dialog.
    const stray = document.createElement("a");
    stray.href = "#stray";
    document.body.appendChild(stray);
    expect(tabReachableElements().map(describeReachable)).toEqual([
      "button in #loading",
      "a in <body>",
    ]);
    stray.remove();

    // ...and the filter must reject the same element inside inerted #terminal
    // or carrying tabindex="-1".
    const insideInert = document.createElement("button");
    root?.appendChild(insideInert);
    const notTabbable = document.createElement("a");
    notTabbable.href = "#not-tabbable";
    notTabbable.setAttribute("tabindex", "-1");
    document.body.appendChild(notTabbable);
    const filtered = tabReachableElements();
    expect(filtered).toHaveLength(1);
    expect(filtered[0]).toBe(reachable[0]);
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

    // Post-boot: #loading is removed and a later runtime error must not throw
    // inside the capture-phase listener or touch anything.
    const root = appendTerminalRoot({ booted: true });

    expect(() =>
      dispatchWindowError({ error: new Error("post-boot runtime error") }),
    ).not.toThrow();

    expect(document.getElementById("loading")).toBeNull();
    expect(document.querySelector('[role="alertdialog"]')).toBeNull();
    expect(root.hasAttribute("inert")).toBe(false);
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
    // /style.css carries .wt-root.wt-viewport's layout and the scroll container,
    // so a 404 leaves an unstyled, unusable terminal while /app.js still loads
    // and createTerminal still succeeds -- no throw reaches app.ts's catch.
    evaluateWatchdog(readWatchdogSource());

    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();

    const linkEl = document.createElement("link");
    linkEl.rel = "stylesheet";
    linkEl.href = "/style.css";
    dispatchWindowError({ target: linkEl });

    expectFatalOverlayShape(overlay, root);
    // Names /style.css rather than the generic "check your connection" hint,
    // since the failure is invisible in the UI (a 200 that never applied).
    expect(overlay.querySelector("#bootstrap-failure-message")?.textContent).toContain(
      "/style.css",
    );
  });

  it("watchdog surfaces a stylesheet that failed before the listener was registered", () => {
    // A classic inline script is blocked while a stylesheet is pending, so a
    // fast local 404 has its error task queued before this end-of-<body> script
    // registers its listener. Resource error events don't bubble or replay, so
    // only the post-registration sweep -- not the listener -- can raise this.
    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();
    appendHeadStylesheet();

    evaluateWatchdog(readWatchdogSource());

    expectFatalOverlayShape(overlay, root);
  });

  it("watchdog sweep fires on a failed stylesheet whose media query matches", () => {
    // The gate isn't just `!link.media`: a matching media query must still
    // report, or every explicit screen/width-scoped stylesheet failure stays
    // silent.
    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();
    appendHeadStylesheet({ media: "screen" });

    evaluateWatchdog(readWatchdogSource());

    expectFatalOverlayShape(overlay, root);
  });

  it("watchdog sweep ignores a failed stylesheet whose media query does not match", () => {
    // A non-matching-media (print) stylesheet has a null .sheet as its normal
    // state, gated by matchMedia(link.media).matches -- without it a print
    // stylesheet raises the fatal dialog over a healthy screen render.
    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();
    appendHeadStylesheet({ media: "print" });

    evaluateWatchdog(readWatchdogSource());

    expectPristineOverlayUntouched(overlay, root);
  });

  it("does not boot over the watchdog's fatal stylesheet dialog", async () => {
    // A failed /style.css does not prevent /app.js from evaluating, so app.ts
    // runs with the watchdog's dialog already on screen and #terminal inerted;
    // it must abort rather than pass the overlay to createTerminal as `loading`
    // (which would fade and remove the only Reload affordance on first frame).
    evaluateWatchdog(readWatchdogSource());

    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();

    const linkEl = document.createElement("link");
    linkEl.rel = "stylesheet";
    linkEl.href = "/style.css";
    dispatchWindowError({ target: linkEl });

    await expect(importApp()).rejects.toThrow(
      "bootstrap watchdog already reported a fatal resource failure",
    );

    expect(createTerminalMock).not.toHaveBeenCalled();
    // The watchdog's recovery UI survives app.ts's pass, inert included.
    expectFatalOverlayShape(overlay, root);
    expect(overlay.querySelector("#bootstrap-failure-message")?.textContent).toContain(
      "Web Terminal for Kiro failed to load",
    );
  });

  it("aborts boot from the fatal handoff marker independently of dialog ARIA", async () => {
    // Isolates the protocol from the real watchdog's ARIA: a pristine
    // role=status overlay carrying only data-bootstrap-fatal must still abort.
    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();
    overlay.setAttribute("data-bootstrap-fatal", "");

    await expect(importApp()).rejects.toThrow(
      "bootstrap watchdog already reported a fatal resource failure",
    );

    expect(createTerminalMock).not.toHaveBeenCalled();
    expectPristineOverlayUntouched(overlay, root);
  });

  it("watchdog stands down when a fatal dialog already owns the overlay", () => {
    // Watchdog idempotency: an earlier error already set data-bootstrap-fatal,
    // and a later error reaching this listener must not rebuild the dialog or
    // overwrite that first, specific message.
    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();
    overlay.setAttribute("data-bootstrap-fatal", "");

    evaluateWatchdog(readWatchdogSource());
    const scriptEl = document.createElement("script");
    document.body.appendChild(scriptEl);
    scriptEl.dispatchEvent(new Event("error"));

    expectPristineOverlayUntouched(overlay, root);
  });

  it("watchdog sweep ignores a stylesheet that loaded successfully", () => {
    // The only guard between a healthy boot and a fatal dialog on EVERY page
    // load: dropping `!link.sheet` converts a working terminal into "Terminal
    // failed to start" for every user. The fixture link has no href so nothing
    // is fetched and .sheet stays null; `loaded` installs a real CSSStyleSheet.
    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();
    appendHeadStylesheet({ loaded: true });

    evaluateWatchdog(readWatchdogSource());

    expectPristineOverlayUntouched(overlay, root);
  });

  it("watchdog sweep ignores a disabled stylesheet", () => {
    // A disabled stylesheet's null .sheet is normal, not a failure; the sweep
    // gates on !link.disabled, read through the IDL property.
    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();
    appendHeadStylesheet({ disabled: true });

    evaluateWatchdog(readWatchdogSource());

    expectPristineOverlayUntouched(overlay, root);
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

    expectFatalOverlayShape(overlay, root);
    expect(overlay.querySelector("#bootstrap-failure-message")?.textContent).toContain(
      "Web Terminal for Kiro failed to load",
    );
    // ...and the runtime-error arm of the ternary, not the program-load arm: the
    // shared prefix is identical, so only this substring separates them.
    expect(overlay.querySelector("#bootstrap-failure-message")?.textContent).toContain(
      "its program stopped with an error before the terminal appeared",
    );
  });

  it("watchdog fires on a runtime error whose thrown value is falsy", () => {
    evaluateWatchdog(readWatchdogSource());

    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();

    // `throw null` (or undefined/false/0/"") is legal and still a real
    // module-evaluation failure. index.html classifies by event SHAPE
    // (`"error" in e`) for exactly this case -- a truthiness test on e.error
    // would stand down here and leave no recovery dialog.
    dispatchWindowError({ target: window, error: null });

    expectFatalOverlayShape(overlay, root);
    expect(overlay.querySelector("#bootstrap-failure-message")?.textContent).toContain(
      "its program stopped with an error before the terminal appeared",
    );
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
    // The two declaration sites, asserted individually and bounded to their own
    // rule: a match COUNT cannot distinguish a declaration from the file's own
    // doc comment (which spells the same literal), so a single-site drift would
    // still clear a >= 2 bound. The [^}]* bound keeps each assertion inside the
    // named rule rather than matching the accent later in the stylesheet.
    const escapedAccent = ACCENT_HSL.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    // The pre-JS overlay, which cannot read the JS theme. It sets the LIBRARY's
    // overlay token now (page.css owns the overlay's appearance and derives the
    // bar and status text from it) rather than a local --accent, so this is the
    // one place the brand reaches the loading screen.
    expect(indexHtml).toMatch(
      new RegExp(`#loading\\s*\\{[^}]*--wt-loading-accent:\\s*${escapedAccent}\\s*;`),
    );
    // the no-JS fallback message:
    expect(indexHtml).toMatch(
      new RegExp(`\\.noscript-fallback\\s*\\{[^}]*color:\\s*${escapedAccent}\\s*;`),
    );
    // installed-PWA chrome: meta and manifest must agree, in hex form
    expect(indexHtml).toContain(`<meta name="theme-color" content="${ACCENT_HEX}">`);
    const manifest: unknown = JSON.parse(manifestJson);
    expect((manifest as { theme_color: string }).theme_color).toBe(ACCENT_HEX);
    // ...and the token name itself is the library's, not ours: the assertions
    // above only compare this app's four sites to each other, so a rename of
    // --wt-loading-accent in page.css would leave the first screen of every load
    // in the library's default blue with every one of them still green.
    expect(pageCss).toContain("var(--wt-loading-accent)");
  });

  it("keeps the served no-JS fallback wired to the class its critical CSS styles", () => {
    // The accent test above pins the .noscript-fallback CSS RULE; nothing pinned
    // the markup that opts into it. That class is what lifts the message over the
    // still-animating loading overlay (position: fixed, inset: 0, z-index: 300,
    // opaque background), so renaming it -- or dropping the <noscript> block --
    // leaves a JS-disabled visitor watching the infinite loading bar with no
    // explanation, while the surviving rule keeps the parity test green.
    const doc = parseServedDocument();
    const fallback = doc.querySelector("noscript .noscript-fallback");
    expect(fallback?.tagName).toBe("P");
    expect(fallback?.textContent?.replace(/\s+/g, " ").trim()).toBe(
      "Web Terminal for Kiro needs JavaScript to run the terminal. Enable JavaScript and reload.",
    );
  });

  it("index.html's pristine overlay satisfies the watchdog's stand-down guards", () => {
    // The watchdog's stand-down guards read index.html's REAL markup (no .fade
    // on the overlay, an empty #terminal) while appendPristineOverlay()
    // recreates that markup by hand. If the served overlay ever drifts from
    // the fixture, the watchdog silently never fires in production while every
    // test above still passes against its own fabricated overlay.
    const doc = parseServedDocument();
    const overlay = doc.getElementById("loading");
    expect(overlay?.getAttribute("role")).toBe("status");
    expect(overlay?.querySelector(".wt-loading-bar")).not.toBeNull();
    expect(overlay?.querySelector(".wt-loading-bar")?.getAttribute("aria-hidden")).toBe("true");
    // No status text of its own: web-terminal-ui's kernel owns that line now.
    expect(overlay?.querySelector(".wt-loading-text")).toBeNull();
    expect(overlay?.textContent?.trim()).toBe("");
    expect(overlay?.classList.contains("wt-loading")).toBe(true);
    expect(overlay?.classList.contains("fade")).toBe(false);
    // #terminal is empty until createTerminal builds into it.
    const terminalRoot = doc.getElementById("terminal");
    expect(terminalRoot).not.toBeNull();
    expect(terminalRoot?.firstElementChild).toBeNull();
  });

  it("keys its fade stand-down on the class the kernel actually adds", () => {
    // The watchdog recognizes the fade state by CLASS, and that name is read
    // from the library's own source here (not LOADING_OVERLAY_CLASSES, which
    // publishes only the classes this app writes, not the one the kernel
    // adds). If the kernel renames it, the stand-down silently stops firing
    // and a stray uncaught error converts an already-lowered overlay into a
    // dialog the kernel then removes.
    expect(kernelSource).toContain('classList.add("fade")');
    expect(readWatchdogSource()).toContain('classList.contains("fade")');
  });

  it("overrides only theme tokens the UI package publicly supports", () => {
    // The theme object is Readonly<Record<string, string>> on the library
    // side: the kernel copies every key onto .wt-root verbatim, so nothing
    // notices a token the library renamed or retired -- it silently becomes a
    // dead declaration and the terminal renders in the library's defaults.
    //
    // PUBLIC_THEME_TOKENS is the library's own inventory (its
    // css-contract.test.ts generates it from the stylesheets and guarantees
    // each listed token is both declared and read), so this only checks the
    // one half that's genuinely the consumer's: every token this app
    // overrides must be one the library supports.
    for (const token of Object.keys(THEME)) {
      expect(
        PUBLIC_THEME_TOKENS as readonly string[],
        `theme token ${token} is not in the UI package's PUBLIC_THEME_TOKENS, so overriding it is unsupported: it may be an internal token the library renames without a release note, or it may not exist`,
      ).toContain(token);
    }

    // The library's list is the assertion's whole strength, so an empty list
    // (bad publish, mocked module) must fail here rather than make the loop
    // above vacuous.
    expect(PUBLIC_THEME_TOKENS.length).toBeGreaterThan(0);

    // A value's var() reads are as much a dependency as its key, and the key
    // loop above can't see them: no theme value may read a token outside the
    // published contract, or a library rename can silently drop a themed
    // surface with nothing here naming the unpublished token.
    const nonPublicReferences = new Set<string>();
    for (const value of Object.values(THEME)) {
      for (const reference of value.matchAll(/var\(\s*(--[\w-]+)/g)) {
        const token = reference[1] as string;
        if (!(PUBLIC_THEME_TOKENS as readonly string[]).includes(token)) {
          nonPublicReferences.add(token);
        }
      }
    }
    expect(
      [...nonPublicReferences],
      "a theme value reads a custom property outside the UI package's PUBLIC_THEME_TOKENS: the library may rename or retire an internal token with no release note, silently dropping whatever this value themes, and neither tsc nor the key check above can see inside a CSS string",
    ).toEqual([]);
  });

  it("opts into the loading-overlay class names the UI package publishes", () => {
    // index.html's overlay is styled by the library now, and it opts in by
    // NAME in a static HTML file no compiler reads -- so a library rename
    // leaves the first screen of every load unstyled with every test above
    // still green. Asserted against LOADING_OVERLAY_CLASSES rather than a
    // regex over the stylesheets, since whether page.css styles those
    // selectors is the library's own assertion.
    mountServedBody();
    const overlay = document.getElementById("loading");
    expect(overlay).not.toBeNull();
    expect([...(overlay?.classList ?? [])]).toContain(LOADING_OVERLAY_CLASSES.overlay);
    // The markup contract is one `overlay` element with one `bar` child; the
    // .wt-loading-text status region is the KERNEL's own, created at runtime.
    expect(overlay?.querySelector(`.${LOADING_OVERLAY_CLASSES.bar}`)).not.toBeNull();
  });
});

describe("the attention icon variants app.ts opts into are actually served", () => {
  // app.ts passes attentionIcons: true, a promise to the UI library that three
  // variants of every icon link exist. The library can't check it: the files
  // live in this repo and the dot's colour comes from this app's theme. So the
  // consequence of breaking the promise is a blank tab icon.
  //
  // This half pins the dot's COLOUR; its sibling in app.node.test.ts pins that
  // every derived variant file is actually served (a directory listing, so it
  // can't run here).

  it("paints each variant's dot in this app's own themed colour", () => {
    // The SVG variants carry the colour as a literal since a static asset
    // can't read a CSS custom property -- a fourth spelling of the theme
    // alongside app.ts, index.html's critical CSS and manifest.json. #d6b529
    // and #67d283 are oklch(78% 0.15 95deg) and oklch(78% 0.15 150deg)
    // resolved to sRGB by the generator.
    const expected: Record<string, string> = {
      input: "#d6b529",
      done: "#67d283",
      alert: THEME["--status-failed"],
    };
    const svgOf: Record<string, string> = {
      input: faviconInputSvg,
      done: faviconDoneSvg,
      alert: faviconAlertSvg,
    };
    for (const [variant, colour] of Object.entries(expected)) {
      const svg = svgOf[variant] as string;
      expect(svg, variant).toContain(`fill="${colour}"`);
      // One dot, added on top of the base art rather than replacing it.
      expect(svg.match(/<circle /g), variant).toHaveLength(1);
      expect(svg, variant).toContain("<path");
    }
  });
});
