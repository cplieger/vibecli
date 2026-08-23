// The DOM half of this app's suite: it runs in the browser project, i.e. real
// headless Chromium, and it carries no per-file environment pragma because
// Browser Mode is a runner rather than an environment.
//
// Every static asset this file needs arrives as a `?raw` import, resolved by Vite
// at transform time, so the assertions read the SHIPPED bytes without a
// filesystem call. The four checks that genuinely need the filesystem — a
// recursive walk of two dependency src trees, a served-directory listing, a
// runtime-derived file list and PNG header bytes — live in app.node.test.ts.
import { beforeEach, describe, expect, it, onTestFinished, vi } from "vitest";
// The real constant from the real package -- NOT mocked below. The point is to
// compare the served HTML against what the library actually ships.
import { STARTUP_FAILURE_COPY } from "@cplieger/web-terminal-ui/startup-copy";
// Likewise real, from the same package's /style-contract subpath: the public
// theme-token list and the loading-overlay class names, published as DATA so the
// two name-addressed surfaces of that library (the open `theme` Record, and
// overlay classes hardcoded in static HTML) can be asserted instead of
// remembered. Imported from the subpath, not the package root, because the root
// is mocked below -- the same reason STARTUP_FAILURE_COPY comes from
// /startup-copy.
import {
  LOADING_OVERLAY_CLASSES,
  PUBLIC_THEME_TOKENS,
} from "@cplieger/web-terminal-ui/style-contract";
// The SERVED static assets, as text, next to static-src. Vite inlines each one at
// transform time, which is strictly stronger than the readFileSync these replaced:
// a renamed or deleted asset now fails to RESOLVE instead of throwing at runtime.
import indexHtml from "../static/index.html?raw";
import manifestJson from "../static/manifest.json?raw";
import faviconAlertSvg from "../static/favicon-alert.svg?raw";
import faviconDoneSvg from "../static/favicon-done.svg?raw";
import faviconInputSvg from "../static/favicon-input.svg?raw";
// Two files from the UI package that its `exports` map does not publish, read as
// source text for the two parity assertions below (the overlay accent token
// page.css must still read, and the class name the kernel adds on its first
// frame). Relative paths into node_modules because a non-exported subpath cannot
// be imported by package name.
import kernelSource from "./node_modules/@cplieger/web-terminal-ui/src/kernel/kernel.ts?raw";
import pageCss from "./node_modules/@cplieger/web-terminal-ui/css/page.css?raw";

// app.ts imports createTerminal from the UI package and presetAgentTabbed from
// its /presets subpath; mock both. presetAgentTabbed returns a sentinel the
// assertions match against, so we verify app.ts passes the agent preset through.
const { createTerminalMock, presetAgentTabbedMock, localScrollbackStorageMock } = vi.hoisted(
  () => ({
    createTerminalMock: vi.fn(),
    presetAgentTabbedMock: vi.fn(() => ["preset-features"]),
    // A sentinel, so the assertions verify the app hands the library's own
    // localStorage store through rather than inventing storage of its own.
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
// app's own --tab-active-bg, so overriding it would restate a library formula.
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
  // The standard HSL->RGB piecewise table, indexed by hue sector (hp clamped to
  // the last sector so h = 360 lands where hp = 6 would fall off the end).
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

// The fatal-overlay alertdialog contract of the inline pre-module bootstrap
// watchdog (static/index.html). It is the LAST hand-built fatal surface in this
// app: app.ts's own copy is gone (createTerminal owns every terminal startup
// failure now), but the watchdog reports "the JS bundle never ran", a rung below
// `import` by definition, so it cannot use the library and cannot be deleted.
function expectFatalOverlayShape(overlay: HTMLElement, root: HTMLElement): void {
  expect(overlay.getAttribute("role")).toBe("alertdialog");
  // aria-modal claims the rest of the page is inert; the watchdog makes that
  // claim true by inerting the terminal root, so assert the containment here
  // rather than per test -- the negative twin below pins the same attribute
  // staying absent, and the two must not drift.
  expect(root.hasAttribute("inert")).toBe(true);
  // The watchdog sets the handoff marker before app.ts can boot. app.ts consumes
  // this explicit token rather than depending on the dialog's ARIA or child shape.
  expect(overlay.hasAttribute("data-bootstrap-fatal")).toBe(true);
  expect(overlay.getAttribute("aria-modal")).toBe("true");
  // Named by a VISIBLE title via aria-labelledby, not an invisible aria-label:
  // one name for both audiences (APG), and it matches web-terminal-ui's
  // renderFatalStartup() so the inline watchdog's dialog and the library's
  // recovery surface -- the only two fatal-startup dialogs left -- read alike. The
  // stale aria-label must be GONE, not merely overridden -- leaving both would
  // let the two names drift apart silently.
  expect(overlay.hasAttribute("aria-label")).toBe(false);
  expect(overlay.getAttribute("aria-labelledby")).toBe("bootstrap-failure-title");
  const title = overlay.querySelector("#bootstrap-failure-title");
  expect(title?.tagName).toBe("H2");
  // Taken from the library's exported constant, not restated. This is the whole
  // reason STARTUP_FAILURE_COPY exists: the watchdog cannot import at runtime, so
  // its wording used to be agreed with the library by comment. Now the agreement
  // is checked, and a change on the library side fails here instead of shipping
  // two different words for one event.
  expect(title?.textContent).toBe(STARTUP_FAILURE_COPY.title);
  expect(overlay.getAttribute("aria-describedby")).toBe("bootstrap-failure-message");
  // The pristine loading bar is always replaced by the dialog content.
  expect(overlay.querySelector(".wt-loading-bar")).toBeNull();
  // ...and so is any status line the kernel had written: replaceChildren() drops
  // every child, so a "still working" reassurance cannot survive next to a
  // failure message that says the terminal is not coming.
  expect(overlay.querySelector(".wt-loading-text")).toBeNull();
  expect(overlay.querySelector(".wt-loading-live")).toBeNull();
  const reload = overlay.querySelector("button");
  expect(reload?.type).toBe("button");
  expect(reload?.textContent).toBe(STARTUP_FAILURE_COPY.reloadLabel);
  // Initial focus lands on the recovery CTA (the alertdialog pattern's
  // initial focus; Reload is the only actionable element left).
  expect(document.activeElement).toBe(reload);
  // ...and Tab is NOT trapped. This button is the only focusable node in the
  // document (index.html declares no anchor/button/input/select/textarea/tabindex,
  // and #terminal is inerted), so a trap had nothing to contain -- it only blocked
  // Tab-to-address-bar, which F6/Ctrl+L reach anyway, and the library's own fatal
  // panel ships without one. Asserted from BOTH the button and <body>: the trap this
  // replaces was document-scoped with nothing removing it, so a reintroduced one
  // would leak across this file (every test in a file shares one window) and swallow
  // Tab for every later test. Either dispatch coming back cancelled means the trap
  // is back.
  for (const target of [reload, document.body]) {
    const tab = new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true });
    expect(target?.dispatchEvent(tab)).toBe(true);
    expect(tab.defaultPrevented).toBe(false);
  }
  // Focus is unchanged by Tab: nothing refocuses the button behind the user's back.
  expect(document.activeElement).toBe(reload);
}

// The inverse of expectFatalOverlayShape: the watchdog stood down, so the
// pristine pre-JS overlay is untouched and #terminal was never inerted. Shared
// by every stand-down test so the negative contract cannot drift or be
// asserted only partially.
function expectPristineOverlayUntouched(overlay: HTMLElement, root: HTMLElement): void {
  expect(overlay.getAttribute("role")).toBe("status");
  expect(overlay.querySelector(".wt-loading-bar")).not.toBeNull();
  expect(overlay.querySelector("button")).toBeNull();
  expect(root.hasAttribute("inert")).toBe(false);
}

// Locate the real inline bootstrap watchdog in the served index.html: the only
// inline <script> that is neither the importmap nor the src-bearing module
// loader. Every watchdog test obtains the source through this single helper so
// discovery cannot drift per test.
function readWatchdogSource(): string {
  // The end-tag half is `<\/script\b[^>]*>`, not `<\/script\s*>`: an HTML parser
  // ends a script element at `</script foo>` and `</script\t\n bar>` too, so a
  // pattern that only tolerates whitespace before `>` reads past a real end tag
  // and swallows the rest of the document into match[2]. The `\b` keeps
  // `</scriptfoo>` out, which is not an end tag for this element.
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
// In a real browser `window.location` is [LegacyUnforgeable]: `reload` is a
// non-configurable, non-writable OWN property of the Location instance (there is
// no Location.prototype.reload to patch either), so neither vi.spyOn nor
// Object.defineProperty can reach it -- `Cannot redefine property: reload`. The
// DOM emulator this suite used to run under let the spy through; a browser does
// not. Shadowing the `window` IDENTIFIER for one evaluation keeps the assertion
// exactly as strong -- a real click on the real button runs the real handler, and
// the call is observed -- without pretending a platform object is patchable.
//
// Every other property is forwarded to the real window, with functions bound to
// it: a Web API method called with the proxy as its receiver is an illegal
// invocation, and the watchdog reads window.addEventListener and
// window.matchMedia through this same object.
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

// Evaluate the inline bootstrap watchdog, capturing the window listener(s) it
// registers and removing them when the calling test finishes: every test in this
// file shares one window, and a leaked capture-phase error listener would clobber
// a pristine #loading overlay in any later test that fires a window error event.
// Every watchdog test MUST evaluate the script through this helper, never via a
// bare new Function().
//
// `reload` is passed only by the test that clicks the dialog's Reload button; see
// windowWithObservableReload above for why that needs its own evaluation shape.
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

// index.html's pristine pre-JS #loading overlay (role=status, one aria-hidden
// .wt-loading-bar child): the exact state the watchdog keys its behavior on.
// fade: the kernel's first-frame fade-out has begun.
function appendPristineOverlay({ fade = false } = {}): HTMLElement {
  const overlay = document.createElement("div");
  overlay.id = "loading";
  overlay.className = "wt-loading";
  overlay.setAttribute("role", "status");
  overlay.setAttribute("aria-label", "Loading");
  if (fade) {
    overlay.classList.add("fade");
  }
  // The overlay's ONLY pre-JS child. It carries no status text of its own any
  // more: web-terminal-ui's kernel writes a progressive status line into this
  // region (silent for the first seconds, then rotating, superseded by the
  // server's reason), so the app no longer keeps a static sentence in step with
  // it. The class is wt-loading-bar, not bar, because css/page.css owns the
  // overlay's appearance now and must not claim a name as generic as `.bar` in a
  // host document.
  const bar = document.createElement("div");
  bar.className = "wt-loading-bar";
  bar.setAttribute("aria-hidden", "true");
  overlay.appendChild(bar);
  document.body.appendChild(overlay);
  return overlay;
}

// A <link rel="stylesheet"> in <head>: the fixture index.html's
// post-registration sweep reads. In <head> because that is where index.html
// declares it -- and beforeEach only clears <body>, so the link MUST be removed
// when the test finishes: every test in this file shares one document, so a
// leaked link is swept by every later watchdog test in this file. Never given an
// href, so the browser has nothing to fetch and .sheet stays null -- exactly the
// failed state the sweep keys on, reached without a network round trip.
// loaded: the stylesheet parsed (a defined .sheet, the healthy state a browser
// exposes); media/disabled: the sweep's two gates.
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
    // Install a real CSSStyleSheet as an OWN property, shadowing the prototype
    // accessor: the surface a browser exposes once it has parsed a stylesheet,
    // and the only way to reach it here, since the fixture deliberately has no
    // href to load.
    Object.defineProperty(link, "sheet", { value: new CSSStyleSheet(), configurable: true });
  }
  onTestFinished(() => {
    link.remove();
  });
  return link;
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

// Parse the SERVED index.html into a detached Document. A DOMParser document has
// no browsing context, so nothing in it is fetched: the markup is inspected as
// markup. (The <link rel="stylesheet"> used to be stripped here, because the DOM
// emulator this suite ran under really did fetch a parsed document's stylesheet
// hrefs; a browser does not, so the strip is gone with it.)
function parseServedDocument(): Document {
  return new DOMParser().parseFromString(indexHtml, "text/html");
}

// index.html's REAL body, scripts removed, mounted into the live document. The
// focusable-inventory test below has to enumerate the SERVED markup rather than
// a hand-built subset of it: a link, a button or a tabindex ADDED to that file
// is precisely what it exists to catch, and a fabricated fixture can never grow
// one. Scripts are stripped because the watchdog is evaluated deliberately
// through evaluateWatchdog() and /app.js must not load in a unit test.
function mountServedBody(): void {
  const doc = parseServedDocument();
  for (const script of doc.querySelectorAll("script")) {
    script.remove();
  }
  document.body.innerHTML = doc.body.innerHTML;
}

// Everything the platform can put in the sequential focus order, enumerated by
// CAPABILITY rather than as a list of the elements index.html happens to declare
// today -- a list would keep passing for exactly the markup edit the inventory
// test guards against.
const FOCUSABLE_CANDIDATE_SELECTOR = [
  "a[href]",
  "button",
  "input",
  "select",
  "textarea",
  "[tabindex]",
  "[contenteditable]",
].join(",");

// Candidates that are focusable by SCRIPT but not by Tab, so a `contenteditable`
// or `tabindex` candidate is judged on its own value rather than on the fact
// that it also happens to be a <button>.
const TABBABLE_BY_DEFAULT = "a[href],button,input,select,textarea";

// Whether Tab can actually land on a candidate. Computed explicitly here, and
// that is not an oversight: no platform API answers it. Chromium implements
// sequential focus navigation for real, but exposes no way to READ the resulting
// order, and `inert` reachability is likewise only observable by trying to focus
// into the tree. A static query cannot ask either question, so the reachability
// rules live here, in the test's own helper.
function isTabReachable(el: HTMLElement): boolean {
  // Script-focusable only; never in the tab order.
  if (el.getAttribute("tabindex") === "-1") {
    return false;
  }
  // contenteditable="false" is plain content again: it only matched the
  // [contenteditable] candidate selector above.
  if (el.getAttribute("contenteditable") === "false" && !el.matches(TABBABLE_BY_DEFAULT)) {
    return false;
  }
  // A disabled form control takes no focus. Read from the property, which is
  // what the platform reads, and which only these four elements carry.
  const disabled =
    (el instanceof HTMLButtonElement ||
      el instanceof HTMLInputElement ||
      el instanceof HTMLSelectElement ||
      el instanceof HTMLTextAreaElement) &&
    el.disabled;
  if (disabled) {
    return false;
  }
  // visibility inherits, so the element's own computed value already accounts
  // for a hidden ancestor -- and for a descendant that deliberately overrides
  // one back to visible, which IS focusable.
  const visibility = getComputedStyle(el).visibility;
  if (visibility === "hidden" || visibility === "collapse") {
    return false;
  }
  for (let node: HTMLElement | null = el; node !== null; node = node.parentElement) {
    // An inert subtree is unreachable by keyboard, which is exactly the claim
    // the watchdog's inert on #terminal makes good on.
    if (node.hasAttribute("inert")) {
      return false;
    }
    if (node.hasAttribute("hidden")) {
      return false;
    }
    // <noscript> content is not rendered while scripting is enabled, and this
    // dialog only exists on a page where it is.
    if (node.localName === "noscript") {
      return false;
    }
    // display:none removes the whole subtree from rendering (and from the tab
    // order); a descendant cannot override it back.
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

// A stable, copy-independent name for a reachable element, so a failure of the
// inventory test NAMES the element that broke the invariant instead of printing
// a length mismatch.
function describeReachable(el: HTMLElement): string {
  const self = el.id === "" ? el.localName : `${el.localName}#${el.id}`;
  const host = el.parentElement?.closest("[id]");
  return `${self} in ${host === null || host === undefined ? "<body>" : `#${host.id}`}`;
}

// Import app.ts and RUN its top-level bootstrap, once per call.
//
// The specifier carries a unique query, and that is load-bearing. Browser Mode
// executes a dynamic import through the browser's own module map, which is keyed
// by URL and holds evaluated modules for the life of the page: `vi.resetModules()`
// clears the runner's registry but cannot evict an entry from that map, so a bare
// `import("./app.js")` returns the instance a previous test already evaluated and
// every assertion about the boot silently observes zero calls. A distinct query is
// a distinct URL and therefore a fresh evaluation. `@vite-ignore` opts out of
// Vite's variable-dynamic-import rewrite, which otherwise resolves the specifier
// against a generated glob map that no query matches.
//
// The `.ts` extension is load-bearing too, and this is the one line here that
// looks like a typo and is not. A statically-analyzable `import("./app.js")` is
// rewritten to the resolved `app.ts` id at transform time, but this specifier is
// built at runtime, so the URL the browser requests is the one written here --
// and that URL is what v8 coverage reports. Written as `./app.js` every
// evaluation is attributed to a file that does not exist, all nine of them are
// discarded, and app.ts reports 0% while the suite stays green.
//
// The mocked dependencies are unaffected: they resolve through the mock registry
// whatever query the importer carries, which is what the call-count assertions
// below rely on.
let bootCount = 0;
function importApp(): Promise<unknown> {
  return import(/* @vite-ignore */ `./app.ts?boot=${++bootCount}`);
}

describe("web-terminal-kiro bootstrap (app.ts)", () => {
  beforeEach(() => {
    // Each test re-runs app.ts's top-level code through importApp(), whose unique
    // query is what makes the re-evaluation happen (see there). Mock call history
    // is cleared by the config's mockReset before each test (implementations given
    // to vi.fn persist through mockReset).
    document.body.replaceChildren();
  });

  it("mounts by SELECTOR and passes the preset as a function, not a call", async () => {
    const root = appendTerminalRoot();

    await importApp();

    expect(createTerminalMock).toHaveBeenCalledTimes(1);
    // Both halves of this assertion are the reason this app no longer carries a
    // fatal dialog of its own. A selector means createTerminal resolves the
    // element inside its failure boundary, so a missing #terminal is the
    // library's to report; a preset FUNCTION means the library calls it inside
    // the same boundary, so a preset that throws is too. Passing a resolved
    // element and an already-called preset put both failures out here, where the
    // app had to hand-build a recovery surface -- and the library never saw them.
    expect(createTerminalMock).toHaveBeenCalledWith("#terminal", {
      features: expect.any(Function),
      persistScrollback: { kind: "scrollback-store" },
      theme: THEME,
    });
    // Passing the function must NOT call it here.
    expect(presetAgentTabbedMock).not.toHaveBeenCalled();
    // ...and calling it must reach the preset with this app's options, which is
    // the half a bare `expect.any(Function)` would not catch: an arrow that
    // dropped attentionIcons would still be a function, and the tab icon would
    // silently never change.
    const passed = createTerminalMock.mock.calls[0]?.[1] as { features: () => unknown };
    passed.features();
    expect(presetAgentTabbedMock).toHaveBeenCalledExactlyOnceWith({ attentionIcons: true });
    // The root is untouched by this module: the mocked kernel builds nothing, and
    // the app adds no dialog, no inert, nothing.
    expect(root.hasAttribute("inert")).toBe(false);
    expect(root.children).toHaveLength(0);
  });

  it("persists each tab's scrollback through the library's own store", async () => {
    // The point of the option, and the reason it is set here rather than left off:
    // iOS discards this page's process routinely, the server keeps every session,
    // and without a restored store the reload asks for the whole scrollback back
    // over the wire — which is the line-by-line refill that made an ordinary tab
    // eviction look like a crash.
    //
    // It must be the LIBRARY's store, called with no arguments. A hand-rolled one
    // here would be a fourth copy of the same forty lines across the consumers,
    // and the part that gets omitted in a copy is the orphan sweep, whose absence
    // is invisible until the origin quota fills.
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
    // The app used to look the root up and throw its own error here, because the
    // old signature could not accept a null element. It now hands the selector
    // over unconditionally: an unresolvable one is a kernel-init failure that
    // lowers the overlay and renders the library's panel. The app's job is to
    // NOT get in the way of that.
    await importApp();

    expect(createTerminalMock).toHaveBeenCalledTimes(1);
    expect(createTerminalMock).toHaveBeenCalledWith("#terminal", expect.anything());
    expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  });

  // The one startup condition this app still decides for itself, and it is not a
  // terminal failure: the inline watchdog has already reported a resource failure
  // this module cannot see (a dead /style.css still lets /app.js evaluate), so
  // booting would hand its live dialog to createTerminal as `loading` and the
  // kernel would fade the Reload button away on first frame.
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
    // By the time the kernel-init path rethrows, the library has rendered its own
    // surface and lowered #loading. This app has no try/catch around
    // createTerminal at all now, so the throw propagates untouched.
    createTerminalMock.mockImplementationOnce(() => {
      throw new Error("kernel boom");
    });

    await expect(importApp()).rejects.toThrow("kernel boom");

    // The app must NOT build a second dialog. Two recovery surfaces at once (the
    // kernel's and the app's) is the regression this pins, and deleting the
    // app's builder is what makes it unreachable.
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
    // Execute the REAL inline bootstrap watchdog from static/index.html (the
    // pre-module, CSP-hashed script that catches /app.js load failures before
    // app.ts can run) against index.html's pristine pre-JS markup, and assert
    // it produces the shape expectFatalOverlayShape pins — including the title
    // and Reload label, which come from the library's exported
    // STARTUP_FAILURE_COPY rather than being restated here, so the one copy this
    // app still hand-writes cannot drift from the one the library renders.
    // Mirrors how routes_test.go independently re-extracts the same inline
    // scripts for the CSP hash check.
    const watchdogSource = readWatchdogSource();

    // Recreate index.html's static body: the terminal root plus the pristine
    // loading overlay (role=status, .wt-loading-bar child, no fade).
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
    //
    // `reload` is handed in here rather than spied on later because the Reload
    // button's handler closes over the `window` of its evaluation; see
    // windowWithObservableReload.
    const reload = vi.fn();
    evaluateWatchdog(watchdogSource, { reload });
    const scriptEl = document.createElement("script");
    document.body.appendChild(scriptEl);
    scriptEl.dispatchEvent(new Event("error"));

    expectFatalOverlayShape(overlay, root);
    const description = overlay.querySelector("#bootstrap-failure-message");
    expect(description?.textContent).toContain("Web Terminal for Kiro failed to load");
    // ...and it names THIS cause. Every branch shares the prefix above, so a
    // prefix-only assertion cannot tell the program-load message from the
    // runtime-error one: swapping the two arms of index.html's message ternary
    // keeps the whole suite green while a failed /app.js fetch stops telling the
    // user to check their connection.
    expect(description?.textContent).toContain(
      "failed to load its program (/app.js or a module it imports)",
    );
    // The watchdog's Reload button must actually reload -- the same contract
    // the library's own fatal-panel tests pin for its Reload button. A
    // dead click listener would leave a dead-end recovery CTA on the only
    // actionable element left.
    overlay.querySelector("button")?.click();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  // GUARDS A DELIBERATE DECISION -- read this before "fixing" a failure here.
  // index.html's watchdog does NOT trap Tab (expectFatalOverlayShape pins that,
  // from both the button and <body>), and that is the wanted behaviour. It is
  // only SAFE because of an invariant nothing else asserts: while the fatal
  // dialog is shown, the dialog's Reload button is the only thing in the page
  // Tab can land on, so Tab leaves for browser chrome rather than walking onto
  // page content behind a dialog that claims aria-modal="true". Today that holds
  // for two reasons that are easy to break by accident -- index.html declares no
  // other focusable element, and the terminal's hidden text input cannot exist
  // in this state (the watchdog stands down once createTerminal has built UI,
  // and its fatal marker aborts boot before createTerminal runs). Add a link, a
  // button or anything with a tabindex outside the dialog and the reasoning is
  // silently gone. If this test fails: either restore the invariant (put the
  // element inside the dialog, or make it unreachable -- inert, hidden,
  // tabindex="-1") or revisit containment and add a real focus trap. Do not
  // weaken the assertion.
  it("fatal dialog leaves Reload as the ONLY tab-reachable element in the document (no-Tab-trap invariant)", () => {
    // The SERVED body, not a hand-built subset: the markup edit this test exists
    // to catch can only appear in the real file.
    mountServedBody();
    const overlay = document.getElementById("loading");
    const root = document.getElementById("terminal");
    evaluateWatchdog(readWatchdogSource());
    const scriptEl = document.createElement("script");
    document.body.appendChild(scriptEl);
    scriptEl.dispatchEvent(new Event("error"));

    // Precondition: the watchdog really did reach the fatal state against the
    // served markup, and made its aria-modal claim good by inerting #terminal.
    // Without this the inventory below would be asserting over the pristine
    // pre-JS page, where no Reload button exists at all.
    expect(overlay?.getAttribute("role")).toBe("alertdialog");
    expect(root?.hasAttribute("inert")).toBe(true);

    const reachable = tabReachableElements();
    expect(
      reachable.map(describeReachable),
      "a tab-reachable element outside the fatal dialog breaks index.html's no-Tab-trap decision",
    ).toEqual(["button in #loading"]);
    expect(reachable[0]).toBe(overlay?.querySelector("button"));
    // The one reachable element is the one that already holds focus, so Tab has
    // nowhere else in the page to go.
    expect(reachable[0]).toBe(document.activeElement);

    // The enumerator must be able to SEE an element outside the dialog, or this
    // test would pass for the wrong reason forever -- the local lesson from the
    // KAS-prune guard tests: plant the bait the unguarded code would take.
    const stray = document.createElement("a");
    stray.href = "#stray";
    document.body.appendChild(stray);
    expect(tabReachableElements().map(describeReachable)).toEqual([
      "button in #loading",
      "a in <body>",
    ]);
    stray.remove();

    // ...and the reachability filter must be doing real work rather than
    // accepting every candidate: the same element inside the inerted #terminal,
    // or carrying tabindex="-1", is not tab-reachable and must not be reported.
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

    expectFatalOverlayShape(overlay, root);
    // The message must NAME this cause, not fall back to the generic "check your
    // connection": /style.css is the branch a user cannot see (the page just goes
    // black, nothing 404s in the UI) and it is routinely a 200 that never applied,
    // so a connection hint points the user -- and an operator reading a
    // screenshot -- at the wrong thing.
    expect(overlay.querySelector("#bootstrap-failure-message")?.textContent).toContain(
      "/style.css",
    );
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
    appendHeadStylesheet();

    evaluateWatchdog(readWatchdogSource());

    expectFatalOverlayShape(overlay, root);
  });

  it("watchdog sweep fires on a failed stylesheet whose media query matches", () => {
    // The other half of the media gate. The non-matching (print) case below
    // pins the stand-down, but nothing pinned that a MATCHING media query
    // still reports: narrowing the gate to `!link.media` alone keeps every
    // explicit screen/width-scoped stylesheet failure silent, which is the
    // unstyled, unusable terminal the watchdog exists to surface.
    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();
    appendHeadStylesheet({ media: "screen" });

    evaluateWatchdog(readWatchdogSource());

    expectFatalOverlayShape(overlay, root);
  });

  it("watchdog sweep ignores a failed stylesheet whose media query does not match", () => {
    // A non-matching-media stylesheet (print-only here) never applies to the
    // current rendering, so a null .sheet is its normal state and its failure
    // is not fatal: index.html's post-registration sweep gates the
    // re-dispatch on window.matchMedia(link.media).matches. Without that gate
    // a print stylesheet raises the fatal dialog over a perfectly healthy
    // screen render, and no test pins it.
    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();
    appendHeadStylesheet({ media: "print" });

    evaluateWatchdog(readWatchdogSource());

    expectPristineOverlayUntouched(overlay, root);
  });

  it("does not boot over the watchdog's fatal stylesheet dialog", async () => {
    // The second half of the stylesheet flow the "watchdog fires on a failed
    // <link rel=stylesheet> (/style.css)" test stops short of: a
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
    // The test above drives the REAL watchdog, which sets both the marker and
    // role=alertdialog, so it stays green if app.ts regresses to the old ARIA
    // predicate. This isolates the protocol: a pristine role=status overlay
    // carrying only data-bootstrap-fatal must still abort the boot.
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
    // Watchdog idempotency, not an app-owned dialog: app.ts no longer builds a
    // fatal surface or sets the marker, so the only producer is this same inline
    // watchdog. An EARLIER bootstrap error it already handled set
    // data-bootstrap-fatal, and a later error reaching this capture-phase
    // listener must NOT rebuild the dialog or overwrite that first, specific
    // message with the generic "failed to load" text. data-bootstrap-fatal is the
    // only ownership signal the watchdog reads, so the fixture is a pristine
    // overlay carrying just the marker: with that guard removed the watchdog
    // builds its dialog here.
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
    // The false-positive direction of the sweep, and the only guard between a
    // healthy boot and a fatal dialog on EVERY page load: index.html's own
    // <link rel="stylesheet" href="/style.css"> is present on every load, so
    // dropping the `!link.sheet` clause converts a working terminal into
    // "Terminal failed to start" for every user. The fixture link carries no
    // href, so nothing is fetched and .sheet stays null; appendHeadStylesheet's
    // `loaded` flag installs a real CSSStyleSheet instead -- the same surface a
    // browser exposes once the stylesheet parses.
    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();
    appendHeadStylesheet({ loaded: true });

    evaluateWatchdog(readWatchdogSource());

    expectPristineOverlayUntouched(overlay, root);
  });

  it("watchdog sweep ignores a disabled stylesheet", () => {
    // A disabled stylesheet is not applied, so a null .sheet is its normal
    // state rather than a load failure: index.html's sweep gates the
    // re-dispatch on !link.disabled. Set through the IDL property, which is the
    // one the sweep reads and the one a script toggles.
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

    // `throw null` (or undefined/false/0/"") is legal, and the window error event
    // still reports a real module-evaluation failure. index.html classifies by
    // event SHAPE (`"error" in e`) for exactly this case: a truthiness test on
    // e.error stands down here and leaves the user behind a pristine, infinitely
    // animating loading overlay with no recovery dialog. The helper defines the
    // property for any non-undefined argument, so `error: null` recreates that
    // shape and this test is red on the pre-fix classifier.
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
    // Why this test exists: the watchdog's stand-down guards read index.html's
    // REAL markup (no .fade on the overlay, an empty #terminal) while
    // appendPristineOverlay() re-creates that markup by hand. If the served
    // overlay ever drifts from the fixture -- a .fade already present, or
    // #terminal shipping a pre-JS child -- the watchdog silently never fires in
    // production while every watchdog test above still passes against its own
    // fabricated overlay, so pin the hand-built fixture to the served file here.
    // The role and .wt-loading-bar assertions below are NOT watchdog guards. The
    // watchdog's stand-down states are the four its own error listener checks --
    // no #loading at all, data-bootstrap-fatal, .fade, and a non-empty #terminal
    // -- and neither role nor the bar is among them: they pin the bar the
    // library's page.css animates, and the fixture's fidelity to the served
    // markup.
    // The guards below live entirely in the markup, read through the suite's
    // shared served-document policy.
    const doc = parseServedDocument();
    const overlay = doc.getElementById("loading");
    // The served overlay's shape the fixture must reproduce, read from the file
    // rather than from appendPristineOverlay()'s hand-built copy. Of the
    // assertions below only the absent .fade and the empty #terminal are
    // watchdog guards; role and the bar pin the fixture's fidelity to the
    // served markup.
    expect(overlay?.getAttribute("role")).toBe("status");
    expect(overlay?.querySelector(".wt-loading-bar")).not.toBeNull();
    expect(overlay?.querySelector(".wt-loading-bar")?.getAttribute("aria-hidden")).toBe("true");
    // The overlay ships with NO status text of its own: web-terminal-ui's kernel
    // owns that line now (progressive, rotating, superseded by the server's own
    // reason), so a static sentence here would be a second owner to keep in step.
    expect(overlay?.querySelector(".wt-loading-text")).toBeNull();
    expect(overlay?.textContent?.trim()).toBe("");
    // ...and it opts in to the library's overlay styling by CLASS, which is what
    // makes page.css the single definition of this screen across the fleet.
    expect(overlay?.classList.contains("wt-loading")).toBe(true);
    expect(overlay?.classList.contains("fade")).toBe(false);
    // ...and the booted-root guard's pre-JS precondition: #terminal is empty
    // until createTerminal builds into it.
    const terminalRoot = doc.getElementById("terminal");
    expect(terminalRoot).not.toBeNull();
    expect(terminalRoot?.firstElementChild).toBeNull();
  });

  it("keys its fade stand-down on the class the kernel actually adds", () => {
    // index.html's watchdog stands down while the overlay is fading out, and it
    // recognizes that state by CLASS. LOADING_OVERLAY_CLASSES publishes the two
    // classes this app WRITES (overlay/bar) but not the one the kernel ADDS, so the
    // name is read from the library's own source here. If the kernel renames it, the
    // stand-down silently stops firing and a stray uncaught error converts an
    // already-lowered overlay into a dialog the kernel then removes.
    expect(kernelSource).toContain('classList.add("fade")');
    expect(readWatchdogSource()).toContain('classList.contains("fade")');
  });

  it("overrides only theme tokens the UI package publicly supports", () => {
    // The theme object is Readonly<Record<string, string>> on the library side:
    // the kernel copies every key onto .wt-root verbatim, so nothing -- not tsc,
    // not the assertions above, which only pin what app.ts PASSES -- notices a
    // token the library renamed or retired. The override silently becomes a dead
    // declaration, the terminal renders in the library's neutral blue defaults,
    // and this file stays green.
    //
    // The check used to be a SCRAPE: read the library's css/MANIFEST out of
    // node_modules, concatenate the bundle, strip comments, regex the `--token:`
    // declarations, then confirm each override appeared as both a declaration and
    // a var() read. Every one of those steps is gone. The library publishes
    // PUBLIC_THEME_TOKENS now and guarantees on its own side that each listed
    // token is both declared and read by the shipped CSS (its
    // src/css-contract.test.ts generates the inventory from the stylesheets and
    // fails otherwise), so re-deriving that here would duplicate the library's
    // assertion against bytes this app has no business reading -- and would do it
    // with a weaker parser. Same mechanism as STARTUP_FAILURE_COPY: import the
    // contract, do not re-litigate it.
    //
    // What is left is the only half that is genuinely the CONSUMER's: every token
    // this app overrides must be a token the library supports.
    for (const token of Object.keys(THEME)) {
      expect(
        PUBLIC_THEME_TOKENS as readonly string[],
        `theme token ${token} is not in the UI package's PUBLIC_THEME_TOKENS, so overriding it is unsupported: it may be an internal token the library renames without a release note, or it may not exist`,
      ).toContain(token);
    }

    // The library's list is the assertion's whole strength, so a list that
    // arrived empty (a bad publish, a mocked module, a subpath that resolved to
    // something else) must fail here rather than make the loop above vacuous.
    expect(PUBLIC_THEME_TOKENS.length).toBeGreaterThan(0);

    // A value's var() reads are as much a dependency as its key, and the key
    // loop above cannot see them. One override used to reach THROUGH the public
    // surface here: --tab-active-border restated the library's own edge
    // derivation and read var(--text) with it, an INTERNAL token
    // PUBLIC_THEME_TOKENS deliberately does not cover (the library's doc comment
    // says a value reaching an internal name is the consumer's to assert on
    // separately). That override is gone -- the kernel derives the edge from this
    // app's own --tab-active-bg, byte-identically -- so the expectation is not a
    // LIST of tolerated internal names any more: NO theme value may read a token
    // outside the published contract. Strictly stronger than pinning the set to
    // ["--text"], and it is what stops this coupling class returning: a library
    // rename can no longer silently drop a themed surface, because nothing here
    // names an unpublished token. Spell a value as a literal, or compose it from
    // public tokens only.
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
    // index.html's overlay is styled by the library now (its ~70 duplicated lines
    // are gone), and it opts in by NAME, hardcoded in a static HTML file no
    // compiler reads -- so a library rename leaves the first screen of every load
    // unstyled with every test above still green.
    //
    // Asserted against the library's exported LOADING_OVERLAY_CLASSES rather than
    // against a regex over its stylesheets, for the same reason as the theme test
    // above: whether page.css actually styles those selectors is the library's own
    // assertion. Read in the opposite direction from that test, too -- here the
    // SERVED markup is what must agree with the library, so this reads
    // static/index.html rather than app.ts's theme object. The
    // "index.html's pristine overlay satisfies the watchdog's stand-down guards"
    // test pins the same element's ARIA half.
    // mountServedBody() rather than a fresh DOMParser call: it applies the
    // suite's shared policy for reading the served markup (scripts stripped,
    // because /app.js must not load in a unit test).
    mountServedBody();
    const overlay = document.getElementById("loading");
    expect(overlay).not.toBeNull();
    expect([...(overlay?.classList ?? [])]).toContain(LOADING_OVERLAY_CLASSES.overlay);
    // The markup contract is one `overlay` element with one `bar` child; the
    // .wt-loading-text status region is the KERNEL's own (it creates it inside the
    // overlay at runtime), so it is deliberately not asserted as app markup.
    expect(overlay?.querySelector(`.${LOADING_OVERLAY_CLASSES.bar}`)).not.toBeNull();
  });
});

describe("the attention icon variants app.ts opts into are actually served", () => {
  // app.ts passes attentionIcons: true, which is a PROMISE to the UI library that
  // three variants of every icon link exist. The library cannot check it: the
  // files live in this repo, the dot's colour comes from this app's theme, and the
  // library derives the URLs by a naming convention rather than reading a map. So
  // the consequence of breaking the promise is a BLANK tab icon, and this test is
  // the only thing standing between a renamed icon and that.
  //
  // This half pins the dot's COLOUR. Its sibling in app.node.test.ts pins that
  // every derived variant file is actually served, which is a directory listing
  // and therefore cannot run here.

  it("paints each variant's dot in this app's own themed colour", () => {
    // The SVG variants carry the colour as a literal, because a static asset
    // cannot read a CSS custom property. That makes them a fourth spelling of the
    // theme (alongside app.ts, index.html's critical CSS and manifest.json), so
    // this pins them to the tokens above the same way the brand-accent test pins
    // the accent. #d6b529 and #67d283 are oklch(78% 0.15 95deg) and
    // oklch(78% 0.15 150deg) resolved to sRGB by the generator.
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
