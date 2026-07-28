// @vitest-environment happy-dom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeEach, describe, expect, it, onTestFinished, vi } from "vitest";
// The real constant from the real package -- NOT mocked below. The point is to
// compare the served HTML against what the library actually ships.
import { STARTUP_FAILURE_COPY } from "@cplieger/web-terminal-ui/startup-copy";

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
  "--status-working": "#c6a0ff",
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

// The single fixture-location policy for every file this suite reads. INIT_CWD is
// set by the npm/npx launcher to the real static-src directory, so fixtures are
// found even when the runner changes process.cwd() — Stryker's dry run executes
// inside its .stryker-tmp sandbox, where a cwd-relative read ENOENTs.
function fixtureRoot(): string {
  return process.env["INIT_CWD"] ?? process.cwd();
}

// Read one of the SERVED static assets next to static-src.
function readStaticAsset(name: string): string {
  return readFileSync(resolve(fixtureRoot(), `../static/${name}`), "utf8");
}

// The UI package's shipped stylesheets, assembled from its own css/MANIFEST --
// exactly the member list scripts/css-bundle.sh concatenates into the served
// /style.css -- with CSS comments stripped so a name that survives only in prose
// can never satisfy a parity assertion. Rooted at node_modules rather than
// ../static, which is why this is not a readStaticAsset() call.
function readUiCssBundle(): string {
  const readCss = (name: string): string =>
    readFileSync(
      resolve(fixtureRoot(), `node_modules/@cplieger/web-terminal-ui/css/${name}`),
      "utf8",
    );
  const members = readCss("MANIFEST")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
  expect(members.length).toBeGreaterThan(0);
  return members
    .map(readCss)
    .join("\n")
    .replace(/\/\*[\s\S]*?\*\//g, "");
}

function declaredCustomProperties(bundle: string): string[] {
  return [...bundle.matchAll(/^\s*(--[\w-]+)\s*:/gm)].map((match) => match[1] as string);
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
  // would leak across this suite (isolate is false) and swallow Tab for every later
  // test. Either dispatch coming back cancelled means the trap is back.
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
// when the test finishes: isolate is false, so a leaked link is swept by every
// later watchdog test in this file. Never given an href, so happy-dom cannot
// attempt a real fetch. loaded: the stylesheet parsed (a defined .sheet, the
// healthy state a browser exposes); media/disabled: the sweep's two gates.
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
    // happy-dom never loads a link it was given no resolvable href for, so set
    // .sheet directly -- the same surface a browser exposes once it parses.
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

describe("web-terminal-kiro bootstrap (app.ts)", () => {
  beforeEach(() => {
    // resetModules so each dynamic import re-runs app.ts top-level code. Mock
    // call history is cleared by the config's clearMocks/mockReset before each
    // test (implementations given to vi.fn persist through mockReset).
    vi.resetModules();
    document.body.replaceChildren();
  });

  it("mounts by SELECTOR and passes the preset as a function, not a call", async () => {
    const root = appendTerminalRoot();

    await import("./app.js");

    expect(createTerminalMock).toHaveBeenCalledTimes(1);
    // Both halves of this assertion are the reason this app no longer carries a
    // fatal dialog of its own. A selector means createTerminal resolves the
    // element inside its failure boundary, so a missing #terminal is the
    // library's to report; a preset FUNCTION means the library calls it inside
    // the same boundary, so a preset that throws is too. Passing a resolved
    // element and an already-called preset put both failures out here, where the
    // app had to hand-build a recovery surface -- and the library never saw them.
    expect(createTerminalMock).toHaveBeenCalledWith("#terminal", {
      features: presetAgentTabbedMock,
      theme: THEME,
    });
    // Passing the function must NOT call it here.
    expect(presetAgentTabbedMock).not.toHaveBeenCalled();
    // The root is untouched by this module: the mocked kernel builds nothing, and
    // the app adds no dialog, no inert, nothing.
    expect(root.hasAttribute("inert")).toBe(false);
    expect(root.children).toHaveLength(0);
  });

  it("passes the #loading element to createTerminal when it is present", async () => {
    appendTerminalRoot();
    const loading = document.createElement("div");
    loading.id = "loading";
    document.body.appendChild(loading);

    await import("./app.js");

    expect(createTerminalMock).toHaveBeenCalledTimes(1);
    expect(createTerminalMock).toHaveBeenCalledWith("#terminal", {
      features: presetAgentTabbedMock,
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
    await import("./app.js");

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

    await expect(import("./app.js")).rejects.toThrow(
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

    await expect(import("./app.js")).rejects.toThrow("kernel boom");

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

    await expect(import("./app.js")).rejects.toThrow("kernel boom no overlay");
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
    evaluateWatchdog(watchdogSource);
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

  it("watchdog does not clobber an overlay a fatal dialog already converted", () => {
    evaluateWatchdog(readWatchdogSource());

    appendTerminalRoot();
    // The marker-less converted overlay: this fixture deliberately omits
    // data-bootstrap-fatal, so it is NOT the full claimed-overlay
    // shape -- it isolates the older missing-.wt-loading-bar fallback
    // clause, complementing the marker-only stand-down test above.
    const overlay = document.createElement("div");
    overlay.id = "loading";
    overlay.setAttribute("role", "alertdialog");
    overlay.setAttribute("aria-modal", "true");
    const description = document.createElement("p");
    description.id = "bootstrap-failure-message";
    description.textContent = "Web Terminal for Kiro failed to start.";
    const reload = document.createElement("button");
    reload.type = "button";
    reload.textContent = "Reload page";
    overlay.replaceChildren(description, reload);
    document.body.appendChild(overlay);

    const scriptEl = document.createElement("script");
    dispatchWindowError({ target: scriptEl });

    // the existing dialog's specific message survives; the watchdog's generic
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

    await expect(import("./app.js")).rejects.toThrow(
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
    // message with the generic "failed to load" text. A pristine overlay carrying
    // only the marker isolates that clause from the replaced-.wt-loading-bar side
    // effect it supersedes:
    // with the marker guard removed the watchdog builds its dialog here.
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
    // "Terminal failed to start" for every user. happy-dom never loads a link
    // it was given no resolvable href for, so .sheet is defined directly --
    // the same surface a browser exposes once the stylesheet parses.
    const root = appendTerminalRoot();
    const overlay = appendPristineOverlay();
    appendHeadStylesheet({ loaded: true });

    evaluateWatchdog(readWatchdogSource());

    expectPristineOverlayUntouched(overlay, root);
  });

  it("watchdog sweep ignores a disabled stylesheet", () => {
    // A disabled stylesheet is not applied, so a null .sheet is its normal
    // state rather than a load failure: index.html's sweep gates the
    // re-dispatch on !link.disabled. happy-dom does not reflect the disabled
    // content attribute onto the IDL property, so set the property directly --
    // the same surface a browser exposes and scripts toggle.
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
    // The pre-JS overlay, which cannot read the JS theme. It sets the LIBRARY's
    // overlay token now (page.css owns the overlay's appearance and derives the
    // bar and status text from it) rather than a local --accent, so this is the
    // one place the brand reaches the loading screen.
    expect(html).toMatch(
      new RegExp(`#loading\\s*\\{[^}]*--wt-loading-accent:\\s*${escapedAccent}\\s*;`),
    );
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
    // REAL markup (a .wt-loading-bar child, no .fade) while appendPristineOverlay()
    // re-creates that markup by hand. If index.html's overlay ever loses the
    // .wt-loading-bar (or #terminal ships a pre-JS child), the watchdog silently
    // never fires in production while every watchdog test above still passes
    // against its own fabricated overlay -- so pin the hand-built fixture to
    // the served file here.
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

  it("themes only custom properties the shipped UI package declares and reads", () => {
    // The theme object is Readonly<Record<string, string>> on the library side:
    // the kernel copies every key onto .wt-root verbatim, so nothing -- not tsc,
    // not the assertions above, which only pin what app.ts PASSES -- notices a
    // token the library renamed or retired. The override silently becomes a dead
    // declaration, the terminal renders in the library's neutral blue defaults,
    // and this file stays green. Same mechanism as STARTUP_FAILURE_COPY: the
    // agreement is checked against the shipped package rather than remembered.
    const bundle = readUiCssBundle();
    const declared = declaredCustomProperties(bundle);

    // Every key app.ts sets, plus every token its VALUES reach through var():
    // --tab-active-border's color-mix reads --text, so a rename there breaks the
    // whole declaration and the active tab loses its edge.
    const named = new Set(Object.keys(THEME));
    for (const value of Object.values(THEME)) {
      for (const reference of value.matchAll(/var\(\s*(--[\w-]+)/g)) {
        named.add(reference[1] as string);
      }
    }
    expect([...named]).toContain("--text");

    for (const token of named) {
      expect(declared, `theme token ${token} is not declared by the UI package`).toContain(token);
      // Declared but unread is the same silent no-op: the kernel writes the
      // override onto .wt-root and no rule consumes it.
      expect(
        new RegExp(`var\\(\\s*${token}\\s*[,)]`).test(bundle),
        `theme token ${token} is declared but never read by the UI package`,
      ).toBe(true);
    }
  });

  it("opts into loading-overlay names the shipped UI package still styles", () => {
    // index.html's overlay is styled by the library now (its ~70 duplicated lines
    // are gone), and it opts in by NAME: the .wt-loading class, the
    // .wt-loading-bar child, the .wt-loading-text region the kernel writes the
    // progressive status line into, and the one --wt-loading-accent token that
    // carries the brand into the pre-JS screen. Those names are hardcoded in a
    // static HTML file no compiler reads, so a library rename leaves the first
    // screen of every load unstyled with every test above still green -- the test
    // at the end of this file pins index.html's half of the same contract.
    const bundle = readUiCssBundle();

    for (const selector of [".wt-loading", ".wt-loading-bar", ".wt-loading-text"]) {
      expect(
        new RegExp(`(^|[\\s,])\\${selector}(?![\\w-])[^{}]*\\{`, "m").test(bundle),
        `${selector} is not styled by the UI package`,
      ).toBe(true);
    }
    expect(declaredCustomProperties(bundle)).toContain("--wt-loading-accent");
    expect(
      /var\(\s*--wt-loading-accent\s*[,)]/.test(bundle),
      "--wt-loading-accent is declared but never read by the UI package",
    ).toBe(true);
  });
});
