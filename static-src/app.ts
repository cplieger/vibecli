// web-terminal-kiro client entry point.
//
// All terminal behavior lives in the shared packages: the
// @cplieger/web-terminal-engine engine (render / scroll / connection / keyboard)
// and the @cplieger/web-terminal-ui reference UI (the modular kernel plus opt-in
// features). web-terminal-kiro is the thinnest possible consumer: createTerminal builds the
// whole terminal UI inside the #terminal root element with the agent-shell
// feature set (presetAgentTabbed: tabs + activity monitor + touch toolbar +
// context menu + clipboard + scroll-to-bottom + predictive echo + connection
// banner + animations). presetAgentTabbed and presetTabbed ship the SAME
// features -- the library's buildTabbed always includes the activity monitor --
// and differ only in presumeReports (every session here IS an agent that will
// report OSC 9;4, so the activity dot shows from tab creation instead of popping
// in once the agent has booted far enough to first report). Tab LABELS are not a
// preset concern at all: the engine resolves each session's name server-side, and
// this app's agent-shell tuning for that is routes.go's terminal.WithInputTitle()
// (kiro-cli emits a non-empty but useless OSC 0/2 title, so the label follows the
// latest submitted line). A generic shell
// would use presetTabbed, whose dot stays hidden until a session actually
// reports. Each browser tab drives its own independent kiro-cli chat session
// over the shared server; kiro-cli's TUI is rendered verbatim through the raw PTY
// stream.
//
// The session WebSocket ("/ws") and font (Monaspace) use createTerminal's
// defaults and are left implicit. The options passed are `features` (the agent
// preset), `theme` (web-terminal-kiro's purple tokens), and -- only when present --
// `loading`, the overlay element createTerminal fades out once the first frame
// renders.

import { createTerminal } from "@cplieger/web-terminal-ui";
import { presetAgentTabbed } from "@cplieger/web-terminal-ui/presets";

// The one brand accent, as bare hsl() components: the accent token and the two
// alpha-blended tab fills in the theme below all compose from this single
// literal, so a hue change cannot land on some of them only. The copies in
// static/index.html and static/manifest.json (which cannot read this module) are
// pinned by app.test.ts's brand-accent parity test instead.
const ACCENT_HSL_COMPONENTS = "263.1683 100% 80%";

// Reveal the #loading overlay as a modal alert dialog with a fatal message.
// remove("fade") is unconditional normalization, not a race fix: it guarantees the
// dialog is opaque and hit-testable (.fade sets opacity:0 + pointer-events:none)
// however the overlay arrived. It is a no-op on both call sites that fire today --
// but NOT because the kernel fades only from asynchronous callbacks: since
// web-terminal-ui 4.7.0 createTerminal's OWN synchronous catch calls
// fadeOutOverlay(opts.loading) before it rethrows (kernel.ts). It is a no-op
// because BOTH live call sites are pre-kernel and this app builds no dialog for
// any kernel failure: the missing-root path never calls createTerminal, and a
// preset failure throws before createTerminal is entered. So no path reaching
// here has had this overlay faded (and thus none has a transitionend listener or
// 1.5s removeOverlay timer armed against it), which is also why the retired
// detached-clone workaround is no longer needed.
// Mirrored by the inline bootstrap watchdog in static/index.html, which builds
// the same alertdialog shape for app.js load failures (before this module can
// run) -- keep the two in sync when changing this shape: the shared shape
// helper in app.test.ts pins every attribute of it, including the
// data-bootstrap-fatal marker both builders set. That marker is what stops the
// watchdog from overwriting the specific message set here with its generic
// "failed to load" text when the rethrown error reaches its capture-phase
// window listener; its other stand-down guards (absent overlay, the pristine
// .bar already replaced, a fade-out under way, #terminal already carrying built
// children) are not this function's responsibility.
function showFatal(overlay: HTMLElement, message: string): void {
  // Symmetric with the index.html watchdog's own first stand-down guard:
  // whichever fatal builder claimed this overlay first keeps it. Load-bearing
  // for the missing-#terminal-root branch below, which runs BEFORE app.ts's
  // data-bootstrap-fatal abort and would otherwise replaceChildren() over a
  // watchdog dialog already on screen -- discarding its Reload button while its
  // own document-scoped Tab trap stays live (the overlay it guards is still
  // connected, only its children were replaced), so every Tab would first
  // refocus that detached button as a no-op before this dialog's trap refocuses
  // the live one.
  if (overlay.hasAttribute("data-bootstrap-fatal")) {
    return;
  }
  overlay.classList.remove("fade");
  // alertdialog, not alert: the overlay carries an interactive Reload button
  // and moves focus into it, which is the alertdialog interaction model (APG).
  // The role plus the focus transition supplies the announcement, so no
  // aria-live is needed. The name comes from a VISIBLE title via
  // aria-labelledby, not an invisible aria-label: APG prefers one name serving
  // both audiences, and the sighted user previously got a bare message with no
  // heading saying what had happened. Title text and button copy match
  // web-terminal-ui's own renderFatalStartup() so the same event ("the terminal
  // did not start") reads identically whichever startup phase failed; the
  // branch-specific message stays this app's, since it is more precise than the
  // library's generic text.
  const title = document.createElement("h2");
  title.id = "bootstrap-failure-title";
  title.textContent = "Terminal failed to start";
  const description = document.createElement("p");
  description.id = "bootstrap-failure-message";
  description.textContent = message;
  overlay.setAttribute("role", "alertdialog");
  // Same handoff marker the index.html watchdog sets: 'a fatal bootstrap dialog owns
  // this overlay'. Set here too so the watchdog's stand-down is explicit rather than
  // resting on replaceChildren having dropped the .bar when the rethrow reaches its
  // capture-phase listener.
  // Stryker disable next-line StringLiteral: a marker attribute read only with
  // hasAttribute (here, in index.html's watchdog, and in app.test.ts), so its VALUE
  // is unobservable by construction; the empty string is the HTML convention for a
  // boolean attribute. Any assertion on it would test the mutant, not the contract.
  overlay.setAttribute("data-bootstrap-fatal", "");
  overlay.setAttribute("aria-modal", "true");
  overlay.removeAttribute("aria-label");
  overlay.setAttribute("aria-labelledby", title.id);
  overlay.setAttribute("aria-describedby", description.id);
  // manifest.json declares display: standalone, so an installed PWA has no browser
  // chrome; "reload the page" needs an in-page affordance (Vercel: no dead ends).
  const reload = document.createElement("button");
  reload.type = "button";
  reload.textContent = "Reload page";
  reload.addEventListener("click", () => {
    window.location.reload();
  });
  // Focus containment (APG alertdialog): inert-ing #terminal below keeps focus
  // OUT of the half-built terminal, but it does not make Tab/Shift+Tab cycle
  // WITHIN the dialog -- without this, Tab walks off Reload into the browser
  // chrome (or nothing at all in an installed standalone PWA, where this dialog
  // is the only recovery surface). Reload is the dialog's sole control, so both
  // directions wrap back onto it. Bound on the DOCUMENT (capture), not on the
  // overlay: a stray tap or click on this full-viewport dialog's own background
  // blurs to <body>, which is NOT a descendant of the overlay, so an
  // overlay-scoped listener stops containing Tab after the single most likely
  // stray interaction. isConnected keeps the trap from outliving the dialog
  // (the UI kernel removes the overlay it owns on first frame).
  // Mirrored by the index.html watchdog.
  document.addEventListener(
    "keydown",
    (event) => {
      if (event.key !== "Tab" || !overlay.isConnected) {
        return;
      }
      event.preventDefault();
      // Stryker disable next-line ObjectLiteral,BooleanLiteral: focusVisible is a UA
      // RENDERING hint (paint the focus ring for this script-initiated focus) with no
      // scriptable effect, and happy-dom models neither the option nor :focus-visible,
      // so no test in this environment can observe either mutant. Engines that ignore
      // the option are covered by index.html's plain :focus rule for this button.
      reload.focus({ focusVisible: true });
    },
    true,
  );
  overlay.replaceChildren(title, description, reload);
  // aria-modal claims everything outside the dialog is inert; make it true so
  // Tab cannot reach focusables inside a partially-built terminal behind the
  // opaque overlay (APG alertdialog focus containment; WCAG 2.4.11). On the
  // missing-root path there is no #terminal, so the lookup is a no-op.
  // Stryker disable next-line StringLiteral: inert is a boolean attribute -- presence
  // is the whole semantic, and both the tests and the browser read it that way -- so
  // the value is unobservable. Same class as data-bootstrap-fatal above.
  document.getElementById("terminal")?.setAttribute("inert", "");
  // Move focus to the recovery CTA: the page content is gone and Reload is the
  // only actionable element left (the alertdialog pattern's initial focus).
  // focusVisible asks the UA to paint the ring for this SCRIPT-initiated focus:
  // the family convention is :focus-visible only (web-terminal-ui
  // 10-primitives.css:47) and script focus does not match it after a pointer
  // load, so the dialog's only control would otherwise be focused with no
  // visible indicator. Engines that ignore the option (Samsung Internet,
  // Chrome < 145, Safari < 18.4) are covered by index.html's plain :focus rule
  // for this dialog's button, which is scoped to the fatal overlay so it never
  // leaks onto terminal chrome.
  // Stryker disable next-line ObjectLiteral,BooleanLiteral: focusVisible is a UA
  // RENDERING hint (paint the focus ring for this script-initiated focus) with no
  // scriptable effect, and happy-dom models neither the option nor :focus-visible,
  // so no test in this environment can observe either mutant. Engines that ignore
  // the option are covered by index.html's plain :focus rule for this button.
  reload.focus({ focusVisible: true });
}

const loading = document.getElementById("loading");
const root = document.getElementById("terminal");
if (!root) {
  // Surface the failure on the page, not just the console: createTerminal (which
  // fades the #loading overlay out on first frame) is never reached on this path,
  // so without this the user is left on a stuck loading screen with no explanation.
  if (loading) {
    showFatal(
      loading,
      "Web Terminal for Kiro failed to start. Reload the page; if this persists the app was built incorrectly.",
    );
  }
  throw new Error("web-terminal-kiro: missing #terminal root element");
}
// The inline watchdog in static/index.html may have already claimed the
// #loading overlay as its fatal alertdialog -- most importantly for a failed
// <link rel="stylesheet">, which is fatal (no /style.css means an unstyled,
// unusable terminal) yet does NOT stop /app.js from evaluating, so control
// reaches here with the recovery dialog already on screen and #terminal
// inerted. Booting anyway would hand that dialog to createTerminal as
// `loading`; the UI kernel fades and REMOVES it on first frame while nothing
// un-inerts #terminal, leaving an inert, unstyled page with no Reload
// affordance. data-bootstrap-fatal is the watchdog-to-app handoff signal: an
// explicit protocol marker rather than the dialog's ARIA role, so changing
// the fatal surface's a11y shape cannot silently sever this handoff.
if (loading?.hasAttribute("data-bootstrap-fatal")) {
  throw new Error(
    "web-terminal-kiro: bootstrap watchdog already reported a fatal resource failure",
  );
}
// presetAgentTabbed() runs BEFORE the kernel is entered, so a preset failure is
// the one startup failure this app still owns: no kernel ran, nothing captured
// #loading, and nothing will ever lower it, so the app must put the recovery
// surface on the page itself. Its own narrow try/catch is what keeps that
// ownership boundary explicit -- createTerminal is called OUTSIDE it, so every
// kernel failure stays the library's: since @cplieger/web-terminal-ui 4.7.0 the
// kernel lowers #loading and renders its own "Terminal failed to start" surface
// into #terminal before rethrowing, and a dialog built here for that phase would
// put TWO recovery surfaces on the page (the kernel's inside #terminal and this
// one in the #loading slot).
let features: ReturnType<typeof presetAgentTabbed>;
try {
  features = presetAgentTabbed();
} catch (e) {
  if (loading) {
    showFatal(loading, "Failed to start the terminal. Reload the page to retry.");
  }
  throw e;
}

createTerminal(root, {
  features,
  // web-terminal-kiro's purple theme (the consumer "settings"; the UI library ships the
  // neutral defaults). Recolors the ACTIVE tab (fill/edge/label, desktop strip
  // + mobile switcher row), the accent icons (the mobile "+", the toggled
  // keyboard button), the hover/press fill of the mobile switch and "+"
  // buttons, and the tab activity dots (--status-*, below). Note what
  // --tab-hover-bg does NOT reach: both tab HOVER states use the library's own
  // neutral lift, color-mix(in oklch, var(--tab-bg), var(--text) 15%)
  // (30-tabs.css .wt-tab:not(.wt-tab-active):hover desktop,
  // 31-switcher.css .wt-switcher-row-select:hover mobile rows),
  // deliberately -- a translucent accent wash over a filled chip reads as
  // "more transparent", not "lighter" -- so a hovered inactive tab stays grey
  // in this theme however this token is set. Since web-terminal-ui v4 all tokens
  // live on .wt-root -- the element the theme is applied to -- so the library's
  // --tab-active-border derivation (the fill lightened + slightly desaturated)
  // already follows an overridden fill; the explicit re-declaration below is a
  // deliberate pin of that same formula, kept so the edge stays low-saturation
  // even if the library's derivation formula changes.
  theme: {
    // This accent literal is mirrored in four declaration sites across the two
    // static assets that cannot read this object: static/index.html's
    // <meta name="theme-color"> (#c099ff is this same colour) and its #loading
    // critical CSS (--accent plus the .noscript-fallback colour), plus
    // static/manifest.json's theme_color. All four are pinned by app.test.ts's
    // brand-accent parity test.
    // index.html carries the matching note; change all of them together or the
    // installed-PWA chrome and the pre-JS overlay drift from the app accent.
    "--accent": `hsl(${ACCENT_HSL_COMPONENTS})`,
    "--tab-hover-bg": `hsl(${ACCENT_HSL_COMPONENTS} / 16%)`,
    "--tab-active-bg": `hsl(${ACCENT_HSL_COMPONENTS} / 32%)`,
    "--tab-active-border": "color-mix(in oklch, var(--tab-active-bg), var(--text) 25%)",
    "--tab-active-fg": "#fff",
    // Tab activity-dot vocabulary (replaces the library defaults; ui >= the
    // release that tokenized the dots -- older bundles ignore these and keep
    // the defaults): violet = thinking, green = done, yellow = action
    // required. One declared family -- 78% lightness / 0.15 chroma, only the
    // hue carries the state -- sitting at the pastel accent's own level
    // (#c099ff is ~oklch(76% 0.147 301deg)). The single-lightness family
    // deliberately drops the library defaults' working<->done lightness spread
    // (the defaults now separate working from done by hue, blue vs green);
    // state separation rides the wave/ring/shape cues, never lightness or hue
    // alone.
    //
    // Working is PINNED AS AN sRGB HEX while its two siblings stay in oklch,
    // because oklch(78% 0.15 300deg) -- the family formula at the violet hue --
    // is outside sRGB (linear blue 1.086) AND outside Display P3 (1.024), so
    // it can never render as declared on any display we ship to: every screen
    // shows a gamut-mapped approximation, and WHICH approximation is the
    // browser's choice rather than ours. #c6a0ff is that approximation made
    // explicit: it is exactly what Chromium paints for the formula on an sRGB
    // display, deltaEOK 0.0099 from what a P3 display shows for it (a JND is
    // ~0.02, so the pin is imperceptible on wide-gamut screens and a no-op on
    // sRGB ones). The mathematically nearest sRGB colour is #c79eff, better by
    // deltaEOK 0.0004, which is nothing. Green (150deg) and yellow (95deg) ARE
    // in gamut at 0.15 chroma and render as declared (#67d283 / #d6b529), so
    // they keep the formula.
    //
    // Hue alone never carries state (pulse/ring/shape per WCAG 1.4.1):
    // working is a disc emitting a live, soft-edged ripple WAVE that travels
    // outward and dissolves; input is a disc inside a static hard-edged ring
    // (so the two differ by edge quality as well as motion); done is the bare
    // ringless disc. Under prefers-reduced-motion the library punches
    // working's disc into a donut, so all three stay distinct by shape with
    // no motion at all. Wave and ring derive from their own token inside the
    // library CSS.
    "--status-working": "#c6a0ff",
    "--status-done": "oklch(78% 0.15 150deg)",
    "--status-input": "oklch(78% 0.15 95deg)",
  },
  ...(loading ? { loading } : {}),
});
