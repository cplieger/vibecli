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
// and differ only in two agent-shell tunings: preferInputTitle (kiro-cli emits a
// non-empty but useless OSC 0/2 title, so each tab's label follows the latest
// submitted line) and presumeReports (every session here IS an agent that will
// report OSC 9;4, so the activity dot shows from tab creation instead of popping
// in once the agent has booted far enough to first report). A generic shell
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
// however the overlay arrived. It is a no-op on both call sites today -- the UI
// kernel only ever adds .fade from ASYNCHRONOUS callbacks (dismissLoadingOverlay,
// reached via markReady from a screen frame / font settle / close handler, or from
// the setupFeatures continuation), so a synchronous createTerminal throw cannot have
// faded anything by the time this catch runs, and on the missing-root path
// createTerminal never ran at all.
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
  // aria-live is needed. aria-label replaces index.html's "Loading" name so
  // the accessible name doesn't contradict the failure it now shows; the
  // branch-specific message is the dialog's description.
  const description = document.createElement("p");
  description.id = "bootstrap-failure-message";
  description.textContent = message;
  overlay.setAttribute("role", "alertdialog");
  // Same handoff marker the index.html watchdog sets: 'a fatal bootstrap dialog owns
  // this overlay'. Set here too so the watchdog's stand-down is explicit rather than
  // resting on replaceChildren having dropped the .bar when the rethrow reaches its
  // capture-phase listener.
  overlay.setAttribute("data-bootstrap-fatal", "");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-label", "Web Terminal for Kiro startup failure");
  overlay.setAttribute("aria-describedby", description.id);
  // manifest.json declares display: standalone, so an installed PWA has no browser
  // chrome; "reload the page" needs an in-page affordance (Vercel: no dead ends).
  const reload = document.createElement("button");
  reload.type = "button";
  reload.textContent = "Reload";
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
      reload.focus({ focusVisible: true });
    },
    true,
  );
  overlay.replaceChildren(description, reload);
  // aria-modal claims everything outside the dialog is inert; make it true so
  // Tab cannot reach focusables inside a partially-built terminal behind the
  // opaque overlay (APG alertdialog focus containment; WCAG 2.4.11). On the
  // missing-root path there is no #terminal, so the lookup is a no-op.
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
try {
  createTerminal(root, {
    features: presetAgentTabbed(),
    // web-terminal-kiro's purple theme (the consumer "settings"; the UI library ships the
    // neutral defaults). Recolors hovered/active tabs, the accent icons (the
    // mobile "+", the toggled keyboard button), and the tab activity dots
    // (--status-*, below). Since web-terminal-ui v4 all tokens
    // live on .wt-root -- the element the theme is applied to -- so the library's
    // --tab-active-border derivation (the fill lightened + slightly desaturated)
    // already follows an overridden fill; the explicit re-declaration below is a
    // deliberate pin of that same formula, kept so the edge stays low-saturation
    // even if the library's derivation formula changes.
    theme: {
      // This accent literal is mirrored in three static assets that cannot read
      // this object: static/index.html's <meta name="theme-color"> (#c099ff is
      // this same colour) and its #loading critical CSS (--accent plus the
      // .noscript-fallback colour), and static/manifest.json's theme_color.
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
      // (#c099ff is ~oklch(76% 0.147 301deg)). The violet hue's sRGB ceiling at
      // 78% L is C~0.132, so browsers gamut-map the declared 0.15 down to the
      // max-chroma pastel violet (~#c4a3ff); that clamp is deliberate ("the
      // most saturated violet available at the family's lightness"). Green
      // (~#67d283) and yellow (~#d6b529) are in gamut and render as declared.
      // The single-lightness family deliberately drops the library defaults'
      // working<->done lightness spread (pale lime vs green); state separation
      // rides the ring/motion/shape cues, never lightness or hue alone.
      // Hue alone never carries state (pulse/ring/shape per WCAG 1.4.1):
      // working is a ringed disc emitting a live ripple ping off that ring;
      // input freezes that exact silhouette (ringed disc, no motion); done
      // is the bare ringless disc. Under prefers-reduced-motion the library
      // punches working's disc into a donut, so all three stay distinct by
      // shape with no motion at all. Ripple and ring derive from their own
      // token inside the library CSS.
      "--status-working": "oklch(78% 0.15 300deg)",
      "--status-done": "oklch(78% 0.15 150deg)",
      "--status-input": "oklch(78% 0.15 95deg)",
    },
    ...(loading ? { loading } : {}),
  });
} catch (e) {
  if (loading) {
    showFatal(loading, "Failed to start the terminal. Reload the page to retry.");
  }
  throw e;
}
