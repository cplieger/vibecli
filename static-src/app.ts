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
// (kiro-cli sets NO OSC 0/2 window title, so the engine's OSC rung is always empty
// here and the label is the first substantial line the user submitted). Until that
// first eligible line arrives -- 3+ characters, not a bare slash command -- the label
// falls to the engine's own inference and every new tab reads "workspace",
// "workspace 2", which is the state WithInputTitle exists to end. A generic shell
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

// The inline watchdog in static/index.html may have already claimed the #loading
// overlay as its fatal alertdialog -- most importantly for a failed
// <link rel="stylesheet">, which is fatal (no /style.css means an unstyled,
// unusable terminal) yet does NOT stop /app.js from evaluating, so control reaches
// here with the recovery dialog already on screen. Booting anyway would hand that
// dialog to createTerminal as `loading`; the UI kernel fades and REMOVES it on
// first frame, leaving an unstyled page with no Reload affordance.
// data-bootstrap-fatal is the watchdog-to-app handoff signal: an explicit protocol
// marker rather than the dialog's ARIA role, so changing the fatal surface's a11y
// shape cannot silently sever this handoff.
//
// This is the ONE startup condition this app still decides for itself, and it is
// not a failure of the terminal -- it is "someone else already reported a failure
// this module cannot see". Everything that IS a terminal startup failure now
// belongs to createTerminal: it resolves "#terminal" and calls presetAgentTabbed
// inside its own boundary, so a missing root element or a preset that throws
// lowers the overlay and renders the library's recovery panel. This app used to
// carry a hand-built copy of that panel for exactly those two cases, because the
// old signature took a resolved element and an already-called preset and both
// failures happened out here, before the library could see them.
const loading = document.getElementById("loading");
if (loading?.hasAttribute("data-bootstrap-fatal")) {
  throw new Error(
    "web-terminal-kiro: bootstrap watchdog already reported a fatal resource failure",
  );
}

createTerminal("#terminal", {
  // A FUNCTION, not a call: createTerminal invokes it inside its failure
  // boundary, so a preset that throws renders the library's recovery panel
  // instead of escaping to a page stuck on the loading spinner.
  features: presetAgentTabbed,
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
    // critical CSS (--wt-loading-accent, the token the library's overlay reads,
    // plus the .noscript-fallback colour), plus
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
