import { createTerminal, type CreateTerminalOptions } from "@cplieger/web-terminal-ui";
import { presetAgentTabbed } from "@cplieger/web-terminal-ui/presets";
import type { PublicThemeToken } from "@cplieger/web-terminal-ui/style-contract";

// The one brand accent, as bare hsl() components: the accent token and the two
// alpha-blended tab fills below all compose from this single literal, so a hue
// change cannot land on some of them only. Four sites cannot read this module and
// must change with it -- static/index.html's <meta name="theme-color"> and its
// #loading critical CSS (--wt-loading-accent, plus the .noscript-fallback
// colour), and static/manifest.json's theme_color, where this colour is spelled
// #c099ff -- or the installed-PWA chrome and the pre-JS overlay drift from the app
// accent. app.test.ts's brand-accent parity test fails if they do.
const ACCENT_HSL_COMPONENTS = "263.1683 100% 80%";

// A stylesheet failure does not stop app.js from evaluating. If the inline
// watchdog already converted #loading into a recovery dialog, do not let the
// UI kernel remove that dialog when its first frame renders.
const loading = document.getElementById("loading");
if (loading?.hasAttribute("data-bootstrap-fatal")) {
  throw new Error(
    "web-terminal-kiro: bootstrap watchdog already reported a fatal resource failure",
  );
}

const options: CreateTerminalOptions = {
  // Every session is an agent expected to report OSC 9;4, so show its activity
  // dot from tab creation. Pass the function so preset failures remain inside
  // createTerminal's recovery boundary.
  features: presetAgentTabbed,
  // web-terminal-kiro's purple theme (the consumer "settings"; the UI library ships
  // the neutral defaults). Reaches the ACTIVE tab (fill/edge/label, desktop strip
  // + mobile switcher row), the accent icons (the mobile "+", the toggled keyboard
  // button), the hover/press fill of the mobile switch and "+" buttons, and the
  // activity dots (--status-*, below). What --tab-hover-bg does NOT reach: either
  // tab HOVER state, desktop or mobile -- the library keeps its own neutral lift
  // there deliberately (a translucent accent wash over a filled chip reads as
  // "more transparent", not "lighter"), so a hovered inactive tab stays grey
  // however this token is set. The active tab's EDGE is themed without an
  // override of its own: the library derives --tab-active-border from
  // --tab-active-bg (mixed 25% toward its own text colour) and custom properties
  // resolve at USE time, so the brand fill set above is what that derivation
  // consumes. That fill is deliberately app-owned and deliberately NOT the
  // sibling web-terminal-server's edge, which takes the library's accent-derived
  // blue default -- so the derived edge carries THIS app's purple, not a shared
  // one. Do not re-add a --tab-active-border override restating the library's
  // formula: it read var(--text), an internal library token, for a
  // byte-identical result, and app.test.ts now fails any theme value reading a
  // token outside PUBLIC_THEME_TOKENS.
  theme: {
    "--accent": `hsl(${ACCENT_HSL_COMPONENTS})`,
    "--tab-hover-bg": `hsl(${ACCENT_HSL_COMPONENTS} / 16%)`,
    "--tab-active-bg": `hsl(${ACCENT_HSL_COMPONENTS} / 32%)`,
    "--tab-active-fg": "#fff",
    // Tab activity-dot vocabulary for the three states this app's server can
    // actually report, replacing the library defaults: violet = thinking, green
    // = done, yellow = action required. One family -- 78% lightness / 0.15
    // chroma, only the hue varying -- at the pastel accent's own level, so none
    // of THESE THREE is separated by lightness; the wave/ring/shape cues carry
    // that (the WCAG 1.4.1 note below).
    //
    // The library publishes FIVE --status-* tokens; --status-warning and
    // --status-failed (OSC 9;4 progress states 4 and 2) deliberately keep the
    // library defaults, because the pinned Go engine reports only
    // working/idle/input/done/exited (web-terminal-engine/v3 terminal/
    // session_manager.go), so this app can never paint those two dots. Do NOT
    // read the lightness sentence above as a general rule if that ever changes:
    // PUBLIC_THEME_TOKENS requires the three ANIMATED states
    // (working/warning/failed, which share one travelling wave and differ only
    // in hue) to keep a LIGHTNESS spread, and this violet working dot (OKLab L
    // 77.6%) already sits 8.5 L points from the library's default warning
    // yellow (#facc15, L 86.1%) where the library's own blue working dot sat
    // 14.2 apart. Retheme those two in-family before adopting an engine that
    // emits them.
    //
    // Working is pinned as an sRGB HEX while its two siblings stay in oklch,
    // because oklch(78% 0.15 300deg) -- the family formula at the violet hue --
    // is outside sRGB AND outside Display P3, so no display we ship to can render
    // it as declared: every one shows a gamut-mapped approximation of the
    // browser's choosing. #c6a0ff is that approximation made explicit (what
    // Chromium paints on sRGB, deltaEOK 0.0099 from the P3 rendering, well inside
    // a ~0.02 JND). Green (150deg) and yellow (95deg) are in gamut and keep the
    // formula.
    //
    // Hue alone never carries state (WCAG 1.4.1): working is a disc emitting a
    // soft-edged ripple WAVE that travels outward and dissolves, input a disc
    // inside a static hard-edged RING (differing by edge quality as well as
    // motion), done the bare ringless disc. Under prefers-reduced-motion the
    // library punches working's disc into a donut, so all three stay distinct by
    // shape with no motion at all.
    "--status-working": "#c6a0ff",
    "--status-done": "oklch(78% 0.15 150deg)",
    "--status-input": "oklch(78% 0.15 95deg)",
  } satisfies Partial<Record<PublicThemeToken, string>>,
};

// Assigned rather than spread: a spread-introduced key is not "fresh", so
// TypeScript's excess-property check never sees it -- `loading` would survive a
// rename or removal of the option in @cplieger/web-terminal-ui with no compile
// error, and app.test.ts asserts this app's own key name against a mocked
// createTerminal, so nothing else would catch it either. A property assignment on
// a CreateTerminalOptions-typed local IS checked, and the `if` keeps the key
// ABSENT rather than undefined (exactOptionalPropertyTypes).
if (loading) {
  options.loading = loading;
}

createTerminal("#terminal", options);
