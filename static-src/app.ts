import { createTerminal } from "@cplieger/web-terminal-ui";
import { presetAgentTabbed } from "@cplieger/web-terminal-ui/presets";

// The one brand accent, as bare hsl() components: the accent token and the two
// alpha-blended tab fills in the theme below all compose from this single
// literal, so a hue change cannot land on some of them only. The copies in
// static/index.html and static/manifest.json (which cannot read this module) are
// pinned by app.test.ts's brand-accent parity test instead.
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

createTerminal("#terminal", {
  // Every session is an agent expected to report OSC 9;4, so show its activity
  // dot from tab creation. Pass the function so preset failures remain inside
  // createTerminal's recovery boundary.
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
