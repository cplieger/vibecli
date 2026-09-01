import {
  createTerminal,
  localScrollbackStorage,
  type CreateTerminalOptions,
} from "@cplieger/web-terminal-ui";
import { presetAgentTabbed } from "@cplieger/web-terminal-ui/presets";
import type { PublicThemeToken } from "@cplieger/web-terminal-ui/style-contract";

// The one brand accent. static/index.html's <meta name="theme-color">, its
// #loading critical CSS, and static/manifest.json's theme_color (#c099ff) cannot
// read this module and must be kept in sync by hand; app.test.ts's brand-accent
// parity test fails if they drift.
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
  // Every session is an agent reporting OSC 9;4, so show its activity dot from
  // creation. attentionIcons additionally requires static/ to serve
  // favicon-{input,done,alert} in all three icon formats (app.test.ts asserts
  // this); regenerate them via .kiro/scripts/gen-attention-icons.py if a
  // --status-* token below changes.
  features: () => presetAgentTabbed({ attentionIcons: true }),
  // Restore each tab's scrollback from localStorage instead of pulling it back
  // over the wire (see web-terminal-ui.md "Scrollback persistence" for the
  // mechanism and the iOS jetsam rationale). README's "Stored scrollback"
  // section is the operator-facing statement of what this puts on the device.
  persistScrollback: localScrollbackStorage(),
  // web-terminal-kiro's purple theme; see web-terminal-ui.md's theme option docs
  // for what each token reaches and the OKLab/sRGB-gamut reasoning behind
  // --status-working being a literal hex while its siblings stay in oklch.
  theme: {
    "--accent": `hsl(${ACCENT_HSL_COMPONENTS})`,
    "--tab-hover-bg": `hsl(${ACCENT_HSL_COMPONENTS} / 16%)`,
    "--tab-active-bg": `hsl(${ACCENT_HSL_COMPONENTS} / 32%)`,
    "--tab-active-fg": "#fff",
    // violet = thinking, green = done, yellow = action required; --status-failed
    // keeps the library's red (deliberately NOT part of that family — the one
    // state that must read as a break, not a sibling).
    "--status-working": "#c6a0ff",
    "--status-done": "oklch(78% 0.15 150deg)",
    "--status-input": "oklch(78% 0.15 95deg)",
    "--status-failed": "#dc2626",
  } satisfies Partial<Record<PublicThemeToken, string>>,
};

// Assigned rather than spread into the options literal: a spread-introduced key
// is not "fresh" to TypeScript's excess-property check, so a typo or a removed
// option would compile silently. The `if` keeps the key ABSENT rather than
// undefined (exactOptionalPropertyTypes).
if (loading) {
  options.loading = loading;
}

createTerminal("#terminal", options);
