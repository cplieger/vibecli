// web-terminal-kiro client entry point.
//
// All terminal behavior lives in the shared packages: the
// @cplieger/web-terminal-engine engine (render / scroll / connection / keyboard)
// and the @cplieger/web-terminal-ui reference UI (the modular kernel plus opt-in
// features). web-terminal-kiro is the thinnest possible consumer: createTerminal builds the
// whole terminal UI inside the #terminal root element with the agent-shell
// feature set (presetAgentTabbed: tabs + activity monitor + touch toolbar +
// context menu + clipboard + scroll-to-bottom + predictive echo + connection
// banner + animations). web-terminal-kiro is an agent shell, so it wants the activity
// monitor (per-tab working/done/needs-input dots); a generic terminal would use
// the plain presetTabbed, which is label-only. Each browser tab drives its own
// independent kiro-cli chat session
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

// Reveal the #loading overlay as a modal alert dialog with a fatal message.
// remove("fade") undoes any fade-out createTerminal began; on the missing-root
// path createTerminal never ran, so the remove is a harmless no-op.
// Mirrored by the inline bootstrap watchdog in static/index.html, which builds
// the same alertdialog shape for app.js load failures (before this module can
// run) and stands down once the pristine .bar child is gone -- keep the two in
// sync when changing this shape.
function showFatal(overlay: HTMLElement, message: string): void {
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
  overlay.replaceChildren(description, reload);
  // aria-modal claims everything outside the dialog is inert; make it true so
  // Tab cannot reach focusables inside a partially-built terminal behind the
  // opaque overlay (APG alertdialog focus containment; WCAG 2.4.11). On the
  // missing-root path there is no #terminal, so the lookup is a no-op.
  document.getElementById("terminal")?.setAttribute("inert", "");
  // Move focus to the recovery CTA: the page content is gone and Reload is the
  // only actionable element left (the alertdialog pattern's initial focus).
  reload.focus();
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
      "--accent": "hsl(263.1683 100% 80%)",
      "--tab-hover-bg": "hsl(263.1683 100% 80% / 16%)",
      "--tab-active-bg": "hsl(263.1683 100% 80% / 32%)",
      "--tab-active-border": "color-mix(in oklch, var(--tab-active-bg), var(--text) 25%)",
      "--tab-active-fg": "#fff",
      // Tab activity-dot vocabulary (replaces the library defaults; ui >= the
      // release that tokenized the dots -- older bundles ignore these and keep
      // the defaults): violet = thinking, green = done, yellow = action
      // required. One declared family -- 78% lightness / 0.15 chroma, only the
      // hue carries the state -- sitting at the pastel accent's own level
      // (#c099ff is ~oklch(76% 0.13 296deg)). The violet hue's sRGB ceiling at
      // 78% L is C~0.132, so browsers gamut-map the declared 0.15 down to the
      // max-chroma pastel violet (~#c4a3ff); that clamp is deliberate ("the
      // most saturated violet available at the family's lightness"). Green
      // (~#67d283) and yellow (~#d6b529) are in gamut and render as declared.
      // The single-lightness family deliberately drops the library defaults'
      // working<->done lightness spread (pale lime vs green); state separation
      // rides the ring/motion/shape cues, never lightness or hue alone.
      // Hue alone never carries state (pulse/ring/shape per WCAG 1.4.1):
      // working is a bare disc emitting a live ripple ping; input freezes
      // that ping as a static ring; done stays the plain disc. Ripple and
      // ring derive from their own token inside the library CSS.
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
