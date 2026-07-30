#!/bin/bash
# web-terminal-kiro entrypoint. Ensures the pinned kiro-cli version is installed
# (downloads on first boot or whenever the on-disk version drifts from
# the pin), then hands off to the Go web server. Matches vibekit's
# licensing pattern: we download kiro-cli at runtime rather than bake
# it into the image so we don't redistribute proprietary AWS Content.

set -u

TOOLS="/config/tools"
BIN="$TOOLS/bin/kiro-cli"

# Parse the version kiro-cli reports (last field of `--version`). Centralized
# so the three call sites (install verify, drift check, readiness marker)
# share one parse if kiro-cli ever reworks its --version output.
kiro_cli_version() {
  # --kill-after gives a TERM-resistant binary a hard second-stage deadline;
  # without it GNU timeout waits forever on a child that traps/ignores TERM.
  timeout --signal=TERM --kill-after=5s 10s "$1" --version 2>/dev/null | awk '{print $NF}'
}

# kiro-cli is pinned via Renovate against the public install manifest at
# https://desktop-release.q.us-east-1.amazonaws.com/index.json. Bumping
# the version literal triggers a reinstall on next container start (see
# the version-drift check below). Auto-update inside the binary is
# disabled so what runs always matches the version baked into the image
# tag. KIRO_CLI_SHA256 (x86_64) and KIRO_CLI_SHA256_ARM64 (aarch64) are
# the per-arch sha256 of the headless zip, BOTH enforced at install; the
# kiro-cli packageRule in cplieger/.github groups all three literals into
# one Renovate PR so neither arch's gate can land stale.
# COUPLING (re-verify on every bump): routes.go's status classifier matches
# kiro-cli's EXACT OSC 9 notification strings "Response complete" (turn end ->
# done dot) and "Permission required" (tool approval -> needs-input dot),
# verified against this version. A bump that reworded either string silently
# stops the per-tab status dots from latching (no error; only a Debug log in
# routes.go). The feature also depends on the chat.enableNotifications +
# chat.notificationMethod=osc9 settings set below and web-terminal-engine's
# WithKeepUnfocused() in routes.go -- keep all four in lockstep.
# renovate: datasource=custom.kiro-cli depName=kiro-cli
KIRO_CLI_VERSION="2.15.2"
KIRO_CLI_SHA256="eabce0df2f37f071fcc7ec3f6d1e35fb11b94ca98e62f57d97d561d505d0b999"
# The `# kiro-cli <version>` trailer is Renovate's version anchor for this
# arch's digest lookup — do not hand-edit or drop it.
# renovate: datasource=custom.kiro-cli-arm64 depName=kiro-cli-arm64
KIRO_CLI_SHA256_ARM64="4db660fa2217cb8671a6f47afc5a48ca66e70d66c55ab99a4bb95c48e2001260" # kiro-cli 2.15.2

mkdir -p "$TOOLS/bin" "$HOME/.local/bin" "$HOME/.ssh" "$HOME/.kiro" \
  || {
    printf 'level=error msg="failed to create config directories (is /config mounted and writable?)" component=entrypoint\n' >&2
    # Throttle the restart:unless-stopped crash loop: without a mounted,
    # writable /config every boot fails instantly, and an immediate exit
    # would hot-spin the container.
    sleep 10
    exit 1
  }

# mkdir -p succeeds when the directories already exist — even on a read-only
# bind mount — so it is NOT proof that /config is writable. Prove it with a
# create+remove probe and fail fast (the documented behavior for an
# unwritable persistent volume) instead of limping into an install that
# cannot update the readiness marker.
if ! probe=$(mktemp "$TOOLS/.write-probe.XXXXXX") || ! rm -f "$probe"; then
  printf 'level=error msg="/config/tools is not writable (read-only bind mount?)" component=entrypoint\n' >&2
  sleep 10
  exit 1
fi

# Readiness marker consumed by the Go server's /api/health (main.go reads
# KIRO_CLI_READY_MARKER; routes.go Stats it). Initialized BEFORE any fallible
# provisioning work and cleared here so a marker left by a previous boot can
# never survive a failed upgrade: it is re-published only after the final
# version check below.
KIRO_CLI_READY_MARKER="$TOOLS/.kiro-cli-ready"
export KIRO_CLI_READY_MARKER
if ! rm -f "$KIRO_CLI_READY_MARKER"; then
  printf 'level=error msg="failed to clear stale kiro-cli readiness marker" marker="%s" component=entrypoint\n' "$KIRO_CLI_READY_MARKER" >&2
  sleep 10
  exit 1
fi

install_kiro_cli() (
  printf 'level=info msg="installing kiro-cli" version=%s component=entrypoint\n' "$KIRO_CLI_VERSION" >&2
  printf 'level=info msg="kiro-cli is proprietary AWS Content; by installing you accept the AWS Customer Agreement" license=https://kiro.dev/license/ component=entrypoint\n' >&2

  # Direct download from the AWS-hosted zip per the docs:
  # https://kiro.dev/docs/cli/installation/ ("With a zip file" section).
  # We pin the version (not /latest/) so a given image tag is reproducible,
  # and verify the sha256 before running install.sh.
  local arch zip_url tmpdir='' zip install_log=''
  case "$(uname -m)" in
    x86_64) arch="x86_64-linux" ;;
    aarch64) arch="aarch64-linux" ;;
    *)
      printf 'level=error msg="unsupported architecture" arch="%s" component=entrypoint\n' "$(uname -m)" >&2
      return 1
      ;;
  esac
  zip_url="https://desktop-release.q.us-east-1.amazonaws.com/${KIRO_CLI_VERSION}/kirocli-${arch}.zip"

  tmpdir=$(mktemp -d) || return 1
  # Single cleanup owner for both temp resources: the function body runs in a
  # subshell (note the `(` after the function name), so this EXIT trap fires
  # once per invocation on every return path — no per-branch rm bookkeeping.
  trap 'rm -rf "$tmpdir"; [ -z "$install_log" ] || rm -f "$install_log"' EXIT
  zip="$tmpdir/kirocli.zip"

  if ! curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
    --connect-timeout 20 --max-time 300 --retry 3 --retry-delay 5 \
    "$zip_url" -o "$zip"; then
    printf 'level=error msg="failed to download kiro-cli zip" url="%s" component=entrypoint\n' "$zip_url" >&2
    return 1
  fi
  if [ ! -s "$zip" ]; then
    printf 'level=error msg="kiro-cli zip is empty (partial download?)" component=entrypoint\n' >&2
    return 1
  fi

  # Verify SHA-256 per arch: KIRO_CLI_SHA256 (x86_64) / KIRO_CLI_SHA256_ARM64
  # (aarch64), both from the install manifest and kept in lockstep with
  # KIRO_CLI_VERSION by Renovate (one grouped PR moves all three literals).
  local actual expected
  actual=$(sha256sum "$zip" | awk '{print $1}')
  printf 'level=info msg="kiro-cli zip downloaded" sha256=%s url="%s" component=entrypoint\n' "$actual" "$zip_url" >&2
  case "$arch" in
    x86_64-linux) expected="$KIRO_CLI_SHA256" ;;
    aarch64-linux) expected="$KIRO_CLI_SHA256_ARM64" ;;
  esac
  if [ "$actual" != "$expected" ]; then
    printf 'level=error msg="kiro-cli SHA-256 mismatch; refusing install (bump KIRO_CLI_VERSION and both KIRO_CLI_SHA256* literals together)" arch=%s expected=%s actual=%s component=entrypoint\n' \
      "$arch" "$expected" "$actual" >&2
    return 1
  fi
  printf 'level=info msg="kiro-cli SHA-256 verified against pinned hash" arch=%s component=entrypoint\n' "$arch" >&2

  if ! unzip -q "$zip" -d "$tmpdir"; then
    printf 'level=error msg="failed to extract kiro-cli zip" component=entrypoint\n' >&2
    return 1
  fi

  # Run upstream install.sh. Don't gate on its exit code — the kiro-cli
  # installer touches shell profiles and other side surfaces that
  # legitimately fail in our minimal root container; what matters is
  # whether the binary it drops at $HOME/.local/bin/kiro-cli reports
  # the version we pinned. Capture install.sh output to a tempfile so
  # we can surface it on failure.
  local install_rc
  install_log=$(mktemp) || return 1
  timeout --signal=TERM --kill-after=15s 120s "$tmpdir/kirocli/install.sh" --no-confirm </dev/null >"$install_log" 2>&1
  install_rc=$?
  # 124 = TERM deadline hit, 137 = the --kill-after SIGKILL fallback fired.
  # Log deadline exhaustion distinctly so Loki shows a wedged installer
  # rather than a generic install failure.
  if [ "$install_rc" -eq 124 ] || [ "$install_rc" -eq 137 ]; then
    printf 'level=warn msg="install.sh exceeded its 120s deadline and was terminated" rc=%d component=entrypoint\n' "$install_rc" >&2
  fi

  if [ ! -f "$HOME/.local/bin/kiro-cli" ]; then
    printf 'level=error msg="install.sh did not produce kiro-cli binary" path="%s/.local/bin/kiro-cli" rc=%d component=entrypoint\n' \
      "$HOME" "$install_rc" >&2
    printf 'install.sh output:\n' >&2
    cat "$install_log" >&2
    return 1
  fi
  local installed
  installed=$(kiro_cli_version "$HOME/.local/bin/kiro-cli")
  if [ "$installed" != "$KIRO_CLI_VERSION" ]; then
    printf 'level=error msg="installed kiro-cli reports wrong version" installed=%s wanted=%s rc=%d component=entrypoint\n' \
      "${installed:-unknown}" "$KIRO_CLI_VERSION" "$install_rc" >&2
    printf 'install.sh output:\n' >&2
    cat "$install_log" >&2
    return 1
  fi

  # Promote to the canonical /config/tools/bin/ location so PATH
  # ordering (which puts /config/tools/bin first) and any in-process
  # absolute-path references resolve to the freshly installed binary.
  mv -f "$HOME/.local/bin/kiro-cli" "$BIN" || {
    printf 'level=error msg="failed to promote kiro-cli binary to tools bin" src="%s/.local/bin/kiro-cli" dest="%s" component=entrypoint\n' "$HOME" "$BIN" >&2
    return 1
  }
  mv -f "$HOME/.local/bin/kiro-cli-chat" "$TOOLS/bin/kiro-cli-chat" 2>/dev/null || true
  mv -f "$HOME/.local/bin/kiro-cli-term" "$TOOLS/bin/kiro-cli-term" 2>/dev/null || true
)

# Reinstall when either the binary is missing or the on-disk version
# drifts from KIRO_CLI_VERSION. The binary lives on the persistent
# /config volume, so a freshly bumped image needs this drift check to
# actually pick up the new version on restart.
needs_kiro_cli_install() {
  if [ ! -x "$BIN" ]; then
    return 0
  fi
  local current
  current=$(kiro_cli_version "$BIN")
  if [ "$current" != "$KIRO_CLI_VERSION" ]; then
    printf 'level=info msg="kiro-cli version drift; reinstalling" installed=%s pinned=%s component=entrypoint\n' \
      "${current:-unknown}" "$KIRO_CLI_VERSION" >&2
    return 0
  fi
  return 1
}

if needs_kiro_cli_install; then
  if ! install_kiro_cli; then
    printf 'level=warn msg="kiro-cli install failed; web UI starts but the terminal errors until kiro-cli is present" component=entrypoint\n' >&2
  fi
fi

# Tell kiro-cli to skip telemetry by default. User can flip it via
# `kiro-cli settings telemetry.enabled true` inside the terminal.
# Disable in-binary auto-update: KIRO_CLI_VERSION above is the source
# of truth, kept current by Renovate against the public install
# manifest. Letting kiro-cli silently replace itself would invalidate
# the pinned SHA and break image-tag reproducibility.
# kiro_setting applies one kiro-cli settings call, logging a structured warn on
# failure (log-only breadcrumb; exit behavior unchanged — a settings failure
# must not block boot, but a silent one leaves e.g. auto-update enabled or the
# OSC 9 notification path off with no trail in Loki).
kiro_setting() {
  if ! timeout --signal=TERM --kill-after=5s 10s "$BIN" settings "$1" "$2" >/dev/null 2>&1; then
    printf 'level=warn msg="kiro-cli settings call failed; dependent feature may misbehave" setting=%s value=%s component=entrypoint\n' "$1" "$2" >&2
  fi
}
if [ -x "$BIN" ]; then
  kiro_setting telemetry.enabled false
  kiro_setting app.disableAutoupdates true
  # Enable kiro-cli's OSC 9 desktop-notification escape so web-terminal-kiro's tab
  # activity monitor can classify turn-end ("Response complete") and
  # tool-approval ("Permission required") into per-tab status dots. osc9 emits
  # the notification inline in the PTY stream (the only method that reaches a
  # browser terminal); the server holds each session "unfocused" so kiro-cli's
  # focus-gated notifier keeps firing even with no focused browser tab.
  kiro_setting chat.enableNotifications true
  kiro_setting chat.notificationMethod osc9
  # Explicitly disable kiro-cli's dynamic terminal title. Its OSC 0 title only
  # reflects the cwd for a live session (it reloads its session title just on a
  # session-id change, not per turn). The web-terminal-ui tabs feature PREFERS
  # the process OSC title over its own fallback, so leaving this on would make
  # every tab read "kiro: ~/workspace" instead of something useful. Set false
  # (not merely unset) so a container that previously persisted it true gets it
  # turned off on restart. With it off, the tabs feature titles each tab from
  # the user's last submitted line instead.
  kiro_setting chat.terminalTitle false
fi

# Publish the readiness marker (declared + cleared before provisioning above).
# kiro-cli is web-terminal-kiro's core
# dependency, yet the HTTP listener comes up even when the first-boot install
# failed (degraded-not-dead start, per the install WARNING above). Record here
# whether a runnable, correctly-versioned binary is present so the health signal
# reflects the core dependency. Verified ONCE at boot via --version (do NOT
# relaunch kiro-cli per health probe — spawning a heavy PTY process every probe
# would be an anti-pattern). This is a READINESS signal: under
# `restart: unless-stopped` nothing restarts on the resulting unhealthy state,
# so a broken kiro-cli shows as `unhealthy` in `docker ps` + the monitoring
# probe with no restart loop. If ever run under Swarm/k8s, wire /api/health to a
# readinessProbe, not a livenessProbe, to keep it loop-free.
if [ -x "$BIN" ] && [ "$(kiro_cli_version "$BIN")" = "$KIRO_CLI_VERSION" ]; then
  if ! touch "$KIRO_CLI_READY_MARKER"; then
    printf 'level=warn msg="failed to write kiro-cli readiness marker; /api/health will report kiro-cli unavailable" marker="%s" component=entrypoint\n' "$KIRO_CLI_READY_MARKER" >&2
  fi
fi

# OS packages (APT_PACKAGES env, e.g. "python3 gcc libc6-dev"). apt state
# lives in the ephemeral container layer — never on /config — so it is
# re-applied on every container start: compose-level intent, not volume
# intent. Everything else in /config/tools is owned by the server's
# toolbelt engine (manifest: /config/tools.json v2), which converges in
# the background after the listener binds; session creation waits on it
# so kiro-cli never scans PATH before the manifest's tools are present.
#
# Each token is validated against Debian package-name grammar so env
# content cannot smuggle apt options; `apt-get update` is REQUIRED here
# because the image deletes the package indexes at build time (a bare
# install would fail deterministically). Warn-not-fail preserves the
# degraded-boot posture.
if [ -n "${APT_PACKAGES:-}" ]; then
  apt_pkgs=()
  # Word-splitting of $APT_PACKAGES is intentional; glob expansion is not
  # (cwd is /workspace, so a stray "*" token would expand to repo filenames
  # and any name matching package grammar would be apt-installed). set -f
  # keeps such a token literal so the validator below warn-skips it.
  set -f
  for pkg in $APT_PACKAGES; do
    if [[ "$pkg" =~ ^[a-z0-9][a-z0-9+.-]*$ ]]; then
      apt_pkgs+=("$pkg")
    else
      printf 'level=warn msg="skipping invalid APT_PACKAGES token" token="%s" component=entrypoint\n' "$pkg" >&2
    fi
  done
  set +f
  if [ "${#apt_pkgs[@]}" -gt 0 ]; then
    printf 'level=info msg="installing OS packages" packages="%s" component=entrypoint\n' "${apt_pkgs[*]}" >&2
    timeout --signal=TERM --kill-after=30s 600s bash -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends -- "$@"' _ "${apt_pkgs[@]}"
    apt_rc=$?
    if [ "$apt_rc" -ne 0 ]; then
      # 124/137 = the 600s deadline (TERM, then the --kill-after SIGKILL
      # fallback); logged distinctly so Loki shows deadline exhaustion
      # rather than a generic apt failure.
      if [ "$apt_rc" -eq 124 ] || [ "$apt_rc" -eq 137 ]; then
        printf 'level=warn msg="APT_PACKAGES install exceeded its 600s deadline and was terminated; container continues without them" rc=%d component=entrypoint\n' "$apt_rc" >&2
      else
        printf 'level=warn msg="APT_PACKAGES install failed; container continues without them" rc=%d component=entrypoint\n' "$apt_rc" >&2
      fi
    fi
    rm -rf /var/lib/apt/lists/*
  fi
fi

# Hardcode dark theme. kiro-cli's "default" diff preset resolves
# added-line bg to #00FF00 through the truecolor path — unreadable.
# Pinning both baseTheme and diffPreset to "dark" avoids this.
theme_file="$HOME/.kiro/settings/kiro_cli_theme.json"
if ! mkdir -p "$(dirname "$theme_file")" \
  || ! printf '{"baseTheme":"dark","diffPreset":"dark"}\n' >"$theme_file"; then
  printf 'level=warn msg="failed to write kiro-cli theme file; diff colors may be unreadable" file="%s" component=entrypoint\n' "$theme_file" >&2
fi

exec /app/web-terminal-kiro
