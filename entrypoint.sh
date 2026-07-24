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
  timeout --signal=TERM --kill-after=5s 10s "$1" --version 2>/dev/null | awk 'NR==1{print $NF; exit}'
}

# Fatal boot error: log it, then throttle the restart:unless-stopped crash loop
# (an immediate exit would hot-spin the container) before failing. $2 carries
# any extra structured fields, already formatted.
fatal() {
  printf 'level=error msg="%s" %scomponent=entrypoint\n' "$1" "${2:+$2 }" >&2
  sleep 10
  exit 1
}

# Tighten one /config-resident directory to the conventional 0700. mkdir -p
# creates new dirs umask-wide (root umask 022 -> 0755) and leaves an existing
# dir's mode alone; these dirs live on the /config host bind mount, where a
# wider mode lets other host users traverse them and read secret-adjacent
# material (~/.ssh keys and known_hosts, ~/.kiro/settings/mcp.json tokens,
# ~/.local install state, $HOME's .gitconfig/.netrc/credential stores). A
# symlink is refused rather than followed (its target may be outside the
# mount). The directory travels in a dir= field, matching how the rest of this
# file reports variable data (marker=, path=, token=).
harden_config_dir() {
  if [ -L "$1" ]; then
    printf 'level=warn msg="refusing to chmod symlinked config directory" dir="%s" component=entrypoint\n' "$1" >&2
  elif ! chmod 700 "$1"; then
    printf 'level=warn msg="failed to tighten config directory permissions" dir="%s" component=entrypoint\n' "$1" >&2
  fi
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
KIRO_CLI_VERSION="2.14.1"
KIRO_CLI_SHA256="2e35416019a8681586772dc5b0c32539d1712e1469280dbf8cd4bdedc751ea1a"
# The `# kiro-cli <version>` trailer is Renovate's version anchor for this
# arch's digest lookup — do not hand-edit or drop it.
# renovate: datasource=custom.kiro-cli-arm64 depName=kiro-cli-arm64
KIRO_CLI_SHA256_ARM64="37063826dd73d888bb068974e7f1d552cd44a0eaf47d2b9b06c31d48830ee104" # kiro-cli 2.14.1

mkdir -p "$TOOLS/bin" "$HOME/.local/bin" "$HOME/.ssh" "$HOME/.kiro" \
  || fatal 'failed to create config directories (is /config mounted and writable?)'

# Tighten the /config-resident dirs created above (see harden_config_dir for
# why, and for the symlink guard).
harden_config_dir "$HOME/.ssh"
harden_config_dir "$HOME/.kiro"
harden_config_dir "$HOME/.local"
harden_config_dir "$HOME"

# mkdir -p succeeds when the directories already exist — even on a read-only
# bind mount — so it is NOT proof that /config is writable. Prove it with a
# create+remove probe and fail fast (the documented behavior for an
# unwritable persistent volume) instead of limping into an install that
# cannot update the readiness marker.
if ! probe=$(mktemp "$TOOLS/.write-probe.XXXXXX") || ! rm -f "$probe"; then
  fatal '/config/tools is not writable (read-only bind mount?)'
fi

# Readiness marker consumed by the Go server's /api/health (main.go reads
# KIRO_CLI_READY_MARKER; routes.go Stats it). Initialized BEFORE any fallible
# provisioning work and cleared here so a marker left by a previous boot can
# never survive a failed upgrade: it is re-published only after the final
# version check below.
KIRO_CLI_READY_MARKER="$TOOLS/.kiro-cli-ready"
export KIRO_CLI_READY_MARKER
if ! rm -f "$KIRO_CLI_READY_MARKER"; then
  fatal 'failed to clear stale kiro-cli readiness marker' "marker=\"$KIRO_CLI_READY_MARKER\""
fi

# Sweep staged-but-unpromoted kiro-cli binaries out of $HOME/.local/bin. Called
# from install_kiro_cli's failure EXIT path; a sweep failure is not fatal there
# (the install already failed and the caller warns) but MUST be visible: the
# staging dir is on PATH and on the persistent /config volume, so a surviving
# staged binary stays reachable by bare-name resolution (the README's
# `docker exec ... kiro-cli`) at a version the pin does not control -- the same
# residue the pre-reinstall quarantine below treats as fatal.
# shellcheck disable=SC2317,SC2329  # invoked indirectly via trap
sweep_staged_kiro_cli() {
  rm -f "$HOME/.local/bin/kiro-cli" "$HOME/.local/bin/kiro-cli-chat" "$HOME/.local/bin/kiro-cli-term" && return 0
  printf 'level=warn msg="failed to sweep staged kiro-cli binaries after a failed install; an unpinned binary may remain reachable via bare-name PATH resolution" dir="%s/.local/bin" component=entrypoint\n' "$HOME" >&2
}

install_kiro_cli() (
  printf 'level=info msg="installing kiro-cli" version=%s component=entrypoint\n' "$KIRO_CLI_VERSION" >&2
  printf 'level=info msg="kiro-cli is proprietary AWS Content; by installing you accept the AWS Customer Agreement" license=https://kiro.dev/license/ component=entrypoint\n' >&2

  # Direct download from the AWS-hosted zip per the docs:
  # https://kiro.dev/docs/cli/installation/ ("With a zip file" section).
  # We pin the version (not /latest/) so a given image tag is reproducible,
  # and verify the sha256 before running install.sh.
  local arch zip_url tmpdir='' zip install_log='' rc=0
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
  # On a failure exit, also sweep any staged-but-unpromoted binaries out of
  # $HOME/.local/bin: staging lives on the persistent /config volume AND on
  # the image PATH, so leaving it would recreate -- via bare-name resolution,
  # e.g. the README's `docker exec ... kiro-cli mcp add` -- the unpinned-binary
  # exposure the pre-reinstall quarantine below exists to close. A success
  # exit (rc=0) skips the sweep; promotion already consumed the staged files.
  trap 'rc=$?; rm -rf "$tmpdir"; [ -z "$install_log" ] || rm -f "$install_log"; [ "$rc" -eq 0 ] || sweep_staged_kiro_cli' EXIT
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
  printf 'level=info msg="kiro-cli installed and promoted" version=%s path="%s" component=entrypoint\n' "$KIRO_CLI_VERSION" "$BIN" >&2
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
  # Quarantine the stale dispatcher and its sidecars out of BOTH $TOOLS/bin
  # and the $HOME/.local/bin staging directory BEFORE the reinstall.
  # install_kiro_cli stages the replacement in $HOME/.local/bin and only
  # promotes it on success, so without this a failed reinstall after
  # version drift would leave the old, no-longer-pinned binary executable on
  # PATH: /api/health would report unavailable (marker withheld) yet new
  # sessions would still launch the stale CLI, contradicting the pin
  # guarantee. Staging is swept here too: install_kiro_cli's failure EXIT
  # trap is registered only after arch detection and mktemp -d succeed, so
  # residue staged by an earlier boot would survive those early returns and
  # stay reachable via bare-name PATH resolution after the canonical binary
  # was removed. With the quarantine an install failure leaves every binary
  # absent, so new sessions hit the explicit install-failed guard instead.
  # Inability to quarantine is fatal: we cannot guarantee the pin controls
  # what runs. rm -f is a no-op on the first-boot (nothing present) path.
  if [ -e "$BIN" ] || [ -e "$HOME/.local/bin/kiro-cli" ]; then
    printf 'level=info msg="quarantining stale kiro-cli binaries (canonical and staging) before reinstall" path="%s" component=entrypoint\n' "$BIN" >&2
  fi
  if ! rm -f \
    "$BIN" "$TOOLS/bin/kiro-cli-chat" "$TOOLS/bin/kiro-cli-term" \
    "$HOME/.local/bin/kiro-cli" "$HOME/.local/bin/kiro-cli-chat" "$HOME/.local/bin/kiro-cli-term"; then
    fatal 'failed to remove stale kiro-cli binaries before reinstall; refusing to leave an unpinned binary on PATH' "path=\"$BIN\""
  fi
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
  local setting_rc
  timeout --signal=TERM --kill-after=5s 10s "$BIN" settings "$1" "$2" >/dev/null 2>&1
  setting_rc=$?
  if [ "$setting_rc" -ne 0 ]; then
    # 124/137 = the 10s deadline (TERM, then the --kill-after SIGKILL fallback),
    # logged with rc so Loki distinguishes a wedged binary from a settings error.
    printf 'level=warn msg="kiro-cli settings call failed; dependent feature may misbehave" setting=%s value=%s rc=%d component=entrypoint\n' "$1" "$2" "$setting_rc" >&2
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
# Resolve the on-disk version ONCE: a second probe here would add another 10s
# to the foreground boot allowance the Dockerfile HEALTHCHECK comment sums.
kiro_cli_installed=""
if [ -x "$BIN" ]; then
  kiro_cli_installed=$(kiro_cli_version "$BIN")
fi
if [ "$kiro_cli_installed" = "$KIRO_CLI_VERSION" ]; then
  printf 'level=info msg="kiro-cli verified at pinned version; publishing readiness marker" version=%s component=entrypoint\n' "$KIRO_CLI_VERSION" >&2
  if ! touch "$KIRO_CLI_READY_MARKER"; then
    printf 'level=warn msg="failed to write kiro-cli readiness marker; /api/health will report kiro-cli unavailable" marker="%s" component=entrypoint\n' "$KIRO_CLI_READY_MARKER" >&2
  fi
else
  # Withholding the marker is otherwise a silent signal: /api/health answers 503
  # and the container sits `unhealthy` forever (readiness, not liveness) with no
  # reason in Loki. Log the observed version so a wedged --version (timeout) is
  # distinguishable from a missing binary or a genuine version mismatch.
  printf 'level=warn msg="kiro-cli not verified at pinned version; readiness marker withheld and /api/health will report kiro-cli unavailable" installed=%s pinned=%s component=entrypoint\n' \
    "${kiro_cli_installed:-none}" "$KIRO_CLI_VERSION" >&2
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
    # Also reject a trailing '-': apt-get treats 'pkg-' as a REMOVE request
    # (and a nonexistent 'name.-' as a regex remove), so a grammar-valid
    # token ending in '-' smuggles a removal through this install-only
    # path. No Debian package name ends in '-' (trailing '+' stays: g++).
    if [[ "$pkg" =~ ^[a-z0-9][a-z0-9+.-]*$ && "$pkg" != *- ]]; then
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
theme_tmp=''
if ! mkdir -p "$(dirname "$theme_file")" \
  || ! theme_tmp=$(mktemp "${theme_file}.XXXXXX") \
  || ! printf '{"baseTheme":"dark","diffPreset":"dark"}\n' >"$theme_tmp" \
  || ! mv "$theme_tmp" "$theme_file"; then
  [ -z "${theme_tmp:-}" ] || rm -f "$theme_tmp"
  printf 'level=warn msg="failed to write kiro-cli theme file; diff colors may be unreadable" file="%s" component=entrypoint\n' "$theme_file" >&2
fi

exec /app/web-terminal-kiro
