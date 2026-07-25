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
  local out rc
  # --kill-after gives a TERM-resistant binary a hard second-stage deadline;
  # without it GNU timeout waits forever on a child that traps/ignores TERM.
  # Capture the output and the timeout STATUS separately: piping straight into
  # awk discarded the status at the pipeline boundary (awk exits 0 even when its
  # producer was TERMed/KILLed), so a wedged --version looked identical to a
  # missing binary at all three call sites -- install verify reported a "wrong
  # version" using install.sh's unrelated rc, drift reported installed=unknown,
  # and readiness reported installed=none. One helper-level warning now gives
  # every caller the same timeout diagnostic, while their empty-version
  # (mismatch) handling stays exactly as it was.
  out=$(timeout --signal=TERM --kill-after=5s 10s "$1" --version 2>/dev/null)
  rc=$?
  if [ "$rc" -ne 0 ]; then
    # 124/137 = the 10s deadline (TERM, then the --kill-after SIGKILL fallback).
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
      printf 'level=warn msg="kiro-cli --version exceeded its 10s deadline and was terminated" path="%s" rc=%d component=entrypoint\n' "$1" "$rc" >&2
    else
      printf 'level=warn msg="kiro-cli --version failed" path="%s" rc=%d component=entrypoint\n' "$1" "$rc" >&2
    fi
    return "$rc"
  fi
  printf '%s\n' "$out" | awk 'NR==1{print $NF; exit}'
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
# ALSO re-verify `kiro-cli settings app.disableAutoupdates true` still succeeds: it is
# the one settings call that is not best-effort. It gates promotion in
# install_kiro_cli AND the readiness marker on a boot that skips the install, so a
# renamed key or subcommand makes every container report kiro-cli unavailable
# (unhealthy, no restart loop) rather than merely logging a warning.
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

# Best-effort: drop boot-time temp artifacts orphaned by a hard container kill
# (a stage dir from install_kiro_cli, or a write probe removed as part of its
# own test). Both are covered on every ordinary path -- the installer's EXIT
# trap and the probe's own rm -- so this only catches SIGKILL residue. Swept
# unconditionally, not just on the reinstall path: a kill that landed after the
# binary was promoted leaves the pinned version on disk, so the next boot needs
# no install and would otherwise never revisit the orphan, leaving tens of MB
# on the persistent /config volume until the next version bump. Off PATH, so
# this is disk hygiene, not an integrity gate; it stays ahead of any install so
# a fresh stage dir is never swept.
rm -rf "$TOOLS"/.kiro-cli-stage.* "$TOOLS"/.write-probe.* 2>/dev/null || true

# Same hygiene argument, applied to the one residue class the sweep above omits:
# binaries an EARLIER image version staged into $HOME/.local/bin (that install ran with
# the real HOME; the current one stages off-PATH under $TOOLS). The reinstall path's
# quarantine only reaches them when this boot installs, so a container already at the
# pin would otherwise carry them until the next version bump -- tens of MB on /config,
# and an unpinned binary one PATH-shadow behind the canonical one. Warn, don't exit:
# the pinned binary is present and leads PATH here, so this is hygiene, not an
# integrity gate (the fatal treatment stays on the reinstall paths below).
if ! rm -f "$HOME/.local/bin/kiro-cli"*; then
  printf 'level=warn msg="failed to sweep legacy kiro-cli staging residue; a shadowed unpinned binary may remain on the volume" dir="%s/.local/bin" component=entrypoint\n' "$HOME" >&2
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

install_kiro_cli() (
  printf 'level=info msg="installing kiro-cli" version=%s component=entrypoint\n' "$KIRO_CLI_VERSION" >&2
  printf 'level=info msg="kiro-cli is proprietary AWS Content; by installing you accept the AWS Customer Agreement" license=https://kiro.dev/license/ component=entrypoint\n' >&2

  # Direct download from the AWS-hosted zip per the docs:
  # https://kiro.dev/docs/cli/installation/ ("With a zip file" section).
  # We pin the version (not /latest/) so a given image tag is reproducible,
  # and verify the sha256 before running install.sh.
  local arch zip_url tmpdir='' zip install_log='' stage=''
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
  # Private staging HOME for the upstream installer. install.sh writes its
  # dispatchers into $HOME/.local/bin, which is BOTH on the image PATH and on
  # the persistent /config volume -- so installing with the real HOME exposed an
  # unverified candidate by bare-name resolution (`docker exec ... kiro-cli`)
  # for the whole validation window, and left it reachable for the container
  # lifetime whenever cleanup failed. Staging under $TOOLS keeps the candidate
  # off PATH entirely and on the same filesystem as $BIN, so promotion stays a
  # rename rather than a copy.
  stage=$(mktemp -d "$TOOLS/.kiro-cli-stage.XXXXXX") || {
    rm -rf "$tmpdir"
    return 1
  }
  # Single cleanup owner for every temp resource: the function body runs in a
  # subshell (note the `(` after the function name), so this EXIT trap fires
  # once per invocation on every return path — no per-branch rm bookkeeping.
  # Removing the private stage is all the failure cleanup needed now: nothing
  # was ever written to a PATH directory, so a cleanup failure can no longer
  # leave an unpinned binary reachable (which is why the old sweep helper and
  # its rc bookkeeping are gone).
  trap 'rm -rf "$tmpdir" "$stage"; [ -z "$install_log" ] || rm -f "$install_log"' EXIT
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

  # Run upstream install.sh against the PRIVATE staging HOME. Don't gate on its
  # exit code — the kiro-cli installer touches shell profiles and other side
  # surfaces that legitimately fail in our minimal root container; what matters
  # is whether the binary it drops at $stage/.local/bin/kiro-cli reports the
  # version we pinned. Capture install.sh output to a tempfile so we can surface
  # it on failure.
  local install_rc staged="$stage/.local/bin/kiro-cli"
  install_log=$(mktemp) || return 1
  HOME="$stage" timeout --signal=TERM --kill-after=15s 120s "$tmpdir/kirocli/install.sh" --no-confirm </dev/null >"$install_log" 2>&1
  install_rc=$?
  # 124 = TERM deadline hit, 137 = the --kill-after SIGKILL fallback fired.
  # Log deadline exhaustion distinctly so Loki shows a wedged installer
  # rather than a generic install failure.
  if [ "$install_rc" -eq 124 ] || [ "$install_rc" -eq 137 ]; then
    printf 'level=warn msg="install.sh exceeded its 120s deadline and was terminated" rc=%d component=entrypoint\n' "$install_rc" >&2
  fi

  if [ ! -f "$staged" ]; then
    printf 'level=error msg="install.sh did not produce kiro-cli binary" path="%s" rc=%d component=entrypoint\n' \
      "$staged" "$install_rc" >&2
    printf 'install.sh output:\n' >&2
    cat "$install_log" >&2
    return 1
  fi
  local installed
  installed=$(kiro_cli_version "$staged")
  if [ "$installed" != "$KIRO_CLI_VERSION" ]; then
    printf 'level=error msg="installed kiro-cli reports wrong version" installed=%s wanted=%s rc=%d component=entrypoint\n' \
      "${installed:-unknown}" "$KIRO_CLI_VERSION" "$install_rc" >&2
    printf 'install.sh output:\n' >&2
    cat "$install_log" >&2
    return 1
  fi

  # Enforce the pin BEFORE promotion, through the staged binary but against the
  # REAL persisted HOME (no HOME override here): app.disableAutoupdates is the
  # one setting the integrity story depends on — with auto-update live the binary
  # can replace itself and invalidate the verified sha. Unlike the telemetry /
  # notification / title preferences applied after promotion, a failure here is
  # fatal to the install: refuse to promote a candidate whose self-replacement we
  # could not turn off.
  if ! timeout --signal=TERM --kill-after=5s 10s "$staged" settings app.disableAutoupdates true >/dev/null 2>&1; then
    printf 'level=error msg="failed to disable kiro-cli auto-update; refusing to promote a binary that may replace itself and invalidate the pinned digest" setting=app.disableAutoupdates path="%s" component=entrypoint\n' "$staged" >&2
    return 1
  fi

  # Promote to the canonical /config/tools/bin/ location so PATH
  # ordering (which puts /config/tools/bin first) and any in-process
  # absolute-path references resolve to the freshly installed binary.
  mv -f "$staged" "$BIN" || {
    printf 'level=error msg="failed to promote kiro-cli binary to tools bin" src="%s" dest="%s" component=entrypoint\n' "$staged" "$BIN" >&2
    return 1
  }
  mv -f "$stage/.local/bin/kiro-cli-chat" "$TOOLS/bin/kiro-cli-chat" 2>/dev/null || true
  mv -f "$stage/.local/bin/kiro-cli-term" "$TOOLS/bin/kiro-cli-term" 2>/dev/null || true
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
  # and the legacy $HOME/.local/bin staging directory BEFORE the reinstall.
  # install_kiro_cli now stages into a private, off-PATH directory under
  # $TOOLS, but $HOME/.local/bin is on the image PATH and on the persistent
  # /config volume, so residue staged there by an EARLIER image version must
  # still be swept: otherwise, once the canonical binary is removed, that
  # residue stays reachable via bare-name PATH resolution (the README's
  # `docker exec ... kiro-cli mcp add`) at a version the pin does not control.
  # Without the quarantine, a failed reinstall after version drift would also
  # leave the old, no-longer-pinned binary executable on PATH: /api/health
  # would report unavailable (marker withheld) yet new sessions would still
  # launch the stale CLI, contradicting the pin guarantee. With it, an install
  # failure leaves every binary absent, so new sessions hit the explicit
  # install-failed guard instead.
  # Inability to quarantine is fatal: we cannot guarantee the pin controls
  # what runs. rm -f is a no-op on the first-boot (nothing present) path.
  if [ -e "$BIN" ] || [ -e "$HOME/.local/bin/kiro-cli" ]; then
    printf 'level=info msg="quarantining stale kiro-cli binaries (canonical and legacy staging) before reinstall" path="%s" component=entrypoint\n' "$BIN" >&2
  fi
  # Glob rather than an explicit name list: an installer that resolves its
  # prefix via getpwuid writes whatever dispatcher set THAT version ships, so a
  # name added upstream must still be quarantined. "$BIN" is covered by the
  # first pattern.
  if ! rm -f \
    "$TOOLS/bin/kiro-cli"* \
    "$HOME/.local/bin/kiro-cli"*; then
    fatal 'failed to remove stale kiro-cli binaries before reinstall; refusing to leave an unpinned binary on PATH' "path=\"$BIN\""
  fi
  if ! install_kiro_cli; then
    printf 'level=warn msg="kiro-cli install failed; web UI starts but the terminal errors until kiro-cli is present" component=entrypoint\n' >&2
    # Belt-and-braces: the installer ran with HOME pointed at the private stage, so it
    # should never have touched $HOME/.local/bin -- but that dir is on PATH and on the
    # persistent volume, and an installer that resolves its prefix via getpwuid rather
    # than $HOME would have. Sweeping here keeps a failed install from leaving an
    # unpinned binary reachable by bare-name resolution until the NEXT boot's
    # pre-reinstall quarantine runs. A sweep FAILURE is fatal, on the same terms
    # as the pre-reinstall quarantine above: it is exactly the case where an
    # installer that resolved its prefix via getpwuid left an unpinned binary on
    # PATH for the container's lifetime. A failed install alone still degrades
    # (web UI up, terminal errors) — only the integrity cleanup failing exits,
    # with fatal's 10s crash-loop throttle. rm -f is a no-op when nothing was
    # written there, which is the normal path.
    if ! rm -f "$HOME/.local/bin/kiro-cli"*; then
      fatal 'failed to sweep legacy staging dir after a failed install; refusing to leave an unpinned binary reachable via bare-name PATH resolution' "dir=\"$HOME/.local/bin\""
    fi
  fi
fi

# Tell kiro-cli to skip telemetry by default. User can flip it via
# `kiro-cli settings telemetry.enabled true` inside the terminal.
# Disable in-binary auto-update: KIRO_CLI_VERSION above is the source
# of truth, kept current by Renovate against the public install
# manifest. Letting kiro-cli silently replace itself would invalidate
# the pinned SHA and break image-tag reproducibility.
# kiro_setting applies one kiro-cli settings call, logging a structured warn on
# failure and RETURNING the call's rc. Boot is never blocked (no caller exits on
# it), but the rc is not decoration: the app.disableAutoupdates caller below
# treats a failure as integrity-relevant and withholds the readiness marker,
# while the telemetry / notification / title callers stay best-effort. A silent
# failure would otherwise leave e.g. auto-update enabled or the OSC 9
# notification path off with no trail in Loki.
kiro_setting() {
  local setting_rc
  timeout --signal=TERM --kill-after=5s 10s "$BIN" settings "$1" "$2" >/dev/null 2>&1
  setting_rc=$?
  if [ "$setting_rc" -ne 0 ]; then
    # 124/137 = the 10s deadline (TERM, then the --kill-after SIGKILL fallback),
    # logged with rc so Loki distinguishes a wedged binary from a settings error.
    printf 'level=warn msg="kiro-cli settings call failed; dependent feature may misbehave" setting=%s value=%s rc=%d component=entrypoint\n' "$1" "$2" "$setting_rc" >&2
  fi
  return "$setting_rc"
}
# Tracks whether the pin-enforcing auto-update setting is actually in force.
# install_kiro_cli refuses to promote a binary it could not turn auto-update off
# for, but a boot that skips the install (already at the pinned version) must
# still re-assert it — and a failure there means the binary may replace itself,
# so readiness is withheld below rather than merely warned about.
kiro_cli_pin_enforced=1
if [ -x "$BIN" ]; then
  kiro_setting telemetry.enabled false
  # app.disableAutoupdates is not a preference: it is what keeps the running
  # binary from replacing itself and invalidating the verified sha. Unlike the
  # best-effort settings around it, a failure here is integrity-relevant.
  if ! kiro_setting app.disableAutoupdates true; then
    kiro_cli_pin_enforced=0
  fi
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
if [ "$kiro_cli_installed" != "$KIRO_CLI_VERSION" ]; then
  # Withholding the marker is otherwise a silent signal: /api/health answers 503
  # and the container sits `unhealthy` forever (readiness, not liveness) with no
  # reason in Loki. Log the observed version so a wedged --version (timeout) is
  # distinguishable from a missing binary or a genuine version mismatch.
  printf 'level=warn msg="kiro-cli not verified at pinned version; readiness marker withheld and /api/health will report kiro-cli unavailable" installed=%s pinned=%s component=entrypoint\n' \
    "${kiro_cli_installed:-none}" "$KIRO_CLI_VERSION" >&2
elif [ "$kiro_cli_pin_enforced" -ne 1 ]; then
  # Right version on disk, but auto-update could not be turned off: the binary
  # may replace itself mid-session and invalidate the pinned sha, so the version
  # just observed guarantees nothing for the container's lifetime. Withhold
  # readiness for the same reason a version mismatch does.
  printf 'level=warn msg="kiro-cli auto-update could not be disabled; readiness marker withheld because the binary may replace itself and invalidate the pinned digest" version=%s component=entrypoint\n' \
    "$KIRO_CLI_VERSION" >&2
else
  printf 'level=info msg="kiro-cli verified at pinned version; publishing readiness marker" version=%s component=entrypoint\n' "$KIRO_CLI_VERSION" >&2
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
    # Also reject a trailing '-': apt-get treats 'pkg-' as a REMOVE request
    # (and a nonexistent 'name.-' as a regex remove), so a grammar-valid
    # token ending in '-' smuggles a removal through this install-only
    # path. No Debian package name ends in '-' (trailing '+' stays: g++).
    if [[ "$pkg" =~ ^[a-z0-9][a-z0-9+.-]*$ && "$pkg" != *- ]]; then
      apt_pkgs+=("$pkg")
    else
      # The rejected token is untrusted env content: bound its length so one bad
      # token cannot dominate the log line, then strip non-printable bytes and
      # neutralize the quote that would close the logfmt field.
      # Backslash is logfmt's escape character; double it so the field's closing
      # quote cannot be escaped. The RAW token is bounded BEFORE that doubling:
      # truncating after it could split a `\\` pair and leave a trailing lone
      # backslash that escapes the closing quote. The bound is therefore 64
      # INPUT chars (at most 128 emitted), not 64 emitted chars.
      safe_pkg=${pkg:0:64}
      safe_pkg=${safe_pkg//\\/\\\\}
      safe_pkg=${safe_pkg//[![:print:]]/?}
      safe_pkg=${safe_pkg//\"/\'}
      printf 'level=warn msg="skipping invalid APT_PACKAGES token" token="%s" component=entrypoint\n' "$safe_pkg" >&2
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
theme_dir="$HOME/.kiro/settings"
theme_file="$theme_dir/kiro_cli_theme.json"
theme_tmp=''
if ! mkdir -p "$theme_dir" \
  || ! theme_tmp=$(mktemp "${theme_file}.XXXXXX") \
  || ! printf '{"baseTheme":"dark","diffPreset":"dark"}\n' >"$theme_tmp" \
  || ! mv "$theme_tmp" "$theme_file"; then
  [ -z "${theme_tmp:-}" ] || rm -f "$theme_tmp"
  printf 'level=warn msg="failed to write kiro-cli theme file; diff colors may be unreadable" file="%s" component=entrypoint\n' "$theme_file" >&2
fi
# kiro-cli persists mcp.json (remote MCP server URLs and tokens) in this same
# directory, so tighten it on the same terms as the /config dirs hardened at the
# top of this file: the mkdir -p above creates it umask-wide (root umask 022 ->
# 0755), and only the 0700 ~/.kiro parent is stopping traversal today. Guarded on
# existence so a failed mkdir does not emit a second, redundant warning.
[ ! -d "$theme_dir" ] || harden_config_dir "$theme_dir"

exec /app/web-terminal-kiro
