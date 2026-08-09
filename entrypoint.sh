#!/bin/bash
# web-terminal-kiro entrypoint. It prepares persistent user and tool state,
# hardens the paths root executes from, prunes superseded KAS runtimes, notices
# legacy tool metadata, seeds the Kiro theme and the session-title hook,
# optionally installs requested apt packages, prepares per-session containment,
# declares the Renovate-pinned kiro-cli version plus both per-arch archive
# digests, exports the pins, and execs the Go web server.
#
# It does NOT install kiro-cli. The server OWNS that install (the
# cplieger/pinstall library, wired in main.go): it downloads
# the pinned archive, verifies its SHA-256, installs it into a
# version-addressed directory under /config/tools/kiro-cli-versions, and decides
# readiness. It does that AFTER the listener binds, so a slow first-boot
# download answers 503 with a reason instead of refusing connections.
#
# kiro-cli is still fetched at runtime rather than baked into the image, for
# the same licensing reason vibekit has: we do not redistribute proprietary AWS
# Content, and the user accepts the license on first boot.

set -u

# This script's own commands must NOT resolve through /config/tools/bin. That dir leads the
# image PATH (Dockerfile ENV PATH) and lives on the persistent bind mount, so on a volume
# that ever permitted group/other writes -- the state secure_tools_dir exists to detect -- a
# planted stat/chmod there would BE the oracle every directory check below trusts. Resolve
# the entrypoint's tools from the image only; the session PATH (which must keep the
# engine-managed dir first) is restored for the exec'd server at the bottom.
#
# The saved value travels in its OWN exported variable, and that is load-bearing rather
# than defensive. The containment block below RE-EXECS this script through setpriv, and
# PATH is exported, so the NARROWED value crosses that exec: a plain SESSION_PATH="$PATH"
# captures the narrowed list on the second invocation, and the restore at the bottom then
# hands the server a PATH carrying none of the three /config-resident tool dirs. Observed
# on borgcube (2026-08): the server ran with exactly the narrow list below, so every binary
# the toolbelt engine installs was unreachable by bare name in the server, in every PTY
# session, and to any agent running in one -- including the engine's own npm and uv, which
# is why /api/health reported tools "degraded" while the tools themselves were installed
# and fine, and why a failed install left a dangling bin/ symlink behind. Deriving from
# KWEB_SESSION_PATH when it is already set makes the capture idempotent across any number
# of re-execs. It is not an operator knob and is unset again before the final exec; a
# deployment that wants a different PATH sets PATH itself, which compose can already do.
#
# Two shapes that look simpler and are wrong. Restoring PATH immediately before that
# re-exec would run the re-exec'd child's whole /config hardening pass with
# /config/tools/bin back on PATH, which is the oracle-poisoning this narrowing exists to
# prevent. Moving the save/narrow pair BELOW the containment block would resolve that
# block's own `mount`, `setpriv` and `awk` through /config/tools/bin for the same reason.
# Both are pinned by tests/shell/session_path_test.sh.
SESSION_PATH="${KWEB_SESSION_PATH:-$PATH}"
export KWEB_SESSION_PATH="$SESSION_PATH"
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

TOOLS="/config/tools"

# The kiro-cli hook that pairs a tab with its kiro session, shipped in the image
# beside this script (Dockerfile COPY). Derived from this script's own location
# rather than restated, so the Dockerfile's COPY destination is the ONE place the
# install path is decided: a literal here would let that COPY move while this kept
# seeding a hook config pointing at the old path, and the whole feature would then
# no-op with no log line anywhere (every tab silently falls back to the engine's
# automatic name ladder). CDPATH='' cd -- "$(dirname -- "$0")" is the same idiom
# tests/image-smoke.sh uses for SMOKE_DIR, and it yields an absolute path even if
# $0 arrives relative. See the seeding block at the bottom for what it does.
SESSION_TITLE_HOOK="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/hooks/session-title.sh"

# Fatal boot error: log it, then throttle the restart:unless-stopped crash loop
# (an immediate exit would hot-spin the container) before failing. $2 carries
# any extra structured fields, already formatted.
fatal() {
  printf 'level=error msg="%s" %scomponent=entrypoint\n' "$1" "${2:+$2 }" >&2
  sleep 10
  exit 1
}

# Make a value this script did not author safe inside a quoted logfmt field. Two
# untrusted classes reach these log lines and they share one implementation so the rules
# cannot drift: APT_PACKAGES tokens (env content) and names read off the /config bind
# mount, which this script's threat model treats as writable by a foreign host user --
# the same premise secure_tools_dir and the taint flag exist for. So the actor a warning
# describes chooses the bytes inside the field that reports him: a file named
# `x" level=info msg="tools tree clean` would otherwise close the field early and append
# attacker-authored logfmt keys, losing the rest of the real message.
#
# Bound the RAW length first (one bad value must not dominate the line, and truncating
# after the backslash doubling could split a `\\` pair and leave a trailing lone
# backslash that escapes the closing quote), double logfmt's escape character, replace
# non-printables, then neutralize the quote that would close the field. $2 is the INPUT
# bound, defaulting to 200 (at most 2x that emitted).
logfmt_value() {
  local raw=$1 safe
  safe=${raw:0:${2:-200}}
  safe=${safe//\\/\\\\}
  safe=${safe//[![:print:]]/?}
  safe=${safe//\"/\'}
  printf '%s' "$safe"
}

# Report a non-root run, because every downstream symptom of one blames something
# else.
#
# This image is root-by-design and there is no second user in it: the Dockerfile
# repoints ROOT's /etc/passwd home to /config/home so OpenSSH -- which resolves "~"
# through getpwuid(), not $HOME -- finds the persisted ~/.ssh. A compose `user:`
# line therefore does not select a supported mode, it selects a UID that appears in
# no passwd entry. The reflex to add one is strong: `user: "${PUID}:${PGID}"` is
# correct in most of this fleet's compose files and in the whole *arr ecosystem it
# borrows from, so an operator adds it here from habit rather than from a decision.
#
# Warn, never fatal, and the split matters. A non-root run is DEGRADED, not
# impossible: with the volume chowned to that UID, /config is writable, the mode
# hardening below succeeds (the UID owns what it chmods), the terminal serves, and
# git over HTTPS works. Only the getpwuid-dependent paths and the root-only ones
# break. That is squarely outside both cases "Failure posture" reserves fatal for,
# and a fatal would additionally remove the only way IN to undo the mistake.
#
# The reason to say it HERE, before any of it happens, is that each failure reports
# a misleading cause in isolation: ssh blames a missing user, make_config_dir blames
# an unmounted /config, the apt phase blames the package, and the containment
# pre-flight below blames a missing capability. None of them names the `user:` line
# that caused all four. One warning up front is the only place that connection is
# legible -- which is why this sits above the containment block rather than after
# it: the CAP_SYS_ADMIN warning is one of the four misleading causes.
#
# uid/gid are parameters rather than reads of $EUID so the branch is testable; the
# defaults are what the real call site uses. Always returns 0: nothing consumes the
# verdict, and a non-zero return would be one `set -e` away from ending boot over a
# diagnostic.
warn_if_not_root() {
  local uid=${1:-$EUID} gid=${2:-${GROUPS[0]:-unknown}}
  if [ "$uid" -eq 0 ]; then
    return 0
  fi
  # Single-quoted inside the hint: logfmt closes a field on the first unescaped
  # double quote, the same reason warn_skipped_apt_token rewrites quotes.
  printf 'level=warn msg="running as a non-root user, but this image is root-by-design; several subsystems will fail" uid=%s gid=%s hint="%s" component=entrypoint\n' \
    "$uid" "$gid" \
    'git and gh over ssh fail with '\''No user exists for uid'\'' because only root has a passwd entry pointing at /config/home; APT_PACKAGES cannot install; session containment cannot engage (dropping CAP_SYS_ADMIN needs CAP_SETPCAP); and the /config mode hardening cannot chmod paths this UID does not own. Remove the user: line from the compose service. See the README run block.' >&2
  return 0
}

warn_if_not_root

# Make the container's own cgroup tree writable so the server can put each tab's
# kiro-cli process tree in its own cgroup, then hand the rest of this script a
# process WITHOUT the capability that made it possible.
#
# Why this exists at all: `kiro-cli chat` is a four-deep tree (kiro-cli ->
# kiro-cli-chat -> the TUI -> the agent server) whose last process calls setsid().
# That leaves both the process group and the session, so neither a group-scoped
# kill nor the PTY-close SIGHUP can reach it, and since it installs no stdin-EOF
# exit path it can outlive the tab that spawned it holding hundreds of megabytes.
# Measured on this image: 13 stranded processes holding 1.35 GB on a container with
# two tabs open.
#
# That LEAK is no longer what this buys, and the distinction decides whether an
# operator should grant a capability. Engine v3.6.0 reaps a closed session's
# surviving tree from an inherited environment marker with no host support at all
# (the engine's marker-based SESSION reaping; collecting orphan zombies is a separate
# job and it belongs to the container init, which compose supplies with `init: true`),
# so what containment adds ON TOP is the per-session peak numbers (mem_peak_bytes,
# tasks_peak) and a kill domain a scrubbed-environment descendant cannot escape.
# Keep this paragraph in step with startContainment's doc comment in main.go: they
# are the same tradeoff, told to the same operator, on the same boot.
#
# Docker mounts /sys/fs/cgroup read-only and offers no option to change that, so a
# one-time remount is the established workaround (the same one runc documents for
# running systemd in a container). It needs CAP_SYS_ADMIN to OPT IN; the public
# compose example grants no capability, so the refusal path below is the ordinary one
# there, while the homelab deployment does carry cap_add: [SYS_ADMIN] and takes the
# remount path.
#
# WARN, never fatal, per this app's failure posture: without containment the
# server still serves terminals exactly as it did before the feature existed, and
# the public compose example deliberately adds no capability. The server logs what
# is lost when it finds the tree read-only, so the degradation is visible without
# being fatal.
enable_session_containment() {
  # cg_root is a parameter with the real default purely for testability, matching
  # warn_if_not_root's uid/gid: a unit test must be able to hand it a temp dir instead
  # of the host's own /sys/fs/cgroup, whose mount state is the CI runner's, not this
  # function's.
  local cg_root=${1:-/sys/fs/cgroup} mount_err
  if ! mount_err=$(mount -o remount,rw "$cg_root" 2>&1); then
    # Carry mount's own error into the warn: the hint below is only ONE of the ways
    # this remount fails, and the discarded text is the only discriminator between
    # "add the capability" and "this host cannot do this at all". Sanitized through the
    # SHARED logfmt_value (moved above this block for exactly this call), so the four
    # rules have one implementation, which is what its own comment promises. Only the
    # newline flatten stays here, and it is a presentation choice rather than a rule: a
    # space reads better in this message than the `?` logfmt_value's non-print rule
    # would leave, and flattening before the call preserves the original order (bound
    # the RAW value, then escape).
    mount_err=$(logfmt_value "${mount_err//$'\n'/ }")
    printf 'level=warn msg="cannot remount /sys/fs/cgroup rw; per-session containment cannot engage, so per-session peak memory and task counts will not be reported. Closed-tab process trees are still reaped without it" error="%s" hint="OPTIONAL: add cap_add: [SYS_ADMIN] to the compose service to enable containment; the capability is dropped again immediately after this remount. Not granted by default, because marker-based session reaping in the engine closes the process leak without it" component=entrypoint\n' "$mount_err" >&2
    return 1
  fi
  # Report ONLY what the remount proved, and on stderr like every other line in this
  # file. The old message said "per-session process containment available", which is a
  # claim about the MOUNT rather than about containment: measured on borgcube
  # 2026-08-06 (image v2.7.7) the server failed six seconds later with "enable
  # controllers in /sys/fs/cgroup/cgroup.subtree_control: device or resource busy" and
  # every session ran uncontained, while an operator reading only this line concluded
  # the feature was on.
  #
  # Vacating the cgroup root is deliberately NOT done here, and an earlier attempt to
  # do it BROKE containment outright. cgroup v2 does forbid enabling a controller on a
  # cgroup that still holds member processes -- that is the EBUSY above -- and the
  # engine's own NewContainment already handles it: vacateRoot (step 5) moves every pid
  # out of the root into its "wt-server" leaf before delegate() writes
  # cgroup.subtree_control. That does NOT explain the borgcube measurement, and the
  # reason is worth recording rather than assuming: image v2.7.7 pinned engine v3.4.2,
  # whose terminal/containment_linux.go is byte-identical to the v3.4.3 pinned here
  # (containment landed in one engine commit, first tagged v3.4.0, vacate included), so
  # that EBUSY occurred WITH the vacate running. Its cause is still open; do not read
  # this block as having closed it. What is settled is only that the fix does not
  # belong here. A leaf created HERE cannot be named acceptably: step 2, verifyOwnRoot,
  # refuses the entire root as soon as it holds any child directory whose name does not
  # start with the server's prefix ("wt-", main.go's containCgroupPrefix), because a
  # foreign child is exactly how it detects a HOST cgroup root it must not reshape. An
  # entrypoint-created "init" leaf therefore made NewContainment refuse before it ever
  # reached the vacate, disabling containment on the hosts where it would otherwise
  # work -- and this line would have claimed availability while it did.
  #
  # So: remount, say only that, and leave the topology to the process that owns it. The
  # server logs the verdict either way ("terminal: containment enabled", or
  # startContainment's warn naming the reason), and that is the line to read.
  printf 'level=info msg="cgroup tree remounted rw, which is the only step here that needs privilege; whether per-session process containment engages is decided and logged by the server at startup" component=entrypoint\n' >&2
  return 0
}

# One remount, then drop the capability that allowed it, as early as this script
# can. The ordering is the point: the remaining boot work includes `apt-get update`
# plus an APT_PACKAGES install on every start, and holding the broadest capability
# there is across network-fetched package installation to buy a single mount call
# would be a bad trade. Re-executing here reduces the window to that one call.
#
# This block must stay BELOW enable_session_containment's definition: bash resolves
# a function at call time, so a call placed above the definition does not fail
# loudly, it reports "command not found", gets swallowed by the `|| true`, and boot
# continues with containment silently never enabled. Nothing above this point needs
# the capability, so being a few assignments late costs nothing.
#
# Verified safe to run unconditionally: setpriv exits 0 when asked to drop a
# capability the container never had (so the public compose example, which adds
# none, is unaffected), and it is idempotent if somehow reached twice. The marker is
# an env var rather than an argv flag so "$@" reaches the server untouched. setpriv
# ships in util-linux, which Debian marks Essential, so it cannot be missing; the
# guard is there so a hand-built image without it degrades to a warning rather than
# a container that cannot boot.
if [ "${KWEB_CONTAINMENT_CAPS_DROPPED:-}" != "1" ]; then
  enable_session_containment || true
  export KWEB_CONTAINMENT_CAPS_DROPPED=1
  # PRE-FLIGHT the drop before committing to it, because this is an `exec`: a
  # setpriv that fails here does not degrade, it ends the container. Two ways it
  # can fail on an image this one does not control -- setpriv absent from a
  # hand-built variant, and dropping from the BOUNDING set requiring CAP_SETPCAP,
  # which a container started with a reduced capability set or as a non-root user
  # does not have (observed: "setpriv: apply bounding set: Operation not
  # permitted"). One throwaway invocation distinguishes "will work" from "would
  # brick boot" for the cost of a fork, and this app's failure posture is explicit
  # that a dev box must keep serving a terminal rather than refuse to start.
  if setpriv --bounding-set=-sys_admin --inh-caps=-sys_admin -- true 2>/dev/null; then
    exec setpriv --bounding-set=-sys_admin --inh-caps=-sys_admin -- "$0" "$@"
  fi
  # The drop is impossible here. What happens next depends on whether the
  # capability is actually HELD, and the two cases are not the same decision:
  #
  #   not held (the public compose example, no cap_add) - nothing to drop, so this
  #     is the ordinary degraded path. Warn and continue; containment is off.
  #   held but undroppable - continuing would run the server AND every user
  #     terminal with CAP_SYS_ADMIN for the container's life, which is exactly the
  #     standing privilege this whole re-exec exists to avoid. That is a security
  #     regression against today's behaviour rather than a degradation of it, so it
  #     is one of the two cases "Failure posture" reserves fatal for: continuing
  #     would compromise something.
  if [ "$((0x$(awk '$1 == "CapEff:" { print $2 }' /proc/self/status) & (1 << 21)))" -ne 0 ]; then
    fatal "CAP_SYS_ADMIN is held and cannot be dropped; refusing to run the server and terminal sessions with it" \
      'hint="setpriv could not drop the bounding set (needs CAP_SETPCAP). Remove cap_add: [SYS_ADMIN] from the compose service to run without containment."'
  fi
  printf 'level=warn msg="CAP_SYS_ADMIN not held and containment unavailable; continuing without it" component=entrypoint\n' >&2
fi

# Create ONE level of a persistent directory and prove the created path is a real
# directory rather than a symlink, BEFORE anything is written to or deleted beneath
# it. `mkdir -p a/b/c` FOLLOWS a symlink at any component, so creating a deep path in
# one call silently accepts a planted link and every later step then acts on the
# link's TARGET: the $HOME/.local/bin legacy sweep would `rm -rf <target>/kiro-cli*`
# and the ~/.kiro/settings theme write would replace a fixed-name file there. Checking
# only the parent cannot constrain a symlink AT the child, which is why callers walk
# the chain parent-to-child and validate each component before creating its child.
# Mode enforcement stays with harden_config_dir / secure_tools_dir, which the callers
# apply after this walk (they are the ones that must not run before the write probe).
make_config_dir() {
  local dir=$1
  if [ -L "$dir" ]; then
    fatal 'refusing to use a symlinked config path; its target may be outside the /config mount' "dir=\"$dir\""
  fi
  if ! mkdir -p "$dir"; then
    fatal 'failed to create config directory (is /config mounted and writable?)' "dir=\"$dir\""
  fi
  if [ ! -d "$dir" ]; then
    fatal 'config path is not a directory' "dir=\"$dir\""
  fi
}

# Enforce the conventional 0700 on one /config-resident directory. mkdir -p
# creates new dirs umask-wide (root umask 022 -> 0755) and leaves an existing
# dir's mode alone; these dirs live on the /config host bind mount, where a
# wider mode lets other host users traverse them and read secret-adjacent
# material (~/.ssh keys and known_hosts, ~/.kiro/settings/mcp.json tokens,
# ~/.local install state, $HOME's .gitconfig/.netrc/credential stores). Because
# these are credential-bearing directories rather than cosmetic hygiene, the
# POSTCONDITION is enforced, not merely attempted: a symlink (whose target may
# be outside the mount) is fatal, and boot fails unless the final mode has every
# group/other bit clear. A chmod that fails on a mount with foreign permission
# semantics is survivable ONLY when stat then proves the mode is already private.
# The directory travels in a dir= field, matching how the rest of this file
# reports variable data (marker=, path=, token=).
harden_config_dir() {
  local dir=$1 mode
  if [ -L "$dir" ]; then
    fatal 'refusing to use a symlinked config directory; its target may be outside the /config mount' "dir=\"$dir\""
  fi
  if [ ! -d "$dir" ]; then
    fatal 'config path is not a directory' "dir=\"$dir\""
  fi
  if ! chmod 700 "$dir"; then
    printf 'level=warn msg="failed to tighten config directory permissions; verifying the existing mode instead" dir="%s" component=entrypoint\n' "$dir" >&2
  fi
  mode=$(stat -c '%a' "$dir" 2>/dev/null) || mode=""
  if [ -z "$mode" ]; then
    fatal 'failed to read config directory mode; cannot prove it is private' "dir=\"$dir\""
  fi
  # 8#$mode: %a prints octal without a base prefix. 0077 = every group/other bit.
  if [ $((8#$mode & 0077)) -ne 0 ]; then
    fatal 'config directory holding credential-bearing state is not private; refusing to boot with it group/other-accessible' "dir=\"$dir\" mode=$mode"
  fi
}

# --- persistent tool-tree integrity ---------------------------------------------
# $TOOLS/bin leads PATH (see the Dockerfile's ENV PATH) and the version-addressed
# install root sits beside it at $TOOLS/kiro-cli-versions, so the tree HOLDING
# kiro-cli is part of the integrity story, not just the download. The server's
# install manager accepts an already-present version directory on the strength of
# its own `.complete` sentinel, and a sentinel is trivially forgeable, unlike a
# digest. If an inherited /config volume ever permitted group/other writes, another
# host user could plant a version directory there and be launched as root with
# access to credentials and /workspace.
# So: refuse symlinks, strip group/other write bits, fail boot if they survive,
# and remember that the tree WAS writable so the flag exported below tells the
# manager to trust no pre-existing version directory. Sets
# tools_tree_was_writable=1 in that case.
tools_tree_was_writable=0
# $2 (default 1) arms the taint flag when the dir was writable. Pass 0 for a PATH
# segment that never holds kiro-cli.
secure_tools_dir() {
  local dir=$1 arm=${2:-1} owned=${3:-1} mode
  # `owned` decides what an UNRECOVERABLE state costs. This is a dev-box container:
  # the operator is expected to reshape /config/tools to stay productive (the
  # borgcube audit deleted both runtimes trees and symlinked corepack, see
  # web-terminal-kiro.md), so a broken state must be able to heal itself or at worst
  # be fixable from INSIDE the container. Aborting boot fails that test -- there is no
  # way in to repair it, and nothing recreates these trees.
  #   owned=1  the NINE directories this entrypoint creates itself, i.e. exactly the
  #            make_config_dir list outside $HOME: /config, $TOOLS, $TOOLS/bin,
  #            $TOOLS/opt, $TOOLS/npm, $TOOLS/npm/bin, $TOOLS/python,
  #            $TOOLS/python/bin and $TOOLS/kiro-cli-versions. Two properties make
  #            them ours, and both are needed. (a) The entrypoint CREATES them, so a
  #            symlink or a plain file there is unambiguously anomalous rather than
  #            the operator's shape. (b) A reinstall REPAIRS their contents -- the
  #            toolbelt engine reinstalls a tool it finds missing and the kiro-cli
  #            manager reinstalls from the pinned archive -- so refusing to boot
  #            costs a download, not the operator's data. The npm and python roots
  #            are in the set for the reason $TOOLS/bin is: $TOOLS/bin leads PATH
  #            and its entries are symlinks INTO opt/, npm/bin/ and python/bin/
  #            (toolbelt install.go's npmDir/pythonDir + linkPMBins), so root
  #            executes what those trees hold, and a group/other-writable root there
  #            lets a foreign host user replace a launcher -- which tightening the
  #            leaf file alone cannot prevent. Fatal.
  #   owned=0  $TOOLS/go and $TOOLS/go/bin, i.e. GOPATH/bin and its parent: on PATH
  #            (Dockerfile ENV PATH) but never created and never repaired here, and
  #            holding no integrity-gated binary -- a `go install` lands whatever the
  #            operator asked for. Warn and skip, matching
  #            prune_superseded_kas_runtimes' explicit "disk hygiene must not brick
  #            boot" precedent for a tree this script does not own.
  # The mode enforcement below is unaffected: a writable tree is still tightened on
  # every path, and on an owned tree that resists tightening the boot still stops.
  if [ -L "$dir" ]; then
    if [ "$owned" -eq 0 ]; then
      printf 'level=warn msg="PATH-segment directory is a symlink; skipping it (its target may be outside the /config mount, and this tree holds no integrity-gated binary)" dir="%s" component=entrypoint\n' "$dir" >&2
      return 0
    fi
    fatal 'refusing to use a symlinked tools directory; its target may be outside the /config mount' "dir=\"$dir\""
  fi
  if [ ! -d "$dir" ]; then
    if [ "$owned" -eq 0 ]; then
      printf 'level=warn msg="PATH-segment path is not a directory; skipping it" dir="%s" component=entrypoint\n' "$dir" >&2
      return 0
    fi
    fatal 'tools path is not a directory' "dir=\"$dir\""
  fi
  mode=$(stat -c '%a' "$dir" 2>/dev/null) || mode=""
  if [ -z "$mode" ]; then
    if [ "$owned" -eq 0 ]; then
      printf 'level=warn msg="failed to read PATH-segment directory mode; skipping it" dir="%s" component=entrypoint\n' "$dir" >&2
      return 0
    fi
    fatal 'failed to read tools directory mode; cannot prove it is not group/other-writable' "dir=\"$dir\""
  fi
  # 0022 = the group and other write bits; 8#$mode because %a has no base prefix.
  if [ $((8#$mode & 0022)) -eq 0 ]; then
    return 0
  fi
  if [ "$arm" -eq 0 ]; then
    printf 'level=warn msg="PATH-segment directory permits group/other writes; tightening it (no kiro-cli quarantine: this tree never holds one)" dir="%s" mode=%s component=entrypoint\n' "$dir" "$mode" >&2
  else
    tools_tree_was_writable=1
    printf 'level=warn msg="tools directory permits group/other writes; tightening it and treating any kiro-cli it already holds as untrusted" dir="%s" mode=%s component=entrypoint\n' "$dir" "$mode" >&2
  fi
  if ! chmod go-w "$dir"; then
    printf 'level=warn msg="failed to strip group/other write bits from tools directory; verifying the resulting mode instead" dir="%s" component=entrypoint\n' "$dir" >&2
  fi
  mode=$(stat -c '%a' "$dir" 2>/dev/null) || mode=""
  if [ -z "$mode" ]; then
    if [ "$owned" -eq 0 ]; then
      printf 'level=warn msg="failed to re-read PATH-segment directory mode after tightening; leaving it out of the trusted set" dir="%s" component=entrypoint\n' "$dir" >&2
      return 0
    fi
    fatal 'failed to re-read tools directory mode after tightening' "dir=\"$dir\""
  fi
  if [ $((8#$mode & 0022)) -ne 0 ]; then
    if [ "$owned" -eq 0 ]; then
      printf 'level=warn msg="PATH-segment directory remains group/other-writable after tightening; a foreign host user could plant a binary this container runs, but bricking boot on a tree the entrypoint neither creates nor repairs is the worse failure" dir="%s" mode=%s component=entrypoint\n' "$dir" "$mode" >&2
      return 0
    fi
    fatal 'tools directory holding the first-on-PATH kiro-cli remains group/other-writable; refusing to trust the persistent binary tree' "dir=\"$dir\" mode=$mode"
  fi
}

# --- legacy kiro-cli dispatcher sweep -------------------------------------------
# Older image versions ran the upstream installer with the real HOME, so a volume
# created by one can still hold kiro-cli dispatchers in $HOME/.local/bin. That dir is
# on PATH (see the Dockerfile's ENV PATH), so a leftover is an UNPINNED BINARY
# REACHABLE BY BARE NAME, not merely wasted disk. The server's install manager runs
# the upstream installer against a private staging HOME and publishes by directory
# rename, so it never writes there -- this sweep exists for pre-existing volumes and
# as belt-and-braces against an installer that resolves its prefix via getpwuid
# rather than $HOME. The manager owns the matching sweep of $TOOLS/bin, where it also
# republishes the convenience symlink, so this script must not touch that dir.
#
# Two robustness rules:
#
#   1. rm -rf, not rm -f. `rm -f` FAILS on a directory, so a stray directory named
#      kiro-cli-anything under a swept dir would turn a hygiene step into a boot
#      failure (fatal, with its 10s crash-loop throttle) at any caller that checked
#      the status.
#   2. Assert the GOAL, not the ACTION. rm's exit status answers "did the unlink
#      succeed", never "is an unpinned kiro-cli still reachable". Those come apart in
#      BOTH directions: an unremovable non-binary (an immutable kiro-cli-notes.txt, a
#      read-only mount) fails the status check while shadowing nothing, and anything
#      the kiro-cli* prefix does not match (a future dispatcher name, a symlink
#      planted under another name) passes it while shadowing.
#
# What makes shadowing a non-event now is PATH order, not this sweep: every session
# leads with the active version's own directory (the server prepends it), so nothing
# under $HOME/.local/bin can win bare-name resolution while a version is active. That
# is why the sweep is warn-only and why the bare-name resolution check it used to feed
# is gone -- the invariant it asserted now holds by construction.
# Takes ONE directory, deliberately. The only residue dir left in this script's
# remit is $HOME/.local/bin; $TOOLS/bin is the manager's, per the block comment
# above, so a variadic signature only invited the second argument that comment
# forbids.
sweep_legacy_dispatchers() {
  local dir=${1:-}
  # Never expand to /kiro-cli* on an unset/empty argument.
  [ -n "$dir" ] || return 0
  if ! rm -rf "$dir/kiro-cli"*; then
    printf 'level=warn msg="failed to remove legacy kiro-cli residue" dir="%s" component=entrypoint\n' "$dir" >&2
  fi
  # Always 0, deliberately: per the block comment above, rm's status answers 'did the
  # unlink succeed', never 'is an unpinned kiro-cli still reachable'. Returning a
  # failure count here only invited a caller to read it as the safety verdict.
  return 0
}

# Reclaims the one install residue the two bin-dir sweeps cannot see: kiro-cli's own
# agent-server runtimes. Each version unpacks a ~240 MB tree under
# <data-dir>/kas/<version>-<hash>/ (plus a sibling .lock) on its FIRST chat launch --
# after this entrypoint has already exec'd the server -- and nothing ever removes the
# superseded ones, so the store gains a full tree per Renovate bump and never shrinks
# (six trees / 1.4 GB found on the borgcube volume, 2026-07). The miss was structural,
# not an oversight in a loop: every existing sweep cleans what the ENTRYPOINT wrote,
# and this tree is written later, by the binary the entrypoint promoted. The toolbelt
# engine already applies exactly this keep-current-drop-the-rest rule to its own
# versioned opt/<tool>/<version>/ trees (pruneOldVersions in the library's install.go),
# so this extends the same rule to the one install outside the engine's custody --
# kiro-cli, which cannot be engine-managed because licensing forbids baking it in.
#
# Data-dir resolution mirrors kiro-cli's own (XDG_DATA_HOME, else $HOME/.local/share):
# pruning a directory the CLI does not use would be a silent no-op, which is the one
# failure mode a disk-hygiene step must not have. Warn, never fatal -- same argument as
# the sweeps above: nothing here is on PATH or gates integrity, and a container whose
# runtime store cannot be tidied must still boot.
prune_superseded_kas_runtimes() {
  # $1 = the version whose runtime tree must survive; defaults to the pin. The caller
  # passes the pin, since the version that ends up active is only known after the
  # server's install manager has selected one, which happens after this script execs.
  local keep="${1:-$KIRO_CLI_VERSION}" data_home kas_dir kas_real entry name
  data_home="${XDG_DATA_HOME:-}"
  if [ -z "$data_home" ]; then
    # Under set -u an unset HOME would abort the boot; a data dir we cannot locate is
    # simply nothing to prune.
    [ -n "${HOME:-}" ] || return 0
    data_home="$HOME/.local/share"
  fi
  kas_dir="$data_home/kiro-cli/kas"
  [ -d "$kas_dir" ] || return 0
  # `-d` FOLLOWS symlinks and the rm below runs as root, so a `kiro-cli` or `kas`
  # symlink planted on a volume that once permitted foreign writes (the same premise
  # secure_tools_dir defends against) would redirect this sweep at an arbitrary tree
  # and delete every entry that does not match the pin. Prove the store is a real
  # directory resolving where it is named, or skip the prune (warn, never fatal:
  # disk hygiene must not brick boot).
  if [ -L "$data_home/kiro-cli" ] || [ -L "$kas_dir" ]; then
    printf 'level=warn msg="kiro-cli data dir or its kas store is a symlink; refusing to prune through it" dir="%s" component=entrypoint\n' "$kas_dir" >&2
    return 0
  fi
  kas_real=$(realpath "$kas_dir" 2>/dev/null) || kas_real=""
  case "$kas_real" in
    "$data_home"/kiro-cli/kas) ;;
    *)
      printf 'level=warn msg="kiro-cli kas store does not resolve inside the data dir; refusing to prune" dir="%s" resolved="%s" component=entrypoint\n' \
        "$kas_dir" "$(logfmt_value "${kas_real:-unknown}")" >&2
      return 0
      ;;
  esac
  for entry in "$kas_dir"/*; do
    # An empty store leaves the glob unexpanded.
    [ -e "$entry" ] || continue
    name="${entry##*/}"
    # One pattern covers the tree and its sibling .lock: both carry the
    # <version>-<hash> stem, and the quoted expansion keeps a version string from
    # being read as a glob.
    case "$name" in
      "$keep"-*) continue ;;
    esac
    # Only VERSION-KEYED entries are superseded runtimes. kas/ is kiro-cli's
    # directory, not ours, so an entry with no leading numeric version component
    # is something this pruner has never seen (a store-wide lock, an unpack
    # scratch dir, an index) -- and deleting another program's unrecognized state
    # on every boot is a worse failure than leaving a few MB behind. Both layouts
    # observed today (the <version>-<hash> tree and its .lock sibling) match, so
    # this is a no-op against the current CLI; log the skip so a layout change is
    # visible instead of silent.
    if [[ ! "$name" =~ ^[0-9]+\.[0-9]+\.[0-9]+- ]]; then
      printf 'level=info msg="leaving unrecognized (non version-keyed) entry in the kiro-cli agent runtime store" entry="%s" component=entrypoint\n' "$(logfmt_value "$name")" >&2
      continue
    fi
    if rm -rf "$entry"; then
      printf 'level=info msg="pruned superseded kiro-cli agent runtime" entry="%s" keep=%s pinned=%s component=entrypoint\n' "$(logfmt_value "$name")" "$keep" "$KIRO_CLI_VERSION" >&2
    else
      printf 'level=warn msg="failed to prune superseded kiro-cli agent runtime" entry="%s" component=entrypoint\n' "$(logfmt_value "$name")" >&2
    fi
  done
  return 0
}

# --- legacy tool-metadata notice ------------------------------------------------
# toolbelt keeps three metadata files -- tools.json (HAND-AUTHORED intent:
# enabling a tool is a file edit plus a restart), tools-state.json (engine-owned
# machine state) and tool-catalog.cached.json. They used to sit directly under
# /config; the server now points the engine's config dir at $TOOLS, where the
# artifacts they describe already live. That relocation is a CLEAN BREAK, not a
# migration: on a volume created by an earlier image the three files stay where
# they are, nothing reads them, and the engine seeds a fresh manifest beside the
# tree instead.
#
# This notice exists because that break is otherwise SILENT, which is the only
# claim it makes. From the engine's point of view such a volume IS a fresh one:
# it seeds five disabled templates (toolbelt's DefaultSeed) and logs nothing
# unusual. So the operator's enabled tools come back as disabled templates, and
# any tool they added by name is absent from the manifest entirely -- while its
# binary still resolves on PATH, because $TOOLS/bin and the opt/npm/python trees
# were never touched. The engine cannot report any of that: its reconcile derives
# every work set from the manifest and the state file, and an artifact with no
# state row is neither a disabled "extra" nor an "orphan" (that pass iterates the
# state), so a converged boot prints "everything converged" over a tree it no
# longer records as its own -- and a later uninstall of such a name removes
# opt/<name> while leaving bin/<name> behind as a dangling symlink in the dir
# that leads PATH, since the bin names to unlink are read from that same state.
#
# So: say it, and do nothing else. This is a NOTICE, and each of its properties
# is deliberate:
#
#   1. It MOVES, DELETES and CREATES nothing -- not even a marker. A marker is a
#      write, and a write is precisely what must not happen here. It therefore
#      repeats every boot; the operator deleting the old files is what silences
#      it, which is also the action the message asks for.
#   2. It cannot fail boot, per web-terminal-kiro.md "Failure posture": the body
#      is two existence tests per name and one printf.
#   3. A symlink at either end needs no guard, unlike the sweeps above. Nothing
#      here is followed into, chmod'ed, moved or removed, so there is no
#      operation a planted link could redirect. The test accepts a DANGLING link
#      as well ([ -e ] dereferences, [ -L ] does not): a leftover the operator
#      has to clear is a leftover whether its target still exists or not.
warn_legacy_tool_metadata() {
  local from=$1 to=$2 name found=""
  for name in tools.json tools-state.json tool-catalog.cached.json; do
    if [ -e "$from/$name" ] || [ -L "$from/$name" ]; then
      found="${found:+$found }$name"
    fi
  done
  [ -n "$found" ] || return 0
  printf 'level=warn msg="tool metadata found at its OLD location and IGNORED: it now lives beside the tools tree it describes, so the engine seeded a fresh manifest -- previously enabled tools are back to disabled templates, and tools added by name are not in it at all. Their binaries still resolve on PATH, but the engine no longer records, updates or uninstalls them. Re-apply your selections in the new manifest, then delete the old files to silence this" files="%s" old="%s" new="%s" component=entrypoint\n' \
    "$found" "$from" "$to/tools.json" >&2
  return 0
}

# Warn about a rejected APT_PACKAGES token. The token is untrusted env content, so it
# goes through the shared sanitizer above with a tighter 64 INPUT char bound (at most 128
# emitted). Shared by both rejection paths (grammar and known-name) so the sanitizing
# rules cannot drift between them.
warn_skipped_apt_token() {
  local msg=$1 raw=$2 safe
  safe=$(logfmt_value "$raw" 64)
  printf 'level=warn msg="%s" token="%s" component=entrypoint\n' "$msg" "$safe" >&2
}

# kiro-cli is pinned via Renovate against the public install manifest at
# https://desktop-release.q.us-east-1.amazonaws.com/index.json. Bumping the version
# literal makes the server install that version on the next container start. Auto-update
# inside the binary is disabled so what runs always matches the version baked into the
# image tag. KIRO_CLI_SHA256 (x86_64) and KIRO_CLI_SHA256_ARM64 (aarch64) are the
# per-arch sha256 of the headless zip, BOTH enforced at install; the kiro-cli
# packageRule in cplieger/.github groups all three literals into one Renovate PR so
# neither arch's gate can land stale.
# All three are EXPORTED below and consumed by the server's install manager
# (cplieger/pinstall, wired by main.go's kiroInstallConfig), which is the only
# installer. They stay shell literals here
# because that is where Renovate's custom datasource finds them.
# COUPLING (re-verify on every bump): routes.go's status classifier matches
# kiro-cli's EXACT OSC 9 notification strings "Response complete" (turn end ->
# done dot), "Permission required" (tool approval -> needs-input dot) and
# "Input required" (a structured user question -> the same needs-input dot),
# verified against this version. A bump that reworded any of them silently
# stops the per-tab status dots from latching (no error; only a Debug log in
# routes.go). The feature also depends on the chat.enableNotifications +
# chat.notificationMethod=osc9 settings the manager applies and
# web-terminal-engine's WithKeepUnfocused() in routes.go -- keep all four in lockstep.
# ALSO re-verify `kiro-cli settings app.disableAutoupdates true` still succeeds: it is
# the one settings call that is not best-effort. It gates publication of a staged
# install AND readiness on a boot that installs nothing, so a renamed key or
# subcommand makes every container report kiro-cli unavailable (unhealthy, no restart
# loop) rather than merely logging a warning.
# renovate: datasource=custom.kiro-cli depName=kiro-cli
KIRO_CLI_VERSION="2.16.2"
KIRO_CLI_SHA256="0e88b51c894b08915ae47f48da70b8b9c94c267c157f778f54e1c5f5f42b682f"
# The `# kiro-cli <version>` trailer is Renovate's version anchor for this
# arch's digest lookup — do not hand-edit or drop it.
# renovate: datasource=custom.kiro-cli-arm64 depName=kiro-cli-arm64
KIRO_CLI_SHA256_ARM64="2a81e466ac212a45e3f2114b3529597f5a265dbc18bb6256150c5140b3c3c71a" # kiro-cli 2.16.2

# Hand the pins and the tools tree to the server. The manager selects the digest for
# the architecture it is running on, so both travel; the tools tree travels
# EXPLICITLY, so the one path this script hardens is provably the one the manager
# writes to -- and the toolbelt engine now resolves both its config dir and its
# tools dir from the same export, so the manifest and the state cannot end up
# describing a tree they do not sit in.
export KIRO_CLI_VERSION KIRO_CLI_SHA256 KIRO_CLI_SHA256_ARM64
KIRO_CLI_TOOLS_DIR="$TOOLS"
export KIRO_CLI_TOOLS_DIR

# $HOME (/config/home) is the root of every credential-bearing tree hardened
# below, and `mkdir -p "$HOME/.ssh"` would silently FOLLOW a symlinked $HOME to
# a target outside the /config mount -- creating and populating the credential
# dirs somewhere with no enforced mode. Check the boundary BEFORE any child path
# is created: a real directory under /config, not a link.
if [ -L "$HOME" ]; then
  fatal 'refusing to use a symlinked HOME; its target may be outside the /config mount' "home=\"$HOME\""
fi
# Containment is asserted ONCE, on the RESOLVED path (-m, so a not-yet-created
# HOME still resolves). A lexical `case "$HOME" in /config/*` used to run first
# and is gone: it could not decide the question either way (/config/../etc
# matches it and is not a symlink). This check refuses the shapes it refused
# (/etc/foo, /configx/home, /config itself, an empty HOME whose realpath fails)
# plus the '..' and symlinked-ANCESTOR escapes it let through. One acceptance
# deliberately widened: a HOME that lexically sits outside /config but RESOLVES
# inside it (an ancestor symlinked INTO the mount) used to fatal on the lexical
# gate and now boots -- which is what the invariant this gate enforces ("must
# resolve beneath /config") says should happen; everything the walk below
# creates through such a HOME still lands under /config. The -L test above
# stays: it enforces the separate, stricter policy that $HOME's own final
# component must not be a link even when it resolves inside /config.
home_real=$(realpath -m "$HOME" 2>/dev/null) || home_real=""
case "$home_real" in
  /config/?*) ;;
  *) fatal 'HOME does not resolve beneath the /config mount' "home=\"$HOME\" resolved=\"${home_real:-unknown}\"" ;;
esac

# Create every persistent directory parent-to-child, proving each component is a real
# directory before its child (or any file beneath it) is created. A single
# `mkdir -p "$HOME/.local/bin" ...` would traverse a symlink planted at any component
# on an inherited, once-permissive volume -- and $HOME/.local/bin in particular is
# swept with `rm -rf "$dir"/kiro-cli*` a few lines below, as root, so a
# `.local/bin -> /workspace/victim` link used to delete the link target's matching
# files before any guard looked at that path. /config is included so a symlinked mount
# root cannot redirect the whole tree; $HOME itself was proven above.
printf 'level=info msg="preparing persistent directories" dir="%s" component=entrypoint\n' /config >&2
make_config_dir /config
make_config_dir "$TOOLS"
make_config_dir "$TOOLS/bin"
# The version-addressed install root the server's manager writes into. It is created
# and validated HERE, one component at a time, rather than by the manager's own
# MkdirAll: a symlink planted on an inherited volume would silently redirect a
# root-owned tree of executables (and the manager's prune) outside the mount, and
# MkdirAll cannot see that.
#
# It is a SIBLING of $TOOLS/opt, never a child. $TOOLS/opt belongs to the toolbelt
# engine, whose per-tool prune deletes every version directory under opt/<tool> that
# is not the one it just installed -- so a manifest entry named `kiro-cli` (the engine
# accepts any name, and tools.json is hand-editable) used to be able to delete the
# active kiro-cli and its retained predecessor. $TOOLS/opt itself is still created and
# hardened below: it holds engine binaries that $TOOLS/bin symlinks into and root
# executes.
make_config_dir "$TOOLS/opt"
# The toolbelt engine's two package-manager roots. Created and validated here
# for the same reason $TOOLS/opt is: their bin dirs hold npm -g / uv tool
# launchers that $TOOLS/bin symlinks into and root executes
# (toolbelt install.go npmDir/pythonDir).
make_config_dir "$TOOLS/npm"
make_config_dir "$TOOLS/npm/bin"
make_config_dir "$TOOLS/python"
make_config_dir "$TOOLS/python/bin"
make_config_dir "$TOOLS/kiro-cli-versions"
make_config_dir "$HOME/.local"
make_config_dir "$HOME/.local/bin"
make_config_dir "$HOME/.ssh"
make_config_dir "$HOME/.kiro"
# kiro-cli persists cli.json / mcp.json / permissions.yaml here, and the server's
# settings calls write them as root long before the theme block looks at this path, so
# the symlink rejection has to happen in the walk.
make_config_dir "$HOME/.kiro/settings"

# mkdir -p succeeds when the directories already exist — even on a read-only
# bind mount — so it is NOT proof that /config is writable. Prove it with a
# create+remove probe and fail fast (the documented behavior for an
# unwritable persistent volume) instead of exec'ing a server that cannot install
# kiro-cli or persist anything. Runs BEFORE the chmod pass below: on a
# read-only mount every chmod fails too, and four permission warnings ahead of
# this fatal point the operator at the wrong cause.
if ! probe=$(mktemp "$TOOLS/.write-probe.XXXXXX") || ! rm -f "$probe"; then
  fatal '/config/tools is not writable (read-only bind mount?)'
fi

# Tighten the /config-resident dirs created above (see harden_config_dir for
# why, and for the symlink guard).
harden_config_dir "$HOME/.ssh"
harden_config_dir "$HOME/.kiro/settings"
harden_config_dir "$HOME/.kiro"
harden_config_dir "$HOME/.local"
harden_config_dir "$HOME"

# Same argument one level out, for the tree that holds the first-on-PATH binary
# rather than the credentials (see secure_tools_dir). /config is checked too: a
# writable parent lets an attacker replace $TOOLS wholesale. Runs BEFORE the exec,
# so the taint flag exported below is final by the time the manager reads it and a
# planted version directory on a previously-permissive volume can never be activated
# on the strength of its own sentinel.
secure_tools_dir /config
secure_tools_dir "$TOOLS"
secure_tools_dir "$TOOLS/bin"
secure_tools_dir "$TOOLS/opt"
secure_tools_dir "$TOOLS/kiro-cli-versions"
# Same argument as $TOOLS/opt: a group/other-writable directory here lets a
# foreign host user REPLACE a launcher root runs, which tightening the file
# alone cannot prevent. arm=0 -- neither tree ever holds kiro-cli, so a loose
# mode here is no reason to distrust a version directory and re-download.
secure_tools_dir "$TOOLS/npm" 0 1
secure_tools_dir "$TOOLS/npm/bin" 0 1
secure_tools_dir "$TOOLS/python" 0 1
secure_tools_dir "$TOOLS/python/bin" 0 1
# One level INSIDE the install root: the version directories and the dispatchers they hold.
# The root's own mode says nothing about them, and the manager's remaining gates cannot tell
# the difference -- a `.complete` sentinel is a plain file and a --version probe is satisfied
# by a wrapper -- so a version directory a foreign host user can still rewrite would be
# activated with the taint UNSET. Tighten what we can and ARM the taint, which is this app's
# documented remedy (distrust plus reinstall from the digest-verified archive); warn, never
# fatal, and never delete, per web-terminal-kiro.md "Failure posture". The globs skip
# dot-prefixed staging trees for free (a leading dot is not matched by *), and a symlinked
# entry arms the taint rather than being stat'd through -- but pathname expansion happens
# before the body runs, so the */* glob still expands THROUGH a symlinked level-1 entry and
# yields its children as their own words. The loop therefore REFUSES to traverse a symlink
# rather than merely warning about one: no chmod here can reach a path outside the install
# root, which is the same containment the $TOOLS/bin loop below asserts with realpath.
for version_entry in "$TOOLS/kiro-cli-versions"/* "$TOOLS/kiro-cli-versions"/*/*; do
  # -L BEFORE -e: a DANGLING symlink here is exactly as anomalous as a live one and must
  # arm the taint; [ -e ] dereferences, so testing it first skips a dangling link silently.
  if [ -L "$version_entry" ]; then
    tools_tree_was_writable=1
    printf 'level=warn msg="an entry inside the kiro-cli install root is a symlink; treating every pre-existing version directory as untrusted so the manager reinstalls from the pinned SHA-verified archive" path="%s" component=entrypoint\n' \
      "$(logfmt_value "$version_entry")" >&2
    continue
  fi
  [ -e "$version_entry" ] || continue
  # Never act THROUGH a symlink: the */* glob traverses a symlinked level-1 entry, so a
  # level-2 name can be a regular file OUTSIDE the install root ([ -L ] tests only the FINAL
  # component) and the chmod below would strip write bits from a path this container does not
  # own -- a device node, or a /workspace file whose mode the host operator set. The level-1
  # pass has already armed the taint on that symlink, so skip its children rather than
  # tightening them.
  version_entry_parent=${version_entry%/*}
  if [ "$version_entry_parent" != "$TOOLS/kiro-cli-versions" ] && [ -L "$version_entry_parent" ]; then
    continue
  fi
  version_entry_mode=$(stat -c '%a' "$version_entry" 2>/dev/null) || version_entry_mode=""
  if [ -n "$version_entry_mode" ] && [ $((8#$version_entry_mode & 0022)) -eq 0 ]; then
    continue
  fi
  tools_tree_was_writable=1
  printf 'level=warn msg="an entry inside the kiro-cli install root is group/other-writable or its mode cannot be read; tightening it and treating every pre-existing version directory as untrusted so the manager reinstalls from the pinned SHA-verified archive" path="%s" mode=%s component=entrypoint\n' \
    "$(logfmt_value "$version_entry")" "${version_entry_mode:-unknown}" >&2
  version_entry_chmod_rc=0
  chmod go-w "$version_entry" 2>/dev/null || version_entry_chmod_rc=$?
  # Trust the RESULT, not chmod's status -- the same postcondition secure_tools_dir
  # and the $TOOLS/bin loop below assert, and for the same reason: a bind-mounted or
  # foreign-semantics filesystem (a ZFS inheritable ACL is the case seen here) can
  # acknowledge a chmod without applying it, so a zero status proves nothing. Without
  # this the warn above CLAIMS a tightening and no line ever retracts it, and the
  # identical claim repeats on every boot -- indistinguishable from a fresh
  # occurrence. The taint is already armed above, so the manager reinstalls either
  # way; what is missing is telling the operator their volume will not accept the fix.
  version_entry_mode_after=$(stat -c '%a' "$version_entry" 2>/dev/null) || version_entry_mode_after=""
  if [ -z "$version_entry_mode_after" ] || [ $((8#$version_entry_mode_after & 0022)) -ne 0 ]; then
    printf 'level=warn msg="an entry inside the kiro-cli install root is STILL group/other-writable, or its mode cannot be verified, after tightening; the install manager reinstalls from the pinned archive regardless, but this path stays rewritable by any host user in its group until the volume permissions are fixed" path="%s" mode=%s was=%s chmod_rc=%d component=entrypoint\n' \
      "$(logfmt_value "$version_entry")" "${version_entry_mode_after:-unknown}" "${version_entry_mode:-unknown}" "$version_entry_chmod_rc" >&2
  fi
done
# The Dockerfile's ENV PATH puts ONE more /config-resident dir ahead of /usr/bin
# for the server, its PTY sessions and the toolbelt engine: $TOOLS/go/bin, i.e.
# GOPATH/bin. (The two runtimes/{go,node}/bin segments were dropped from ENV PATH
# once the audit showed both trees held only binaries already resolving through
# $TOOLS/bin -- see the Dockerfile's PATH comment. Nothing hardens them here any
# more: a directory that is not on PATH cannot be the source of a root-executed
# planted binary, so walking it would be theatre.)
# /config and $TOOLS keep their group/other EXECUTE bits above -- secure_tools_dir
# strips only w -- so those dirs stay traversable by a foreign host user, and a
# group/other-writable GOPATH/bin lets that user plant a binary this container then
# runs as root, ahead of /usr/bin, with no --version or sha gate anywhere. Tighten
# the mode; arm=0 because this tree never holds kiro-cli, and owned=0 because the
# entrypoint neither creates nor repairs GOPATH/bin, so an odd shape there is warned
# about rather than fatal (see web-terminal-kiro.md "Failure posture"). Walk
# parent-to-child, matching the /config -> $TOOLS -> $TOOLS/bin chain above: a
# writable PARENT lets a foreign host user replace the leaf bin dir wholesale with a
# clean-mode tree of planted binaries, which the leaf check alone would then pass.
#
# Accepted residual, deliberately not hardened further: `chmod go-w` stops NEW
# directory writes but never re-verifies files already planted while the tree was
# writable, and their owner can keep rewriting them. The alternative -- quarantining
# unrecognized binaries -- would delete the user's own `go install` output, which the
# dev-box posture forbids, and the threat already presupposes an actor holding
# /config/home/.ssh and the auth tokens.
for path_dir in "$TOOLS/go" "$TOOLS/go/bin"; do
  [ -e "$path_dir" ] || [ -L "$path_dir" ] || continue
  secure_tools_dir "$path_dir" 0 0
done
# Directory modes still leave every binary in $TOOLS/bin unexamined -- and this dir
# LEADS PATH for the server, every PTY session and root (Dockerfile ENV PATH). The
# argument the directory checks make applies verbatim to the files: a
# group/other-writable file is rewritable in place with no write access to
# the directory, and the toolbelt engine really does leave group-writable modes on
# some volumes. Tighten what we can. Warn, never fatal, and never quarantine: these
# files are the engine's, it reinstalls what is MISSING, and deleting the operator's
# own tools is the productivity harm the dev-box failure posture forbids.
# stat -L / chmod deliberately DEREFERENCE: $TOOLS/bin is mostly symlinks into the
# engine's opt/<tool>/<ver>/ trees, and the target's mode is the one that decides
# whether a foreign host user can rewrite what root executes.
tightened_tool_bins=0
for tool_bin in "$TOOLS/bin"/*; do
  # An unmatched glob, or a dangling symlink -- nothing that can be executed.
  [ -e "$tool_bin" ] || continue
  # Exactly `kiro-cli` is the server's: the manager publishes ONE convenience
  # symlink at $TOOLS/bin/kiro-cli pointing INTO the active version directory
  # (nothing in the product reads it; it exists so
  # `docker exec … kiro-cli --version` keeps working). Dereferencing it would report
  # on a file the manager owns and re-publishes on every boot, so skip it. The
  # skip is the exact name, NOT a kiro-cli* prefix: this directory is co-owned by
  # the toolbelt engine (which is why main.go's legacy purge names its three
  # dispatcher targets rather than prefix-sweeping here), and the purge is
  # marker-gated to one boot -- so any other kiro-cli-* entry is either the
  # engine's or unaccounted for, and both belong under the rule below.
  case "${tool_bin##*/}" in kiro-cli) continue ;; esac
  tool_bin_mode=$(stat -Lc '%a' "$tool_bin" 2>/dev/null) || tool_bin_mode=""
  if [ -n "$tool_bin_mode" ] && [ $((8#$tool_bin_mode & 0022)) -eq 0 ]; then
    continue
  fi
  # chmod FOLLOWS the symlink, so an entry pointing OUT of the tools tree would have root
  # strip write bits from an unrelated path -- and the only entries that reach here are the
  # ones already carrying a group/other write bit, i.e. device nodes (0666) and shared host
  # directories (0777). A planted `x -> /dev/null` would degrade every process in the
  # container; a link into /workspace would undo a permission the host operator set. Only
  # targets inside $TOOLS are ours to tighten -- the same containment assertion
  # prune_superseded_kas_runtimes makes before it deletes as root.
  tool_bin_real=$(realpath -e "$tool_bin" 2>/dev/null) || tool_bin_real=""
  case "$tool_bin_real" in
    "$TOOLS"/*) ;;
    *)
      printf 'level=warn msg="skipping a group/other-writable tools bin entry whose target resolves outside the tools tree; tightening it would chmod a path this container does not own" path="%s" resolved="%s" mode=%s component=entrypoint\n' \
        "$(logfmt_value "$tool_bin")" "$(logfmt_value "${tool_bin_real:-unknown}")" "${tool_bin_mode:-unknown}" >&2
      continue
      ;;
  esac
  loose_mode=$tool_bin_mode
  chmod_rc=0
  chmod go-w "$tool_bin" || chmod_rc=$?
  # Trust the RESULT, not chmod's status -- the same postcondition secure_tools_dir
  # asserts, and for the same reason: a bind-mounted or foreign filesystem can
  # acknowledge a chmod without applying it, so a zero status proves nothing. A mode
  # that is still loose, or that cannot be re-read at all, stays OUT of the count
  # (chmod_rc separates a refused chmod from a silently ignored one), so the
  # aggregate below is true of every file it counts.
  tool_bin_mode=$(stat -Lc '%a' "$tool_bin" 2>/dev/null) || tool_bin_mode=""
  if [ -z "$tool_bin_mode" ] || [ $((8#$tool_bin_mode & 0022)) -ne 0 ]; then
    printf 'level=warn msg="a binary on the first-on-PATH tools tree is still group/other-writable, or its mode cannot be verified after tightening; a foreign host user could rewrite it in place and this container runs it as root" path="%s" mode=%s was=%s chmod_rc=%d component=entrypoint\n' \
      "$(logfmt_value "$tool_bin")" "${tool_bin_mode:-unknown}" "${loose_mode:-unknown}" "$chmod_rc" >&2
    continue
  fi
  tightened_tool_bins=$((tightened_tool_bins + 1))
done
if [ "$tightened_tool_bins" -ne 0 ]; then
  printf 'level=warn msg="tightened group/other-writable binaries on the first-on-PATH tools tree; they were rewritable in place by any host user in their group" dir="%s" count=%d component=entrypoint\n' \
    "$TOOLS/bin" "$tightened_tool_bins" >&2
fi

# Hand the taint observation to the manager. The directories are private NOW, but
# anything already inside a tree that was group/other-writable was writable by another
# host user -- and the manager accepts an existing version directory on the strength of
# its own `.complete` sentinel, which such a user could have written. With this set the
# manager activates only a version IT installed from a digest-verified archive this
# boot. It crosses the boundary as an env var because the observation is only available
# here, before the exec, and losing it would leave a forged sentinel trusted.
KIRO_CLI_TOOLS_TAINTED="$tools_tree_was_writable"
export KIRO_CLI_TOOLS_TAINTED
if [ "$tools_tree_was_writable" -eq 1 ]; then
  printf 'level=warn msg="the tools tree was group/other-writable; telling the install manager to distrust every kiro-cli version directory already on the volume and reinstall from the pinned SHA-verified archive" dir="%s" component=entrypoint\n' "$TOOLS" >&2
fi

# Best-effort: drop the write probe orphaned by a hard container kill. The ordinary
# path removes it in its own test, so this only catches SIGKILL residue. The kiro-cli
# staging trees are NOT swept here any more: they live under the manager's own
# installation root, dot-prefixed, and the manager removes them before it selects a
# version -- sweeping them from this script would race a concurrent install.
# `rm -rf` on an unmatched glob is already a silent no-op returning 0 (-f suppresses
# the missing-path diagnostic), so a non-zero status here is a REAL failure -- an
# immutable attribute, EPERM, a submount -- against the one thing this sweep exists to
# protect. Warn like both sibling sweeps (sweep_legacy_dispatchers,
# prune_superseded_kas_runtimes) instead of discarding it.
if ! rm -rf "$TOOLS"/.write-probe.*; then
  printf 'level=warn msg="failed to remove orphaned boot-time temp artifacts; they keep occupying the /config volume" dir="%s" component=entrypoint\n' "$TOOLS" >&2
fi

# Point out tool metadata still sitting at its pre-$TOOLS location, which nothing
# reads any more (see warn_legacy_tool_metadata). Placed here, after the walk proved
# $TOOLS is a real private directory, so the new path the message names is the one
# the server will actually hand the engine. Reads three directory entries and
# prints; it moves, deletes and creates nothing.
warn_legacy_tool_metadata /config "$TOOLS"

# Hygiene for the one residue class the manager's own purge does not reach: binaries an
# EARLIER image version staged into $HOME/.local/bin (that install ran with the real
# HOME; the manager stages under a private HOME beneath $TOOLS). Tens of MB on /config,
# and an unpinned binary on PATH. Warn, don't exit: every session leads its PATH with
# the active version's directory, so nothing here can shadow the pinned CLI -- this is
# hygiene, not an integrity gate.
sweep_legacy_dispatchers "$HOME/.local/bin"

# Reclaim superseded kiro-cli agent runtimes. This stays in the entrypoint rather than
# moving into the server with the installer, for three reasons: the kas store is a
# SEPARATE object (kiro-cli's own data dir, not the install tree) with its own
# containment guards; it is keyed on the pin, which this script still declares; and
# running it here, before the server binds, is what keeps peak disk at ONE tree -- the
# new tree is unpacked by the binary on its first chat launch, long after this script
# is gone.
#
# The keep-key is the PIN, not the version that ends up active. The manager can fall
# back to a retained predecessor when the pinned install fails, and that predecessor's
# tree will already have been pruned here; the cost is one ~240 MB re-unpack on its
# first chat launch, paid only on a boot whose install failed. The alternative -- moving
# the prune after the manager's selection -- would put it after the listener binds and
# after the first session can start, so two trees could coexist on the routine bump
# path. One tree at peak on every boot beats a rare re-unpack.
printf 'level=info msg="pruning superseded kiro-cli agent runtimes" keep=%s component=entrypoint\n' "$KIRO_CLI_VERSION" >&2
prune_superseded_kas_runtimes "$KIRO_CLI_VERSION"

# OS packages (APT_PACKAGES env, e.g. "python3 gcc libc6-dev"). apt state
# lives in the ephemeral container layer — never on /config — so it is
# re-applied on every container start: compose-level intent, not volume
# intent. Everything else in /config/tools is owned by the server's
# toolbelt engine (manifest: /config/tools/tools.json v2), which converges in
# the background after the listener binds; session creation waits on it
# so kiro-cli never scans PATH before the manifest's tools are present.
#
# Validation is two-stage, and the stages answer different questions:
# the grammar rejects tokens that are not shaped like a package name (so env
# content cannot smuggle apt options, a `pkg=version` pin, `pkg:arch`, or the
# `pkg-` REMOVE form), while the known-name gate rejects tokens that are not
# ACTUALLY packages. `apt-get update` is REQUIRED before either install or the
# gate because the image deletes the package indexes at build time.
# Warn-not-fail preserves the degraded-boot posture throughout.
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
      warn_skipped_apt_token 'skipping invalid APT_PACKAGES token' "$pkg"
    fi
  done
  set +f
  if [ "${#apt_pkgs[@]}" -gt 0 ]; then
    # Refresh the indexes on their OWN deadline, before the known-name gate that
    # reads them. Splitting update from install also makes an exhausted deadline
    # attributable: previously one 600s budget covered both, so a timeout could
    # not say which half consumed it. 300s rather than a tight bound for the same
    # reason the kiro-cli download uses stall detection: a deadline sized for a
    # fast link is a bandwidth floor in disguise.
    apt_update_rc=0
    printf 'level=info msg="refreshing apt indexes for APT_PACKAGES" component=entrypoint\n' >&2
    timeout --signal=TERM --kill-after=30s 300s apt-get update -qq || apt_update_rc=$?
    if [ "$apt_update_rc" -eq 124 ] || [ "$apt_update_rc" -eq 137 ]; then
      # 124/137 = the 300s deadline (TERM, then the --kill-after SIGKILL fallback),
      # named distinctly for the same reason every sibling timeout here does: a
      # stalled mirror and an index apt rejected outright call for different
      # operator action, and the generic wording cannot tell them apart.
      printf 'level=warn msg="apt-get update exceeded its 300s deadline and was terminated; APT_PACKAGES install may fail and the known-name check runs against whatever index survived" rc=%d component=entrypoint\n' "$apt_update_rc" >&2
    elif [ "$apt_update_rc" -ne 0 ]; then
      printf 'level=warn msg="apt-get update failed; APT_PACKAGES install may fail and the known-name check runs against whatever index survived" rc=%d component=entrypoint\n' "$apt_update_rc" >&2
    fi

    # Known-name gate. The grammar above is only a PROXY for "is this a real
    # Debian package name", and apt-get has a third interpretation layer the proxy
    # cannot express: a token containing '.', '?' or '*' that matches no literal
    # package is retried as an UNANCHORED REGEX over every package name. Measured
    # on apt 3.0.3 (trixie's major): `apt-get install -s -- 'jq.'` plans 337
    # packages. So one grammar-valid operator typo (python3., libssl.) turns this
    # install-only path into an unbounded root install into the container layer,
    # re-run on every start. '.' cannot leave the grammar (python3.13, docker.io
    # are real names) and apt-get has no flag to disable the fallback, so the fix
    # is to stop handing apt anything that is not already known to be a literal
    # package name: a token that survives this gate cannot reach the regex path.
    #
    # apt-cache pkgnames is the only safe oracle here. `apt-cache show`, `policy`
    # and `showpkg` ALL regex-expand (verified: `showpkg -- 'jq.'` reports
    # libjs-jquery.sparkline) and return rc=0 for names that do not exist, so none
    # of them can answer "does this literal name exist".
    #
    # Known limit: pkgnames omits PURE VIRTUAL names (awk, provided by mawk/gawk
    # but never a real package), so such a token is skipped here. Acceptable, and
    # the warning says so: `apt-get install awk` fails on its own anyway, because a
    # multi-provider virtual has no installation candidate. Naming a concrete
    # provider is the fix in both cases, and the warning is clearer than apt's.
    #
    # The gate is ATTEMPTED even when apt-get update failed, and that ordering is
    # the safety property, not an optimization. The reachable failure is a PARTIAL
    # refresh (some mirrors fine, non-zero exit, index still usable), and every
    # name such an index yields still comes from real repository metadata -- so an
    # incomplete index can only produce false NEGATIVES (a valid package it does
    # not list is skipped and installs on a later boot), never a false positive
    # that admits a token to apt's regex path. The character fallback below is
    # therefore the LAST resort, reached only when this oracle is unusable.
    apt_gate_ran=0
    apt_names=$(mktemp) || apt_names=''
    # Bounded like every other external call in this foreground path: this runs
    # before any listener exists, so an index apt cannot read through (corrupt or
    # partially-written cache, very slow storage) would otherwise stall boot with
    # no deadline and no diagnostic -- the container would sit in starting/
    # unhealthy forever, and restart:unless-stopped never acts because nothing
    # exited. A killed probe leaves apt_gate_ran=0, which the narrowing below
    # already handles exactly as it handles an unreadable index.
    apt_names_rc=0
    if [ -n "$apt_names" ]; then
      timeout --signal=TERM --kill-after=10s 60s apt-cache pkgnames >"$apt_names" 2>/dev/null || apt_names_rc=$?
    else
      apt_names_rc=1
    fi
    if [ "$apt_names_rc" -eq 124 ] || [ "$apt_names_rc" -eq 137 ]; then
      # 124/137 = the 60s deadline (TERM, then the --kill-after SIGKILL fallback),
      # named distinctly from the generic unreadable-index warning for the same
      # reason the sibling timeouts are: a wedged cache and an index apt rejected
      # outright call for different operator action.
      printf 'level=warn msg="apt-cache pkgnames exceeded its 60s deadline and was terminated; falling back to the expansion-character filter for APT_PACKAGES" rc=%d component=entrypoint\n' "$apt_names_rc" >&2
    fi
    # Usable means exactly this: the command succeeded AND produced a non-empty
    # name list. Anything else (non-zero exit, deadline kill, empty output, no
    # temp file to capture into) is unusable and falls through to the filter.
    if [ "$apt_names_rc" -eq 0 ] && [ -s "$apt_names" ]; then
      apt_gate_ran=1
      known_pkgs=()
      for pkg in "${apt_pkgs[@]}"; do
        if grep -qxF -- "$pkg" "$apt_names"; then
          known_pkgs+=("$pkg")
        else
          warn_skipped_apt_token 'skipping unknown APT_PACKAGES token (no such package; a pure virtual package needs a concrete provider)' "$pkg"
        fi
      done
      apt_pkgs=("${known_pkgs[@]}")
    elif [ -z "$apt_names" ]; then
      # The index may be perfectly readable: what failed is creating the file to
      # capture the name list into. Named separately for the same reason the
      # deadline warnings are -- an unwritable container temp dir and an index apt
      # cannot read call for different operator action.
      printf 'level=warn msg="could not create the temp file for the apt known-name check (is the container temp dir writable?); falling back to the expansion-character filter for APT_PACKAGES" component=entrypoint\n' >&2
    elif [ "$apt_names_rc" -ne 124 ] && [ "$apt_names_rc" -ne 137 ]; then
      printf 'level=warn msg="apt package index unreadable; falling back to the expansion-character filter for APT_PACKAGES" component=entrypoint\n' >&2
    fi
    [ -z "$apt_names" ] || rm -f "$apt_names"

    # Whenever the gate could NOT run -- an unusable oracle, whatever cost it (a
    # failed apt-get update that also left no readable index, a corrupt cache, a
    # killed probe) -- skipping it is still the right failure mode: rejecting every
    # token would turn a transient problem into "none of your packages installed"
    # plus a misleading per-token typo warning, and the grammar still holds. But
    # the pre-gate behaviour is exactly what leaves the 337-package regex blowup
    # described above reachable, so it degrades with ONE narrowing.
    #
    # The narrowing drops every token containing '.' or '+', which is the COMPLETE
    # set of apt expansion characters the grammar admits ('?' and '*' are outside
    # its character class, and a trailing '-' -- apt's remove form -- is already
    # rejected by the grammar; an internal '-' has no special interpretation).
    # Both are live: '.' is any-character and '+' is one-or-more, so `jq++`,
    # `libjq+1` and `libj+q1` ALL regex-resolve to real packages (measured on apt
    # 3.0.3, trixie's major) -- a '+' anywhere in the token is enough, this is not
    # only a trailing-suffix concern. Dropping just these removes the blowup while
    # every plain name still installs, which is the common case and the reason the
    # skip-everything option was rejected.
    #
    # Handled here rather than inside the gate's branches so every way of losing
    # the gate lands on the same rule and they cannot drift apart.
    #
    # The cost is narrow and self-healing: a real name carrying one of these
    # characters (docker.io, python3.13, g++) waits for a boot whose index answers,
    # which is a boot where the install was going to be unreliable anyway. Per "a
    # broken state must be able to heal itself", the next boot's gate installs it —
    # and because the gate is now attempted even after a failed update, a partial
    # index is usually enough to install it on THIS boot.
    if [ "$apt_gate_ran" -eq 0 ] && [ "${#apt_pkgs[@]}" -gt 0 ]; then
      ungated_pkgs=()
      for pkg in "${apt_pkgs[@]}"; do
        if [[ "$pkg" == *.* || "$pkg" == *+* ]]; then
          warn_skipped_apt_token 'skipping unverifiable APT_PACKAGES token containing an apt expansion character (. or +) while the known-name check is unavailable; retry once the package index is readable' "$pkg"
        else
          ungated_pkgs+=("$pkg")
        fi
      done
      apt_pkgs=("${ungated_pkgs[@]}")
    fi
  fi
  if [ "${#apt_pkgs[@]}" -gt 0 ]; then
    # A SIGKILL landing inside the install deadline (docker stop during the
    # foreground window; this shell defers SIGTERM until the child returns) leaves
    # dpkg interrupted, and apt state is container-layer state that SURVIVES
    # docker start -- so every later boot would refuse the install with rc=100 and
    # no package would ever be installed again for this container's life. Reconfigure
    # once, bounded, warn-only: the state is either absent (a no-op) or the only
    # thing standing between the operator and their packages.
    #
    # The AUDIT OUTPUT is the primary evidence, not the exit status: `dpkg --audit`
    # returns 0 while REPORTING unpacked-but-unconfigured packages (measured: 464
    # bytes on stdout, rc=0), which is the ordinary interrupted state this recovery
    # exists for -- gating on rc alone would never fire on it. A healthy tree prints
    # nothing at all, so non-empty output cannot false-positive here. The updates
    # journal stays a third trigger: it is evidence of a transaction killed even
    # earlier, before any package reached the unpacked state.
    dpkg_audit_rc=0
    dpkg_audit_out=$(timeout --signal=TERM --kill-after=30s 300s dpkg --audit 2>/dev/null) || dpkg_audit_rc=$?
    # Bounded for the log line: audit output is short in practice, and a truncated
    # first line is enough to tell an operator WHICH interrupted state was seen.
    dpkg_audit_summary=$(printf '%s' "${dpkg_audit_out:0:400}" | tr '\n' ' ')
    if [ "$dpkg_audit_rc" -ne 0 ] || [ -n "$dpkg_audit_out" ] \
      || [ -n "$(ls -A /var/lib/dpkg/updates 2>/dev/null)" ]; then
      printf 'level=warn msg="dpkg is in an interrupted state (an earlier APT_PACKAGES install was killed mid-transaction); reconfiguring before installing" audit_rc=%d audit="%s" component=entrypoint\n' \
        "$dpkg_audit_rc" "$(logfmt_value "$dpkg_audit_summary" 400)" >&2
      dpkg_fix_rc=0
      timeout --signal=TERM --kill-after=30s 300s dpkg --configure -a || dpkg_fix_rc=$?
      if [ "$dpkg_fix_rc" -ne 0 ]; then
        printf 'level=warn msg="dpkg --configure -a failed; APT_PACKAGES will keep failing until the container is recreated" rc=%d component=entrypoint\n' "$dpkg_fix_rc" >&2
      fi
    fi
    printf 'level=info msg="installing OS packages" packages="%s" component=entrypoint\n' "${apt_pkgs[*]}" >&2
    # Called directly rather than through `bash -c`: with update split out there is
    # nothing left to chain, and one less shell between env content and apt is one
    # less layer that could reinterpret a token.
    timeout --signal=TERM --kill-after=30s 600s apt-get install -y -qq --no-install-recommends -- "${apt_pkgs[@]}"
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
  fi
  # Reclaim the indexes whenever this block refreshed them, whether or not anything
  # was ultimately installed (every token may have been skipped).
  if [ "${apt_update_rc:-1}" -eq 0 ]; then
    rm -rf /var/lib/apt/lists/*
  fi
fi

# Hardcode dark theme. kiro-cli's "default" diff preset resolves
# added-line bg to #00FF00 through the truecolor path — unreadable.
# Pinning both baseTheme and diffPreset to "dark" avoids this.
theme_dir="$HOME/.kiro/settings"
theme_file="$theme_dir/kiro_cli_theme.json"
theme_tmp=''
# Re-validate immediately before the first write here, even though the boot-time walk
# above already created this path (make_config_dir "$HOME/.kiro/settings") and put it
# at 0700 (harden_config_dir "$HOME/.kiro/settings") -- so the mkdir below is a no-op
# on every normal boot and 0700 is enforced ON THIS DIRECTORY, not merely inherited
# from the 0700 ~/.kiro parent. The re-check is deliberate defence for the write
# itself: mkdir -p FOLLOWS a symlink at settings/, and the mktemp + mv below create
# and replace a FIXED-NAME file through it, in the directory where kiro-cli persists
# mcp.json (remote MCP server URLs and tokens). A symlink here is fatal (its target
# may be outside the /config mount); a failed mkdir stays a warn, because the theme is
# cosmetic -- unreadable diff colors, not a broken boot.
if [ -L "$theme_dir" ]; then
  fatal 'refusing to write kiro-cli settings through a symlinked settings directory; its target may be outside the /config mount' "dir=\"$theme_dir\""
fi
if ! mkdir -p "$theme_dir"; then
  printf 'level=warn msg="failed to create kiro-cli settings directory; theme not written and diff colors may be unreadable" dir="%s" component=entrypoint\n' "$theme_dir" >&2
else
  harden_config_dir "$theme_dir"
  if ! theme_tmp=$(mktemp "${theme_file}.XXXXXX") \
    || ! printf '{"baseTheme":"dark","diffPreset":"dark"}\n' >"$theme_tmp" \
    || ! mv "$theme_tmp" "$theme_file"; then
    [ -z "${theme_tmp:-}" ] || rm -f "$theme_tmp"
    printf 'level=warn msg="failed to write kiro-cli theme file; diff colors may be unreadable" file="%s" component=entrypoint\n' "$theme_file" >&2
  fi
fi

# Seed the kiro-cli hook that reports which kiro session each tab is running.
#
# This is the mapping half of the tab-title feature (sessiontitle.go). The server
# injects KWEB_SESSION_ID + KWEB_TITLE_STATE_DIR into each PTY session, and this hook
# — a descendant of that session, handed kiro's own session_id on stdin — writes the
# pair where the server reads it. Without it every tab falls back to the engine's
# automatic cwd/process name ladder, which is a degraded label rather than a failure.
#
# Rewritten on EVERY boot rather than created-if-missing, so an image upgrade updates
# the hook and a deleted or edited file self-heals. Global hooks (~/.kiro/hooks) load
# in every workspace, which is what makes this reach a session whatever directory it
# starts in; the script itself no-ops when KWEB_SESSION_ID is absent, so an operator
# running kiro-cli from `docker exec` is unaffected.
#
# Symlink handling follows the theme block above for the same reason: this writes a
# FIXED-NAME file through the path, in the tree where kiro-cli persists mcp.json, so a
# symlink whose target may be outside the /config mount is fatal. A failed mkdir stays
# a warn -- a missing hook costs a tab label, not a boot.
hooks_dir="$HOME/.kiro/hooks"
hooks_file="$hooks_dir/web-terminal-session-title.json"
hooks_tmp=''
if [ -L "$hooks_dir" ]; then
  fatal 'refusing to write kiro-cli hooks through a symlinked hooks directory; its target may be outside the /config mount' "dir=\"$hooks_dir\""
fi
if ! mkdir -p "$hooks_dir"; then
  printf 'level=warn msg="failed to create kiro-cli hooks directory; tab titles fall back to the automatic name ladder" dir="%s" component=entrypoint\n' "$hooks_dir" >&2
else
  harden_config_dir "$hooks_dir"
  if ! hooks_tmp=$(mktemp "${hooks_file}.XXXXXX") \
    || ! printf '{"version":"v1","hooks":[{"name":"web-terminal-session-title","trigger":"SessionStart","action":{"type":"command","command":"%s"}},{"name":"web-terminal-session-title-prompt","trigger":"UserPromptSubmit","action":{"type":"command","command":"%s"}}]}\n' \
      "$SESSION_TITLE_HOOK" "$SESSION_TITLE_HOOK" >"$hooks_tmp" \
    || ! mv "$hooks_tmp" "$hooks_file"; then
    [ -z "${hooks_tmp:-}" ] || rm -f "$hooks_tmp"
    printf 'level=warn msg="failed to write the kiro-cli session-title hook; tab titles fall back to the automatic name ladder" file="%s" component=entrypoint\n' "$hooks_file" >&2
  fi
fi

# Hand the image's PATH back so the server and its PTY sessions keep the engine-managed
# /config/tools/bin first, as the Dockerfile ENV and the toolbelt engine expect. Each
# PTY session additionally gets the ACTIVE kiro-cli version directory prepended by the
# server, which is what makes bare-name `kiro-cli` and its sidecar resolve to the pinned
# install regardless of what else is on this PATH.
#
# The carry variable is dropped here rather than inherited: it exists only to survive the
# setpriv re-exec above, and nothing past this point re-execs this script, so leaving a
# second copy of PATH in the environment of the server and every terminal session would be
# noise an operator could mistake for a knob.
PATH="$SESSION_PATH"
export PATH
unset KWEB_SESSION_PATH
# Same reason as the PATH carry above, and the same lifetime: this is the setpriv
# re-exec marker, meaningful only until that exec has happened. Nothing past this
# point re-execs this script and no Go code reads it, so leaving it exported would
# advertise an internal control-flow flag to the server and every terminal session
# as though it were a supported knob.
unset KWEB_CONTAINMENT_CAPS_DROPPED
printf 'level=info msg="entrypoint complete; starting the web server" component=entrypoint\n' >&2
exec /app/web-terminal-kiro
