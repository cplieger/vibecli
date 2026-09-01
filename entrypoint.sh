#!/bin/bash
# Prepares persistent user/tool state, hardens paths root executes from,
# prunes superseded KAS runtimes, seeds the Kiro theme and session-title
# hook, prepares per-session containment, exports the Renovate-pinned
# kiro-cli version and digests, and execs the Go web server.
#
# Does NOT install kiro-cli: the server owns that (cplieger/pinstall,
# wired in main.go), after the listener binds, so a slow first-boot
# download answers 503 instead of refusing connections. Fetched at
# runtime rather than baked into the image because we do not redistribute
# proprietary AWS Content; the user accepts the license on first boot.

set -u

# Must NOT resolve this script's own commands through /config/tools/bin: it
# leads PATH and lives on the persistent mount, so on a volume that ever
# permitted group/other writes a planted binary there would be the oracle
# every directory check below trusts.
#
# The narrowed PATH is captured into WT_SESSION_PATH (its own var, exported)
# because the containment block below re-execs this script via setpriv, and a
# plain SESSION_PATH="$PATH" would capture the ALREADY-NARROWED value on the
# second invocation -- handing the server a PATH with none of the
# /config-resident tool dirs (measured on borgcube: toolbelt's npm/uv
# unreachable by bare name, /api/health "degraded" while tools were fine).
# Deriving from WT_SESSION_PATH when already set makes the capture idempotent
# across re-execs. Restored for the exec'd server at the bottom, then unset --
# not an operator knob. Pinned by tests/shell/session_path_test.sh, which also
# covers why the save/narrow pair cannot move below the containment block
# (that block's own mount/setpriv/awk would then resolve through the tainted
# dir too).
SESSION_PATH="${WT_SESSION_PATH:-$PATH}"
export WT_SESSION_PATH="$SESSION_PATH"
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

TOOLS="/config/tools"

# Derived from this script's own location (Dockerfile COPY destination),
# rather than a literal, so the two cannot drift apart.
SESSION_TITLE_HOOK="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/hooks/session-title.sh"

# Log a fatal boot error, then throttle the restart:unless-stopped crash loop
# before failing. $2 carries any extra structured fields, already formatted.
fatal() {
  printf 'level=error msg="%s" %scomponent=entrypoint\n' "$1" "${2:+$2 }" >&2
  sleep 10
  exit 1
}

# Makes a value this script did not author safe inside a quoted logfmt
# field: an attacker-chosen filename off the /config bind mount could
# otherwise close the field early and append forged logfmt keys. Bounds the
# raw length first ($2, default 200) before doubling backslashes, so
# truncation cannot split a `\\` pair and leave an escaping trailing
# backslash.
logfmt_value() {
  local raw=$1 safe
  safe=${raw:0:${2:-200}}
  safe=${safe//\\/\\\\}
  safe=${safe//[![:print:]]/?}
  safe=${safe//\"/\'}
  printf '%s' "$safe"
}

# Warns on a non-root run instead of failing: the image is root-by-design (the
# Dockerfile repoints root's /etc/passwd home to /config/home so OpenSSH's
# getpwuid()-based "~" finds the persisted ~/.ssh), and a compose `user:` line
# selects a UID with no passwd entry rather than a supported mode. Degraded, not
# impossible: /config stays writable and the terminal still serves, only the
# getpwuid-dependent and root-only paths break -- outside both cases "Failure
# posture" reserves fatal for. Said HERE, before any of the four resulting
# failures (ssh, make_config_dir, apt, containment pre-flight) can each blame
# something else instead of the `user:` line.
#
# uid/gid are parameters rather than reads of $EUID so the branch is testable.
# Always returns 0: nothing consumes the verdict.
warn_if_not_root() {
  local uid=${1:-$EUID} gid=${2:-${GROUPS[0]:-unknown}}
  if [ "$uid" -eq 0 ]; then
    return 0
  fi
  # Single-quoted inside the hint: logfmt closes a field on the first unescaped double quote.
  printf 'level=warn msg="running as a non-root user, but this image is root-by-design; several subsystems will fail" uid=%s gid=%s hint="%s" component=entrypoint\n' \
    "$uid" "$gid" \
    'git and gh over ssh fail with '\''No user exists for uid'\'' because only root has a passwd entry pointing at /config/home; apt installs cannot run; session containment cannot engage (dropping CAP_SYS_ADMIN needs CAP_SETPCAP); and the /config mode hardening cannot chmod paths this UID does not own. Remove the user: line from the compose service. See the README run block.' >&2
  return 0
}

warn_if_not_root

# Remounts the container's own cgroup tree rw so the server can put each tab's
# kiro-cli process tree in its own cgroup, then this script drops the
# capability that made the remount possible before running anything else.
#
# kiro-cli's KAS process calls setsid(), leaving both the process group and
# session, so neither a group-scoped kill nor the PTY-close SIGHUP can reach
# it -- measured leak: 13 stranded processes holding 1.35 GB across two tabs.
# Engine v3.6.0's marker-based session reaping now closes that leak with no
# host support at all; what containment adds ON TOP is per-session peak
# stats (mem_peak_bytes, tasks_peak) and a kill domain a scrubbed-environment
# descendant cannot escape. Keep this in step with startContainment's doc
# comment in main.go.
#
# Docker mounts /sys/fs/cgroup read-only with no option to change that, so a
# one-time remount is the established workaround. It needs CAP_SYS_ADMIN to
# opt in; the public compose example grants no capability (the ordinary
# refusal path below), while the homelab deployment carries cap_add:
# [SYS_ADMIN] and takes the remount path.
#
# WARN, never fatal: without containment the server still serves terminals
# exactly as before the feature existed.
enable_session_containment() {
  # cg_root is a parameter, matching warn_if_not_root's uid/gid, so a unit test
  # can hand it a temp dir instead of the host's real /sys/fs/cgroup.
  local cg_root=${1:-/sys/fs/cgroup} mount_err
  if ! mount_err=$(mount -o remount,rw "$cg_root" 2>&1); then
    # Carry mount's own error into the warn: it is the only discriminator between
    # "add the capability" and "this host cannot do this at all". Sanitized
    # through the shared logfmt_value; the newline flatten is a presentation
    # choice, done before the call so the RAW value is bounded first.
    mount_err=$(logfmt_value "${mount_err//$'\n'/ }")
    printf 'level=warn msg="cannot remount /sys/fs/cgroup rw; per-session containment cannot engage, so per-session peak memory and task counts will not be reported. Closed-tab process trees are still reaped without it" error="%s" hint="OPTIONAL: add cap_add: [SYS_ADMIN] to the compose service to enable containment; the server and every terminal session drop the capability immediately after this remount. The grant is not fully transient: the container init at PID 1 keeps it for the container lifetime (inert -- it executes nothing; reaching its capability set needs code execution as root INSIDE the container, which is what this terminal already hands to anyone who can reach the port), docker exec processes receive it, and the widened seccomp profile persists. Not granted by default, because marker-based session reaping in the engine closes the process leak without it" component=entrypoint\n' "$mount_err" >&2
    return 1
  fi
  # Report ONLY what the remount proved, never that containment itself is
  # available: an earlier "per-session process containment available" wording
  # once claimed a state the remount alone cannot prove (measured on borgcube
  # 2026-08-06: the server failed 6s later with an EBUSY every session ran
  # uncontained under, while that line said the feature was on). The server
  # logs the real verdict at startup either way (containment status, or
  # startContainment's warn naming the reason) -- read that line, not this one.
  #
  # Vacating the cgroup root deliberately does NOT happen here. An earlier
  # attempt to do it from this script BROKE containment: cgroup v2 forbids
  # enabling a controller on a cgroup still holding member processes, and the
  # engine's own NewContainment.vacateRoot already handles that by moving every
  # pid into its "wt-server" leaf before writing cgroup.subtree_control. An
  # entrypoint-created leaf here would instead make verifyOwnRoot (step 2)
  # refuse the WHOLE root as soon as it holds a child not prefixed "wt-",
  # disabling containment on hosts where it would otherwise work.
  printf 'level=info msg="cgroup tree remounted rw, which is the only step here that needs privilege; whether per-session process containment engages is decided and logged by the server at startup" component=entrypoint\n' >&2
  return 0
}

# One remount, then drop the capability that allowed it, as early as possible:
# the server this script execs installs packages from the network (kiro-cli's
# archive, any `apt:` tool entry), and holding the broadest capability there
# to buy a single mount call would be a bad trade. The window is per-process
# (the container init at PID 1 keeps the capability for the container's
# life), so this protects the processes that execute terminal input -- the
# server and every PTY session.
#
# Must stay BELOW enable_session_containment's definition: bash resolves a
# function at call time, so a call placed above it fails silently ("command
# not found", swallowed by `|| true`), and containment is never enabled with
# no visible error.
#
# Safe to run unconditionally: setpriv exits 0 dropping a capability the
# container never had, and is idempotent if reached twice. The marker is an
# env var rather than an argv flag so "$@" reaches the server untouched.
if [ "${CONTAINMENT_CAPS_DROPPED:-}" != "1" ]; then
  enable_session_containment || true
  export CONTAINMENT_CAPS_DROPPED=1
  # PRE-FLIGHT the drop before committing: this is an `exec`, so a setpriv
  # that fails here ends the container rather than degrading it. Two known
  # failure causes on an image this one does not control -- setpriv absent
  # from a hand-built variant, and dropping from the BOUNDING set needing
  # CAP_SETPCAP, which a reduced-capability or non-root container lacks
  # ("setpriv: apply bounding set: Operation not permitted").
  if setpriv --bounding-set=-sys_admin --inh-caps=-sys_admin -- true 2>/dev/null; then
    exec setpriv --bounding-set=-sys_admin --inh-caps=-sys_admin -- "$0" "$@"
  fi
  # The drop is impossible here. If the capability is not actually HELD (the
  # public compose example), this is the ordinary degraded path: warn and
  # continue with containment off. If it IS held but undroppable, continuing
  # would run the server and every terminal with CAP_SYS_ADMIN for the
  # container's life -- a security regression this whole re-exec exists to
  # avoid, so it is one of the two cases "Failure posture" reserves fatal for.
  if [ "$((0x$(awk '$1 == "CapEff:" { print $2 }' /proc/self/status) & (1 << 21)))" -ne 0 ]; then
    fatal "CAP_SYS_ADMIN is held and cannot be dropped; refusing to run the server and terminal sessions with it" \
      'hint="setpriv could not drop the bounding set (needs CAP_SETPCAP). Remove cap_add: [SYS_ADMIN] from the compose service to run without containment."'
  fi
  printf 'level=warn msg="CAP_SYS_ADMIN not held and containment unavailable; continuing without it" component=entrypoint\n' >&2
fi

# Creates ONE level of a persistent directory and proves the created path is a
# real directory rather than a symlink, before anything is written to or
# deleted beneath it. `mkdir -p a/b/c` FOLLOWS a symlink at any component, so
# creating a deep path in one call would silently accept a planted link and
# every later step would act on the link's TARGET (e.g. the $HOME/.local/bin
# legacy sweep's `rm -rf`). Checking only the parent cannot constrain a
# symlink AT the child, which is why callers walk the chain parent-to-child.
# Mode enforcement is harden_config_dir / secure_tools_dir, applied by callers
# after this walk.
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

# Enforces 0700 on one /config-resident directory. mkdir -p creates new dirs
# umask-wide (root umask 022 -> 0755) and leaves an existing dir's mode alone;
# these dirs live on the /config host bind mount, where a wider mode lets
# other host users read credential-bearing material (ssh keys, mcp.json
# tokens, .netrc/credential stores). The POSTCONDITION is enforced, not
# merely attempted: a symlink is fatal, and boot fails unless the final mode
# has every group/other bit clear (survivable only when stat then proves the
# mode is already private, for a mount whose chmod acknowledges without applying).
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
# $TOOLS/bin leads PATH and the version-addressed install root sits beside it
# at $TOOLS/kiro-cli-versions, so the tree HOLDING kiro-cli is part of the
# integrity story, not just the download: the install manager accepts an
# already-present version directory on the strength of its own `.complete`
# sentinel, which is trivially forgeable, unlike a digest. If an inherited
# /config volume ever permitted group/other writes, another host user could
# plant a version directory and be launched as root.
# So: refuse symlinks, strip group/other write bits, fail boot if they
# survive, and remember that the tree WAS writable so the taint flag exported
# below tells the manager to trust no pre-existing version directory.
tools_tree_was_writable=0
# $2 (default 1) arms the taint flag when the dir was writable. Pass 0 for a PATH
# segment that never holds kiro-cli.
secure_tools_dir() {
  local dir=$1 arm=${2:-1} owned=${3:-1} mode
  # `owned` decides what an UNRECOVERABLE state costs, per web-terminal-kiro.md
  # "Failure posture": this is a dev-box container the operator is expected to
  # reshape, so a broken state must heal itself or be fixable from inside it.
  #   owned=1  the NINE directories this entrypoint creates itself (the
  #            make_config_dir list outside $HOME). The entrypoint creates
  #            them (so a symlink or plain file there is unambiguously
  #            anomalous) and a reinstall repairs them (toolbelt/kiro-cli
  #            manager reinstall what is missing), so a refusal costs a
  #            download, not data. Fatal.
  #   owned=0  $TOOLS/go and $TOOLS/go/bin (GOPATH/bin and its parent): on
  #            PATH but never created or repaired here, holding no
  #            integrity-gated binary. Warn and skip.
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
# created by one can still hold kiro-cli dispatchers in $HOME/.local/bin, which
# is on PATH -- an UNPINNED BINARY REACHABLE BY BARE NAME, not merely wasted
# disk. The install manager stages under a private HOME and publishes by
# rename, so it never writes there; this sweep covers pre-existing volumes and
# an installer resolving its prefix via getpwuid rather than $HOME. The
# manager owns the matching sweep of $TOOLS/bin (and republishes the
# convenience symlink there), so this script must not touch that dir.
#
# rm -rf, not rm -f: `rm -f` fails on a directory, which would turn a hygiene
# step into a boot failure at any caller that checked the status. The return
# is always 0 regardless: rm's exit status answers "did the unlink succeed",
# never "is an unpinned kiro-cli still reachable" -- and shadowing is a
# non-event now for a reason external to this function (every session leads
# PATH with the active version's own directory), not because this sweep ran.
#
# Takes ONE directory, deliberately: the only residue dir in this script's
# remit is $HOME/.local/bin, since $TOOLS/bin is the manager's.
sweep_legacy_dispatchers() {
  local dir=${1:-}
  # Never expand to /kiro-cli* on an unset/empty argument.
  [ -n "$dir" ] || return 0
  if ! rm -rf "$dir/kiro-cli"*; then
    printf 'level=warn msg="failed to remove legacy kiro-cli residue" dir="%s" component=entrypoint\n' "$dir" >&2
  fi
  return 0
}

# Reclaims the one install residue the two bin-dir sweeps cannot see:
# kiro-cli's own agent-server runtimes. Each version unpacks a ~240 MB tree
# under <data-dir>/kas/<version>-<hash>/ (plus a sibling .lock) on its first
# chat launch -- after this entrypoint has already exec'd the server -- and
# nothing ever removes the superseded ones (six trees / 1.4 GB found on the
# borgcube volume). Applies the toolbelt engine's own
# keep-current-drop-the-rest rule to the one install outside its custody.
#
# Data-dir resolution mirrors kiro-cli's own (XDG_DATA_HOME, else
# $HOME/.local/share): pruning a directory the CLI does not use would be a
# silent no-op. Warn, never fatal.
prune_superseded_kas_runtimes() {
  # $1 = the version whose runtime tree must survive; defaults to the pin.
  # The caller passes the pin, since the version that ends up active is only
  # known after the server's install manager has selected one, after this
  # script execs.
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
  # symlink planted on a once-writable volume would redirect this sweep at an
  # arbitrary tree. Prove the store is a real directory resolving where it is
  # named, or skip the prune.
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
    # <version>-<hash> stem.
    case "$name" in
      "$keep"-*) continue ;;
    esac
    # Only VERSION-KEYED entries are superseded runtimes. kas/ is kiro-cli's
    # directory, not ours; an entry with no leading numeric version is
    # something this pruner has never seen, and deleting another program's
    # unrecognized state is worse than leaving a few MB behind.
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
# toolbelt keeps three metadata files -- tools.json (hand-authored intent),
# tools-state.json (engine-owned machine state) and tool-catalog.cached.json.
# They used to sit directly under /config; the server now points the
# engine's config dir at $TOOLS, beside the artifacts they describe. That
# relocation is a CLEAN BREAK, not a migration: on a volume created by an
# earlier image the three files stay at the old path, nothing reads them,
# and the engine seeds a fresh manifest beside the tree instead.
#
# The break is otherwise SILENT: from the engine's view such a volume IS
# fresh, so previously enabled tools come back as disabled templates and any
# tool added by name is absent from the manifest entirely -- while its
# binary still resolves on PATH, since $TOOLS/bin and the opt/npm/python
# trees were never touched.
#
# So: say it, and do nothing else. Moves, deletes and creates nothing --
# repeats every boot until the operator deletes the old files.
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

# kiro-cli is pinned via Renovate against the public install manifest at
# https://desktop-release.q.us-east-1.amazonaws.com/index.json. Auto-update inside
# the binary is disabled so what runs always matches the version baked into
# the image tag. KIRO_CLI_SHA256 (x86_64) and KIRO_CLI_SHA256_ARM64 (aarch64)
# are the per-arch sha256 of the headless zip, both enforced at install; the
# kiro-cli packageRule in cplieger/.github groups all three literals into one
# Renovate PR so neither arch's gate can land stale.
# Exported below and consumed by the server's install manager (cplieger/pinstall,
# wired by main.go's kiroInstallConfig). They stay shell literals here because
# that is where Renovate's custom datasource finds them.
# COUPLING (re-verify on every bump): routes.go's status classifier matches
# kiro-cli's EXACT OSC 9 notification strings "Response complete", "Permission
# required" and "Input required" (verified against this version) -- a bump
# that rewords any of them silently stops the per-tab status dots from
# latching. Also re-verify `kiro-cli settings app.disableAutoupdates true`
# still succeeds: it gates publication of a staged install AND readiness on a
# boot that installs nothing, so a renamed key or subcommand makes every
# container report kiro-cli unavailable.
# renovate: datasource=custom.kiro-cli depName=kiro-cli
KIRO_CLI_VERSION="2.21.0"
KIRO_CLI_SHA256="6e38c9d3e139419a2edfb54745de8f7bbd8267c67bb23806f501f5bca83907bb"
# The `# kiro-cli <version>` trailer is Renovate's version anchor for this
# arch's digest lookup — do not hand-edit or drop it.
# renovate: datasource=custom.kiro-cli-arm64 depName=kiro-cli-arm64
KIRO_CLI_SHA256_ARM64="b34c3d195d0e79a48306765123283a390bd5177f9dec4178f07f852556319560" # kiro-cli 2.21.0

export KIRO_CLI_VERSION KIRO_CLI_SHA256 KIRO_CLI_SHA256_ARM64
KIRO_CLI_TOOLS_DIR="$TOOLS"
export KIRO_CLI_TOOLS_DIR

# $HOME (/config/home) roots every credential-bearing tree hardened below, and
# `mkdir -p "$HOME/.ssh"` would silently FOLLOW a symlinked $HOME outside the
# /config mount. Check the boundary before any child path is created.
if [ -L "$HOME" ]; then
  fatal 'refusing to use a symlinked HOME; its target may be outside the /config mount' "home=\"$HOME\""
fi
# Asserted on the RESOLVED path (-m, so a not-yet-created HOME still
# resolves), which accepts a HOME that lexically sits outside /config but
# RESOLVES inside it (an ancestor symlinked INTO the mount) -- everything the
# walk below creates through such a HOME still lands under /config. The -L
# test above stays: it enforces the stricter, separate policy that $HOME's
# own final component must not itself be a link.
home_real=$(realpath -m "$HOME" 2>/dev/null) || home_real=""
case "$home_real" in
  /config/?*) ;;
  *) fatal 'HOME does not resolve beneath the /config mount' "home=\"$HOME\" resolved=\"${home_real:-unknown}\"" ;;
esac

# Creates every persistent directory parent-to-child, proving each component
# is a real directory before its child is created. A single `mkdir -p
# "$HOME/.local/bin" ...` would traverse a symlink planted at any component
# on an inherited volume -- and $HOME/.local/bin is later swept with `rm -rf
# "$dir"/kiro-cli*` as root, so a planted link there used to delete the
# link target's own files.
printf 'level=info msg="preparing persistent directories" dir="%s" component=entrypoint\n' /config >&2
make_config_dir /config
make_config_dir "$TOOLS"
make_config_dir "$TOOLS/bin"
# The version-addressed install root the manager writes into, created and
# validated HERE rather than by the manager's own MkdirAll, which cannot see
# a symlink planted on an inherited volume.
#
# A SIBLING of $TOOLS/opt, never a child: $TOOLS/opt's per-tool prune deletes
# every version directory not just installed, so a manifest entry literally
# named `kiro-cli` there could delete the active install and its retained
# predecessor.
make_config_dir "$TOOLS/opt"
# The toolbelt engine's two package-manager roots; their bin dirs hold npm -g
# / uv tool launchers that $TOOLS/bin symlinks into and root executes.
make_config_dir "$TOOLS/npm"
make_config_dir "$TOOLS/npm/bin"
make_config_dir "$TOOLS/python"
make_config_dir "$TOOLS/python/bin"
make_config_dir "$TOOLS/kiro-cli-versions"
make_config_dir "$HOME/.local"
make_config_dir "$HOME/.local/bin"
make_config_dir "$HOME/.ssh"
make_config_dir "$HOME/.kiro"
# kiro-cli persists cli.json / mcp.json / permissions.yaml here, written as
# root long before the theme block looks at this path.
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

# Same argument one level out, for the tree holding the first-on-PATH binary
# rather than credentials. /config is checked too: a writable parent lets an
# attacker replace $TOOLS wholesale. Runs BEFORE the exec, so the taint flag
# exported below is final by the time the manager reads it.
secure_tools_dir /config
secure_tools_dir "$TOOLS"
secure_tools_dir "$TOOLS/bin"
secure_tools_dir "$TOOLS/opt"
secure_tools_dir "$TOOLS/kiro-cli-versions"
# arm=0: neither tree ever holds kiro-cli, so a loose mode here is no reason
# to distrust a version directory and re-download.
secure_tools_dir "$TOOLS/npm" 0 1
secure_tools_dir "$TOOLS/npm/bin" 0 1
secure_tools_dir "$TOOLS/python" 0 1
secure_tools_dir "$TOOLS/python/bin" 0 1
# One level INSIDE the install root: the version directories and dispatchers.
# The root's mode says nothing about them (a `.complete` sentinel is a plain
# file, a --version probe is satisfied by a wrapper), so a rewritable version
# directory would be activated with the taint unset otherwise. Tighten and
# ARM the taint. The globs skip dot-prefixed staging trees for free, and a
# symlinked entry arms the taint rather than being stat'd through -- but
# pathname expansion happens before the body runs, so the */* glob still
# expands THROUGH a symlinked level-1 entry. The loop therefore REFUSES to
# traverse a symlink rather than merely warning about one.
for version_entry in "$TOOLS/kiro-cli-versions"/* "$TOOLS/kiro-cli-versions"/*/*; do
  # -L before -e: [ -e ] dereferences, so testing it first would skip a
  # dangling symlink -- exactly as anomalous as a live one -- silently.
  if [ -L "$version_entry" ]; then
    tools_tree_was_writable=1
    printf 'level=warn msg="an entry inside the kiro-cli install root is a symlink; treating every pre-existing version directory as untrusted so the manager reinstalls from the pinned SHA-verified archive" path="%s" component=entrypoint\n' \
      "$(logfmt_value "$version_entry")" >&2
    continue
  fi
  [ -e "$version_entry" ] || continue
  # Never act THROUGH a symlink: the */* glob traverses a symlinked level-1
  # entry, so a level-2 name can be a regular file OUTSIDE the install root
  # ([ -L ] tests only the final component). The level-1 pass already armed
  # the taint on that symlink, so skip its children rather than tightening them.
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
  # Trust the RESULT, not chmod's status: a bind-mounted or foreign-semantics
  # filesystem (a ZFS inheritable ACL, observed here) can acknowledge a chmod
  # without applying it, so a zero status proves nothing.
  version_entry_mode_after=$(stat -c '%a' "$version_entry" 2>/dev/null) || version_entry_mode_after=""
  if [ -z "$version_entry_mode_after" ] || [ $((8#$version_entry_mode_after & 0022)) -ne 0 ]; then
    printf 'level=warn msg="an entry inside the kiro-cli install root is STILL group/other-writable, or its mode cannot be verified, after tightening; the install manager reinstalls from the pinned archive regardless, but this path stays rewritable by any host user in its group until the volume permissions are fixed" path="%s" mode=%s was=%s chmod_rc=%d component=entrypoint\n' \
      "$(logfmt_value "$version_entry")" "${version_entry_mode_after:-unknown}" "${version_entry_mode:-unknown}" "$version_entry_chmod_rc" >&2
  fi
done
# $TOOLS/go/bin (GOPATH/bin) is one more /config-resident PATH dir the
# Dockerfile puts ahead of /usr/bin. The runtimes/{go,node}/bin segments were
# dropped from ENV PATH once an audit showed both trees held only binaries
# already resolving through $TOOLS/bin, so nothing hardens them here any
# more -- a dir not on PATH cannot source a root-executed planted binary.
# arm=0 (never holds kiro-cli), owned=0 (never created or repaired here, so
# an odd shape warns rather than fails boot).
#
# Accepted residual: `chmod go-w` stops NEW directory writes but never
# re-verifies files already planted while the tree was writable. Quarantining
# unrecognized binaries would delete the user's own `go install` output.
for path_dir in "$TOOLS/go" "$TOOLS/go/bin"; do
  [ -e "$path_dir" ] || [ -L "$path_dir" ] || continue
  secure_tools_dir "$path_dir" 0 0
done
# Directory modes leave every binary in $TOOLS/bin unexamined, and this dir
# LEADS PATH. A group/other-writable file is rewritable in place with no
# write access to the directory, and the toolbelt engine really does leave
# group-writable modes on some volumes. Tighten what we can; never quarantine.
# stat -L / chmod deliberately DEREFERENCE: $TOOLS/bin is mostly symlinks into
# the engine's opt/<tool>/<ver>/ trees, and the target's mode is the one that
# decides whether a foreign host user can rewrite what root executes.
tightened_tool_bins=0
for tool_bin in "$TOOLS/bin"/*; do
  # An unmatched glob, or a dangling symlink -- nothing that can be executed.
  [ -e "$tool_bin" ] || continue
  # Exactly `kiro-cli` is the manager's own republished convenience symlink
  # (for `docker exec … kiro-cli --version`); skip the exact name rather than
  # a kiro-cli* prefix, since this dir is co-owned by the toolbelt engine.
  case "${tool_bin##*/}" in kiro-cli) continue ;; esac
  tool_bin_mode=$(stat -Lc '%a' "$tool_bin" 2>/dev/null) || tool_bin_mode=""
  if [ -n "$tool_bin_mode" ] && [ $((8#$tool_bin_mode & 0022)) -eq 0 ]; then
    continue
  fi
  # chmod FOLLOWS the symlink, and the only entries reaching here already
  # carry a group/other write bit (device nodes at 0666, shared host dirs at
  # 0777) -- a planted `x -> /dev/null` would degrade every process in the
  # container, a link into /workspace would undo the host operator's own
  # permission. Only targets inside $TOOLS are ours to tighten.
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
  # Trust the RESULT, not chmod's status, for the same reason as above. A mode
  # still loose, or unreadable, stays OUT of the count below.
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

# Hands the taint observation to the manager: the directories are private NOW,
# but anything already inside a tree that was group/other-writable was
# writable by another host user, and the manager accepts an existing version
# directory on the strength of its own forgeable `.complete` sentinel. With
# this set the manager activates only a version IT installed this boot.
KIRO_CLI_TOOLS_TAINTED="$tools_tree_was_writable"
export KIRO_CLI_TOOLS_TAINTED
if [ "$tools_tree_was_writable" -eq 1 ]; then
  printf 'level=warn msg="the tools tree was group/other-writable; telling the install manager to distrust every kiro-cli version directory already on the volume and reinstall from the pinned SHA-verified archive" dir="%s" component=entrypoint\n' "$TOOLS" >&2
fi

# Best-effort: drop the write probe orphaned by a hard container kill (the
# ordinary path removes it in its own test). `rm -rf` on an unmatched glob is
# already a silent no-op returning 0, so a non-zero status here is a REAL
# failure -- an immutable attribute, EPERM, a submount.
if ! rm -rf "$TOOLS"/.write-probe.*; then
  printf 'level=warn msg="failed to remove orphaned boot-time temp artifacts; they keep occupying the /config volume" dir="%s" component=entrypoint\n' "$TOOLS" >&2
fi

# Points out tool metadata still sitting at its pre-$TOOLS location, which
# nothing reads any more. Placed here, after the walk proved $TOOLS is a real
# private directory.
warn_legacy_tool_metadata /config "$TOOLS"

# Hygiene for the one residue class the manager's own purge does not reach:
# binaries an EARLIER image version staged into $HOME/.local/bin (that
# install ran with the real HOME; the manager stages under a private HOME
# beneath $TOOLS). Warn, don't exit: every session leads PATH with the active
# version's directory, so nothing here can shadow the pinned CLI.
sweep_legacy_dispatchers "$HOME/.local/bin"

# Reclaims superseded kiro-cli agent runtimes. Stays in the entrypoint rather
# than moving into the server with the installer: the kas store is a
# SEPARATE object (kiro-cli's own data dir) with its own containment guards,
# it is keyed on the pin this script declares, and running it before the
# server binds keeps peak disk at ONE tree.
#
# The keep-key is the PIN, not the version that ends up active: if the manager
# falls back to a retained predecessor, that predecessor's tree has already
# been pruned here, costing one ~240 MB re-unpack on a boot whose install
# failed. Accepted over pruning after selection, which would let two trees
# coexist on the routine bump path.
printf 'level=info msg="pruning superseded kiro-cli agent runtimes" keep=%s component=entrypoint\n' "$KIRO_CLI_VERSION" >&2
prune_superseded_kas_runtimes "$KIRO_CLI_VERSION"

# Repairs an interrupted dpkg transaction, unconditionally: an interrupted
# install leaves dpkg wedged for the container's life, and this must run
# BEFORE the listener binds since the tools engine cannot repair a system
# database it does not own.
#
# The AUDIT OUTPUT is the primary evidence, not the exit status: `dpkg
# --audit` returns 0 while REPORTING unpacked-but-unconfigured packages
# (measured: 464 bytes on stdout, rc=0), so gating on rc alone would never
# fire on the ordinary interrupted state. A healthy tree prints nothing, so
# non-empty output cannot false-positive.
dpkg_audit_rc=0
dpkg_audit_out=$(timeout --signal=TERM --kill-after=30s 300s dpkg --audit 2>/dev/null) || dpkg_audit_rc=$?
dpkg_audit_summary=$(printf '%s' "${dpkg_audit_out:0:400}" | tr '\n' ' ')
if [ "$dpkg_audit_rc" -ne 0 ] || [ -n "$dpkg_audit_out" ] \
  || [ -n "$(ls -A /var/lib/dpkg/updates 2>/dev/null)" ]; then
  printf 'level=warn msg="dpkg is in an interrupted state (an install was killed mid-transaction); reconfiguring" audit_rc=%d audit="%s" component=entrypoint\n' \
    "$dpkg_audit_rc" "$(logfmt_value "$dpkg_audit_summary" 400)" >&2
  dpkg_fix_rc=0
  timeout --signal=TERM --kill-after=30s 300s dpkg --configure -a || dpkg_fix_rc=$?
  if [ "$dpkg_fix_rc" -ne 0 ]; then
    printf 'level=warn msg="dpkg --configure -a failed; apt installs will keep failing until the container is recreated" rc=%d component=entrypoint\n' "$dpkg_fix_rc" >&2
  fi
fi

# Hardcode dark theme. kiro-cli's "default" diff preset resolves
# added-line bg to #00FF00 through the truecolor path — unreadable.
theme_dir="$HOME/.kiro/settings"
theme_file="$theme_dir/kiro_cli_theme.json"
theme_tmp=''
# Re-validated immediately before the write, even though the boot-time walk
# already created and hardened this path: mkdir -p FOLLOWS a symlink, and the
# mktemp + mv below replace a FIXED-NAME file in the directory where kiro-cli
# also persists mcp.json (remote MCP tokens). A symlink here is fatal; a
# failed mkdir stays a warn -- the theme is cosmetic.
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

# Seeds the kiro-cli hook that reports which kiro session each tab is
# running -- the mapping half of the tab-title feature (sessiontitle.go). The
# server injects WT_TITLE_HANDLE + WT_TITLE_STATE_DIR into each PTY session,
# and this hook (a descendant, handed kiro's own session_id on stdin) writes
# the pair where the server reads it. Without it a tab falls back to the
# engine's automatic cwd/process name ladder.
#
# Rewritten on EVERY boot rather than created-if-missing, so an image upgrade
# updates the hook and a deleted/edited file self-heals. Global hooks
# (~/.kiro/hooks) load in every workspace regardless of start directory.
#
# Symlink handling follows the theme block above for the same reason: a
# symlink here is fatal, a failed mkdir stays a warn.
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

# Hands the image's PATH back so the server and its PTY sessions keep
# /config/tools/bin first. Each PTY session additionally gets the ACTIVE
# kiro-cli version directory prepended by the server.
#
# The carry variable is dropped here rather than inherited: it exists only to
# survive the setpriv re-exec above, and nothing past this point re-execs
# this script.
PATH="$SESSION_PATH"
export PATH
unset WT_SESSION_PATH
# Same reason and lifetime as the PATH carry above: the setpriv re-exec
# marker, meaningful only until that exec has happened.
unset CONTAINMENT_CAPS_DROPPED
printf 'level=info msg="entrypoint complete; starting the web server" component=entrypoint\n' >&2
exec /app/web-terminal-kiro
