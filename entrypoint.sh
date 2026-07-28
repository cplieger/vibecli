#!/bin/bash
# web-terminal-kiro entrypoint. Ensures the pinned kiro-cli version is installed
# (downloads on first boot or whenever the on-disk version drifts from
# the pin), then hands off to the Go web server. Matches vibekit's
# licensing pattern: we download kiro-cli at runtime rather than bake
# it into the image so we don't redistribute proprietary AWS Content.

set -u

# This script's own commands must NOT resolve through /config/tools/bin. That dir leads the
# image PATH (Dockerfile ENV PATH) and lives on the persistent bind mount, so on a volume
# that ever permitted group/other writes -- the state secure_tools_dir exists to detect -- a
# planted stat/chmod/curl/sha256sum there would BE the oracle every integrity check below
# trusts. Resolve the entrypoint's tools from the image only; the session PATH (which must
# keep the engine-managed dir first) is restored for the exec'd server at the bottom.
SESSION_PATH="$PATH"
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

TOOLS="/config/tools"
BIN="$TOOLS/bin/kiro-cli"
# `kiro-cli chat` -- the command every session runs -- is DISPATCHED to this sidecar,
# so a missing, stale or unusable one breaks every terminal while `kiro-cli --version`
# (the readiness probe) still answers correctly. It is part of the installed SET, not
# an optional extra, which is why both the drift predicate and readiness check it.
CHAT_SIDECAR="$TOOLS/bin/kiro-cli-chat"
# Install-completion marker: holds the KIRO_CLI_VERSION whose FULL dispatcher set was
# promoted. $BIN's own --version answer cannot distinguish a completed transaction
# from a partial promotion that left the chat sidecar absent, non-executable or at an
# older version, so the persisted-install predicate needs a fact that only a completed
# install writes. install_kiro_cli publishes it atomically after the chat sidecar is
# promoted and immediately BEFORE $BIN (the commit point); the pre-reinstall
# quarantine removes it together with the binaries it describes. An inherited volume
# from a pre-marker image therefore takes exactly one repair install.
KIRO_CLI_INSTALL_MARKER="$TOOLS/.kiro-cli-installed"
# An update replaces THREE REQUIRED files that only mean anything as ONE set: $BIN, the
# $CHAT_SIDECAR it dispatches `chat` to, and the marker that names the version whose
# full set was promoted. (The optional kiro-cli-term dispatcher is NOT in the
# transaction -- it is promoted after the commit, so a rollback cannot strand a
# newer-pin term beside the restored older pair.) Each `mv -f` is atomic; the SEQUENCE
# is not. A kill between
# them -- or a later rename that fails -- leaves the OLD $BIN paired with the NEW
# sidecar: `kiro-cli --version` answers with the old version, the caller's
# keep-the-old-install fallback sees an executable $BIN and publishes readiness, and
# every session then dies at `chat` behind a green /api/health. That is strictly worse
# than the failure the fallback exists to avoid, because it MUTATES the old install it
# claims to have preserved.
#
# So the promotion is journalled. Before the first live rename, install_kiro_cli
# hard-links the current set aside in the SAME directory (instant, and no extra space:
# `mv -f` only rewrites the directory entry, so the link keeps the old inode alive) and
# opens the journal; on success it drops the backups and then the journal; on any
# ordinary failure it restores the complete old set. Any boot that still finds the
# journal knows the set may be mixed and repairs it BEFORE the first version or
# readiness check reads the volume. The backups are dot-prefixed so no bare-name PATH
# lookup and none of the `kiro-cli*` sweeps can reach them.
KIRO_CLI_UPDATE_JOURNAL="$TOOLS/.kiro-cli-update-in-progress"
BIN_PREV="$TOOLS/bin/.kiro-cli.prev"
CHAT_SIDECAR_PREV="$TOOLS/bin/.kiro-cli-chat.prev"
KIRO_CLI_INSTALL_MARKER_PREV="$TOOLS/.kiro-cli-installed.prev"

# Parse the version kiro-cli reports (last field of `--version`). Centralized
# so the four call sites (bare-name resolution check, drift check, install
# verify, readiness marker)
# share one parse if kiro-cli ever reworks its --version output.
kiro_cli_version() {
  local out rc
  # --kill-after gives a TERM-resistant binary a hard second-stage deadline;
  # without it GNU timeout waits forever on a child that traps/ignores TERM.
  # Capture the output and the timeout STATUS separately: piping straight into awk
  # loses the status at the pipeline boundary (awk exits 0 even when its producer
  # was TERMed/KILLed), which makes a wedged --version indistinguishable from a
  # missing binary at every call site. This warning is the only timeout diagnostic;
  # callers keep treating an empty version as a mismatch.
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

# 0 when $1 is a dispatcher that will still work after install_kiro_cli's EXIT trap
# deletes the staging tree: a REGULAR executable file, not a symlink. -f/-x both
# FOLLOW symlinks, so a link into $stage passes them, is mv'd to its destination AS
# A LINK, and dangles the moment the trap fires. Single home for the rule so the
# four staging-tree sites that depend on it cannot drift -- and the four $BIN sites
# (needs_kiro_cli_install, the failed-install fallback, the kiro_setting block and
# the readiness version probe) share it too: a bare -x is also true for a DIRECTORY,
# which the quarantine sweep passes (a 0755 dir has no group/other write bit) and
# which the fallback would otherwise misreport as a kept previous version (exec of
# a directory fails instantly with rc 126, so the cost is misattribution, not time).
is_self_contained_executable() {
  [ ! -L "$1" ] && [ -f "$1" ] && [ -x "$1" ]
}

# --- kiro-cli update transaction ---------------------------------------------
# See KIRO_CLI_UPDATE_JOURNAL above for why the promotion needs one at all.

# Link $1 aside as $2 so the promotion can be undone, and record an ABSENCE
# explicitly when there is nothing to link. "No backup" used to carry two
# meanings -- "this component did not exist before the update" and "the snapshot
# never ran" -- and rollback could only read the second, so it left a component
# this update newly promoted in place. That is the mixed-set bug on a REPAIR
# install: an old $BIN with no chat sidecar snapshots only $BIN, so a later $BIN
# promotion failure restored the old $BIN beside the NEW sidecar and marker. The
# `.absent` tombstone beside the backup closes that: restore consumes it by
# DELETING $dest, which leaves the genuine pre-update set (no sidecar => the set
# is incomplete => readiness is withheld and the drift check reinstalls). Any
# other failure returns non-zero, and the caller then refuses to start the
# transaction at all -- refusing to update is the app's stated trade (a working
# old terminal beats a dead one), while promoting without a way back is the
# mixed-set bug this exists to prevent.
kiro_cli_snapshot_one() {
  local src="$1" backup="$2" absent="$2.absent"
  rm -rf "$backup" "$absent" || return 1
  # A symlink is deliberately NOT snapshotted: the boot quarantine treats one at
  # these paths as untrusted, so restoring it would put back a file this script
  # already refuses to authenticate. It is tombstoned rather than ignored for the
  # same reason an absent file is: whatever this update promotes over it is the
  # only thing rollback can be sure about.
  if [ ! -e "$src" ] || [ -L "$src" ]; then
    : >"$absent" || return 1
    return 0
  fi
  # A hard link is instant and costs no space; fall back to a copy only where the
  # filesystem refuses links (nothing on /config should, but a bind mount of an
  # exotic fs must not silently skip the backup).
  ln -f "$src" "$backup" 2>/dev/null && return 0
  cp -p "$src" "$backup"
}

# Put $2 back from the backup at $1, consuming the backup -- or, when the snapshot
# left a tombstone, remove $2 because it did not exist before the update. Only the
# two together restore the COMPLETE old set: without the tombstone arm, a promoted
# file whose predecessor was absent survives a rollback and pairs a new component
# with an old $BIN. A tombstone that is a symlink is not one this script wrote, so
# it is not trusted to describe the old set either; the conservative reading is
# "no snapshot", which leaves $dest alone.
kiro_cli_restore_one() {
  local backup="$1" dest="$2" absent="$1.absent"
  if [ -f "$absent" ] && [ ! -L "$absent" ]; then
    rm -rf -- "$dest" "$absent" || return 1
    return 0
  fi
  if [ ! -e "$backup" ] || [ -L "$backup" ]; then
    return 0
  fi
  # A backup that is not a regular file is not one this script wrote. A DIRECTORY
  # is the reachable shape (mkdir needs no privilege on a tree that once permitted
  # foreign writes): `mv` would rename it over $dest, and `rm -f` could never
  # remove it, so the journal would never close and every later boot would re-fail
  # the repair. Discard it and report "no snapshot" rather than promoting it.
  if [ ! -f "$backup" ]; then
    rm -rf "$backup"
    return 0
  fi
  # Same inode => this component was never promoted, so the backup IS the live file
  # and there is nothing to put back. It has to be special-cased rather than left to
  # `mv`, which refuses a same-file rename with an error ("are the same file") and
  # would otherwise turn every partial rollback into a reported failure.
  if [ "$backup" -ef "$dest" ]; then
    rm -rf "$backup"
    return
  fi
  mv -f "$backup" "$dest"
}

# Close the transaction. Backups go FIRST and the journal LAST: a kill in between
# leaves a journal with nothing to restore, which the next boot's recovery reads
# as "nothing to do" and leaves the committed set alone. The reverse order would
# let that same kill make recovery restore a stale set over a good install. The
# `.absent` tombstones are backups too -- an orphaned one would make the next
# recovery pass DELETE a committed component -- so they are dropped here as well.
kiro_cli_update_finish() {
  if ! rm -rf "$BIN_PREV" "$CHAT_SIDECAR_PREV" "$KIRO_CLI_INSTALL_MARKER_PREV" \
    "$BIN_PREV.absent" "$CHAT_SIDECAR_PREV.absent" "$KIRO_CLI_INSTALL_MARKER_PREV.absent"; then
    printf 'level=warn msg="failed to remove kiro-cli update backups; they keep occupying the /config volume" dir="%s" component=entrypoint\n' "$TOOLS" >&2
  fi
  if ! rm -rf "$KIRO_CLI_UPDATE_JOURNAL"; then
    printf 'level=warn msg="failed to clear the kiro-cli update journal; the next boot will run an unnecessary recovery pass" journal="%s" component=entrypoint\n' "$KIRO_CLI_UPDATE_JOURNAL" >&2
    return 1
  fi
  return 0
}

# Open the transaction: snapshot the set, then publish the journal atomically.
# The journal is written LAST, so it is never present without its backups. Its
# stage-prefixed temp name is covered by the every-boot orphan sweep, like the
# completion marker's.
kiro_cli_update_begin() {
  local journal_tmp=''
  # Refuse to open a transaction on top of an unresolved one. A journal still on disk
  # here means the previous update neither committed nor finished rolling back, and its
  # backups plus `.absent` tombstones are the ONLY record of what the pre-update set
  # was. Starting anyway would destroy that record twice over: kiro_cli_snapshot_one
  # deletes each fixed-name backup before linking a new one, and the snapshot it takes
  # is of the already-MIXED live set -- so a later promotion failure would "roll back"
  # to the mixed state instead of to a set that ever existed. Return WITHOUT calling
  # kiro_cli_update_finish (unlike the two failure paths below, which close a
  # transaction THIS call opened): finishing would clear the very journal the next
  # boot's recovery pass needs to attempt the repair again. A symlink counts as present
  # for the same reason recovery distrusts one -- this script did not write it, so it
  # cannot be read as "no transaction" either.
  if [ -e "$KIRO_CLI_UPDATE_JOURNAL" ] || [ -L "$KIRO_CLI_UPDATE_JOURNAL" ]; then
    printf 'level=error msg="refusing to start a kiro-cli update transaction while an unresolved one is journalled; its backups are the only record of the previous dispatcher set" journal="%s" component=entrypoint\n' \
      "$KIRO_CLI_UPDATE_JOURNAL" >&2
    return 1
  fi
  if ! kiro_cli_snapshot_one "$BIN" "$BIN_PREV" \
    || ! kiro_cli_snapshot_one "$CHAT_SIDECAR" "$CHAT_SIDECAR_PREV" \
    || ! kiro_cli_snapshot_one "$KIRO_CLI_INSTALL_MARKER" "$KIRO_CLI_INSTALL_MARKER_PREV"; then
    printf 'level=error msg="failed to back up the current kiro-cli dispatcher set; refusing to promote an update that could not be undone" dir="%s" component=entrypoint\n' "$TOOLS/bin" >&2
    kiro_cli_update_finish
    return 1
  fi
  if ! journal_tmp=$(mktemp "$TOOLS/.kiro-cli-stage.journal.XXXXXX") \
    || ! printf 'pinned=%s previous=%s\n' "$KIRO_CLI_VERSION" "${kiro_cli_measured_version:-unknown}" >"$journal_tmp" \
    || ! mv -f "$journal_tmp" "$KIRO_CLI_UPDATE_JOURNAL"; then
    [ -z "$journal_tmp" ] || rm -f "$journal_tmp"
    printf 'level=error msg="failed to open the kiro-cli update journal; refusing to promote an update a later boot could not repair" journal="%s" component=entrypoint\n' "$KIRO_CLI_UPDATE_JOURNAL" >&2
    kiro_cli_update_finish
    return 1
  fi
  return 0
}

# Undo whatever was promoted, restoring the COMPLETE old set. On failure the
# journal is deliberately left in place so the next boot retries the repair
# before anything reads a version off the volume.
kiro_cli_update_rollback() {
  local rc=0
  kiro_cli_restore_one "$BIN_PREV" "$BIN" || rc=1
  kiro_cli_restore_one "$CHAT_SIDECAR_PREV" "$CHAT_SIDECAR" || rc=1
  kiro_cli_restore_one "$KIRO_CLI_INSTALL_MARKER_PREV" "$KIRO_CLI_INSTALL_MARKER" || rc=1
  if [ "$rc" -ne 0 ]; then
    printf 'level=error msg="failed to restore the previous kiro-cli dispatcher set after a failed update; the journal is kept so the next boot retries the repair" journal="%s" component=entrypoint\n' "$KIRO_CLI_UPDATE_JOURNAL" >&2
    return 1
  fi
  kiro_cli_update_finish
}

# Every-boot repair, called BEFORE any version, set-completeness or readiness
# check. A journal here means the last update did not commit, so the persisted
# set may pair the old $BIN with the new sidecar -- the one state whose
# --version answer is actively misleading.
recover_kiro_cli_update_journal() {
  if [ ! -e "$KIRO_CLI_UPDATE_JOURNAL" ] || [ -L "$KIRO_CLI_UPDATE_JOURNAL" ]; then
    # No open transaction (a symlink is not one this script wrote, so it is not
    # trusted to describe one either), which makes any surviving backup pure
    # residue -- a commit whose backup removal failed, or a link left by a kill.
    # kiro_cli_update_finish is exactly that cleanup.
    kiro_cli_update_finish
    return 0
  fi
  printf 'level=warn msg="found an uncommitted kiro-cli update; restoring the previous dispatcher set before any version or readiness check" journal="%s" component=entrypoint\n' \
    "$KIRO_CLI_UPDATE_JOURNAL" >&2
  if ! kiro_cli_update_rollback; then
    return 1
  fi
  printf 'level=info msg="uncommitted kiro-cli update rolled back; the drift check reinstalls from the pinned archive" pinned=%s component=entrypoint\n' \
    "$KIRO_CLI_VERSION" >&2
  return 0
}

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
# $TOOLS/bin leads PATH (see the Dockerfile's ENV PATH) and KIRO_CLI_PATH points
# into it, so the tree HOLDING kiro-cli is part of the integrity story, not just
# the download: needs_kiro_cli_install authenticates an already-present binary
# only by asking it for `--version`, which a planted payload spoofs trivially. If
# an inherited /config volume ever permitted group/other writes, another host
# user could drop a version-spoofing executable there, skip the SHA-verified
# reinstall, and be launched as root with access to credentials and /workspace.
# So: refuse symlinks, strip group/other write bits, fail boot if they survive,
# and remember that the tree WAS writable so the caller can quarantine whatever
# kiro-cli* files it already held. Sets tools_tree_was_writable=1 in that case.
tools_tree_was_writable=0
# $2 (default 1) arms the kiro-cli quarantine when the dir was writable. Pass 0
# for a PATH segment that never holds kiro-cli.
secure_tools_dir() {
  local dir=$1 arm=${2:-1} owned=${3:-1} mode
  # `owned` decides what an UNRECOVERABLE state costs. This is a dev-box container:
  # the operator is expected to reshape /config/tools to stay productive (the
  # borgcube audit deleted both runtimes trees and symlinked corepack, see
  # web-terminal-kiro.md), so a broken state must be able to heal itself or at worst
  # be fixable from INSIDE the container. Aborting boot fails that test -- there is no
  # way in to repair it, and nothing recreates these trees.
  #   owned=1  /config, $TOOLS, $TOOLS/bin -- created by this entrypoint, so a symlink
  #            or a plain file there is unambiguously anomalous and a reinstall repairs
  #            the contents. Fatal.
  #   owned=0  the legacy PATH segments -- never created, never repaired, and holding
  #            no integrity-gated binary. Warn and skip, matching
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
# REACHABLE BY BARE NAME, not merely wasted disk. The current installer stages under
# $TOOLS and promotes by rename, so it never writes there -- these sweeps exist for
# pre-existing volumes and as belt-and-braces against an installer that resolves its
# prefix via getpwuid rather than $HOME.
#
# Two robustness rules:
#
#   1. rm -rf, not rm -f. `rm -f` FAILS on a directory, so a stray directory named
#      kiro-cli-anything under a swept dir would turn a hygiene step into a boot
#      failure (fatal, with its 10s crash-loop throttle) at the two reinstall sites.
#   2. Assert the GOAL, not the ACTION. rm's exit status answers "did the unlink
#      succeed", never "is an unpinned kiro-cli still reachable ahead of $BIN". Those
#      come apart in BOTH directions: an unremovable non-binary (an immutable
#      kiro-cli-notes.txt, a read-only mount) failed the old check while shadowing
#      nothing, and anything the kiro-cli* prefix does not match (a future dispatcher
#      name, a symlink planted under another name) passed it while shadowing the
#      pinned binary. resolves_to_pinned_kiro_cli() checks the invariant directly, so
#      the fatal paths now fire on the dangerous condition instead of on rm's status.
#
# Note PATH order makes the exposure window precise: $TOOLS/bin precedes
# $HOME/.local/bin, so a leftover can only win bare-name resolution while $BIN is
# ABSENT -- i.e. exactly the pre-reinstall and failed-install windows the two fatal
# sites guard. With $BIN present nothing in $HOME/.local/bin can shadow it, which is
# why the every-boot site stays warn-only.
sweep_legacy_dispatchers() {
  local dir
  for dir in "$@"; do
    # Never expand to /kiro-cli* on an unset/empty argument.
    [ -n "$dir" ] || continue
    if ! rm -rf "$dir/kiro-cli"*; then
      printf 'level=warn msg="failed to remove legacy kiro-cli residue" dir="%s" component=entrypoint\n' "$dir" >&2
    fi
  done
  # Always 0, deliberately: per the block comment above, rm's status answers 'did the
  # unlink succeed', never 'is an unpinned kiro-cli still reachable'. Callers gate on
  # resolves_to_pinned_kiro_cli; returning a failure count here only invited them to read
  # it as the safety verdict.
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
  # passes the version actually on disk, because a failed update keeps serving that one
  # and deleting its ~240 MB tree makes the next session re-unpack it on every boot.
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
        "$kas_dir" "${kas_real:-unknown}" >&2
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
      printf 'level=info msg="leaving unrecognized (non version-keyed) entry in the kiro-cli agent runtime store" entry="%s" component=entrypoint\n' "$name" >&2
      continue
    fi
    if rm -rf "$entry"; then
      printf 'level=info msg="pruned superseded kiro-cli agent runtime" entry="%s" keep=%s pinned=%s component=entrypoint\n' "$name" "$keep" "$KIRO_CLI_VERSION" >&2
    else
      printf 'level=warn msg="failed to prune superseded kiro-cli agent runtime" entry="%s" component=entrypoint\n' "$name" >&2
    fi
  done
  return 0
}

# 0 when bare-name `kiro-cli` resolves to the pinned binary AT the pinned version, or
# resolves to nothing at all (a fresh volume, or the window right after the
# pre-reinstall sweep removed $BIN -- nothing to shadow). 1 when it resolves somewhere
# else, and equally when it resolves to $BIN but that binary is NOT the pinned version:
# path identity alone is weaker than the property the callers rely on. If `rm -rf`
# cannot remove a drifted canonical binary (immutable file, submount), `command -v`
# still answers "$BIN" while a stale, no-longer-pinned CLI remains first on PATH and
# launchable by sessions -- exactly the state the quarantine exists to prevent.
resolves_to_pinned_kiro_cli() {
  local mode=${1:-full} resolved resolved_version
  # Resolve against the SESSION PATH, not the entrypoint's trimmed one: this check is about
  # what a session (or `docker exec ... kiro-cli`) resolves by bare name.
  resolved=$(PATH="$SESSION_PATH" command -v kiro-cli 2>/dev/null) || return 0
  [ -n "$resolved" ] || return 0
  # Two distinct failures, distinct statuses: rc 2 is OUR OWN binary at the wrong
  # version (nothing is shadowing anything -- the pinned path simply holds an older
  # build, which is the state a failed update deliberately falls back to), while rc 1
  # is a binary at some OTHER path winning bare-name resolution, which is the genuine
  # shadowing risk. Callers that must tolerate a fallback check the status explicitly;
  # `! resolves_to_pinned_kiro_cli` still treats both as failure.
  #
  # mode=identity asks only the SHADOWING question and never probes --version. The
  # every-boot advisory site wants exactly that: on the first boot after a Renovate
  # bump, $BIN legitimately holds the OLD version, and a full check there emitted a
  # warn about a suspected "unremovable stale binary" on the routine upgrade path,
  # followed by a second warn from the caller -- for a condition that is expected and
  # corrected by needs_kiro_cli_install's own truthful info line moments later. The
  # version question belongs to that check, not to this one, and skipping the probe
  # also keeps the every-boot path at ONE fewer 10s --version call (the foreground
  # boot allowance the Dockerfile HEALTHCHECK comment sums).
  if [ "$resolved" = "$BIN" ]; then
    [ "$mode" = identity ] && return 0
    resolved_version=$(kiro_cli_version "$resolved")
    [ "$resolved_version" = "$KIRO_CLI_VERSION" ] && return 0
    printf 'level=warn msg="bare-name kiro-cli resolves to the pinned path but not the pinned version (unremovable stale binary?)" resolved="%s" installed=%s pinned=%s component=entrypoint\n' \
      "$resolved" "${resolved_version:-unknown}" "$KIRO_CLI_VERSION" >&2
    return 2
  fi
  printf 'level=warn msg="bare-name kiro-cli resolves to an unpinned path ahead of the pinned binary" resolved="%s" pinned="%s" component=entrypoint\n' "$resolved" "$BIN" >&2
  return 1
}

# Warn about a rejected APT_PACKAGES token. The token is untrusted env content, so
# bound its length first (one bad token must not dominate the log line), then strip
# non-printable bytes and neutralize the quote that would close the logfmt field.
# Backslash is logfmt's escape character, so double it: otherwise the field's closing
# quote can itself be escaped. The RAW token is bounded BEFORE that doubling, because
# truncating after it could split a `\\` pair and leave a trailing lone backslash that
# escapes the closing quote. The bound is therefore 64 INPUT chars (at most 128
# emitted), not 64 emitted chars. Shared by both rejection paths (grammar and
# known-name) so the sanitizing rules cannot drift between them.
warn_skipped_apt_token() {
  local msg=$1 raw=$2 safe
  safe=${raw:0:64}
  safe=${safe//\\/\\\\}
  safe=${safe//[![:print:]]/?}
  safe=${safe//\"/\'}
  printf 'level=warn msg="%s" token="%s" component=entrypoint\n' "$msg" "$safe" >&2
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
# done dot), "Permission required" (tool approval -> needs-input dot) and
# "Input required" (a structured user question -> the same needs-input dot),
# verified against this version. A bump that reworded any of them silently
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
KIRO_CLI_VERSION="2.14.2"
KIRO_CLI_SHA256="b144d4b1f8ca0083967fe13a5c35db18bd9543ecede6f1eec166f3b0a04f876a"
# The `# kiro-cli <version>` trailer is Renovate's version anchor for this
# arch's digest lookup — do not hand-edit or drop it.
# renovate: datasource=custom.kiro-cli-arm64 depName=kiro-cli-arm64
KIRO_CLI_SHA256_ARM64="c6a090372664db8a103b5de1addcf6322a845be853d8e8f38aab9c28a6de6866" # kiro-cli 2.14.2

# $HOME (/config/home) is the root of every credential-bearing tree hardened
# below, and `mkdir -p "$HOME/.ssh"` would silently FOLLOW a symlinked $HOME to
# a target outside the /config mount -- creating and populating the credential
# dirs somewhere with no enforced mode. Check the boundary BEFORE any child path
# is created: a real directory under /config, not a link.
case "$HOME" in
  /config/*) ;;
  *) fatal 'HOME must resolve beneath the /config mount' "home=\"$HOME\"" ;;
esac
if [ -L "$HOME" ]; then
  fatal 'refusing to use a symlinked HOME; its target may be outside the /config mount' "home=\"$HOME\""
fi
# The pattern above is a LEXICAL prefix match, so it accepts a path that only
# looks contained: /config/../etc matches /config/* and is not a symlink, and
# the walk below would then create .ssh / .kiro/settings under it while
# harden_config_dir chmod 700's the target. Re-assert the boundary on the
# RESOLVED path (-m, so a not-yet-created HOME still resolves) -- that closes
# '..' components and a symlinked ANCESTOR in one check, which the -L test on
# the final component alone cannot.
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
make_config_dir /config
make_config_dir "$TOOLS"
make_config_dir "$TOOLS/bin"
make_config_dir "$HOME/.local"
make_config_dir "$HOME/.local/bin"
make_config_dir "$HOME/.ssh"
make_config_dir "$HOME/.kiro"
# kiro-cli persists cli.json / mcp.json / permissions.yaml here, and the
# kiro_setting calls below write them as root long before the theme block
# looks at this path, so the symlink rejection has to happen in the walk.
make_config_dir "$HOME/.kiro/settings"

# mkdir -p succeeds when the directories already exist — even on a read-only
# bind mount — so it is NOT proof that /config is writable. Prove it with a
# create+remove probe and fail fast (the documented behavior for an
# unwritable persistent volume) instead of limping into an install that
# cannot update the readiness marker. Runs BEFORE the chmod pass below: on a
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
# writable parent lets an attacker replace $TOOLS wholesale. Runs BEFORE any
# sweep, version probe, or marker handling, so a spoofable binary on a
# previously-permissive volume can never authenticate itself by --version.
secure_tools_dir /config
secure_tools_dir "$TOOLS"
secure_tools_dir "$TOOLS/bin"
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
# Directory modes are only half the invariant: a kiro-cli binary that is ITSELF
# group/other-writable can be rewritten in place with no write access to the
# directory at all, and a symlinked $BIN points wherever its target says. In both
# cases needs_kiro_cli_install's --version probe authenticates nothing, while the
# directory checks above stay silent. Fold those states into the same quarantine
# the writable-tree case triggers.
for existing in "$TOOLS/bin"/kiro-cli*; do
  [ -e "$existing" ] || [ -L "$existing" ] || continue
  existing_mode=$(stat -c '%a' "$existing" 2>/dev/null) || existing_mode=""
  if [ -L "$existing" ] || [ -z "$existing_mode" ] || [ $((8#$existing_mode & 0022)) -ne 0 ]; then
    tools_tree_was_writable=1
    printf 'level=warn msg="kiro-cli binary on the persistent tree is a symlink or permits group/other writes; treating it as untrusted and forcing a pinned SHA-verified reinstall" path="%s" mode=%s component=entrypoint\n' \
      "$existing" "${existing_mode:-unknown}" >&2
  fi
done
# Directory modes and the kiro-cli loop above still leave every OTHER binary in
# $TOOLS/bin unexamined -- and this dir LEADS PATH for the server, every PTY session
# and root (Dockerfile ENV PATH). The argument the loop above makes applies verbatim
# to them: a group/other-writable file is rewritable in place with no write access to
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
  # Already handled, with its own stricter symlink rule, by the loop above.
  case "${tool_bin##*/}" in kiro-cli*) continue ;; esac
  tool_bin_mode=$(stat -Lc '%a' "$tool_bin" 2>/dev/null) || tool_bin_mode=""
  if [ -n "$tool_bin_mode" ] && [ $((8#$tool_bin_mode & 0022)) -eq 0 ]; then
    continue
  fi
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
      "$tool_bin" "${tool_bin_mode:-unknown}" "${loose_mode:-unknown}" "$chmod_rc" >&2
    continue
  fi
  tightened_tool_bins=$((tightened_tool_bins + 1))
done
if [ "$tightened_tool_bins" -ne 0 ]; then
  printf 'level=warn msg="tightened group/other-writable binaries on the first-on-PATH tools tree; they were rewritable in place by any host user in their group" dir="%s" count=%d component=entrypoint\n' \
    "$TOOLS/bin" "$tightened_tool_bins" >&2
fi
if [ "$tools_tree_was_writable" -eq 1 ]; then
  # The directories are private now, but anything already inside them was
  # writable by another host user, so its --version answer proves nothing.
  # Quarantine it: needs_kiro_cli_install then reinstalls from the pinned,
  # SHA-verified archive instead of trusting what is on the volume.
  printf 'level=warn msg="quarantining kiro-cli binaries from a previously group/other-writable tools tree; forcing a pinned SHA-verified reinstall" dir="%s" component=entrypoint\n' "$TOOLS/bin" >&2
  sweep_legacy_dispatchers "$TOOLS/bin" || true
  # The update journal and its backups describe the very files just quarantined, and
  # their dot-prefixed names are outside the `kiro-cli*` glob the sweep uses. Drop
  # them here so the recovery pass below cannot restore a payload this boot has
  # already decided not to trust.
  # The install-completion marker is the same class of artifact: it lives one dir up from
  # the swept bin dir and is dot-prefixed, so neither the sweep's glob nor the survival
  # assertion below reaches it -- yet kiro_cli_dispatcher_set_complete reads it as the
  # authority on whether this pin's full set was promoted. A marker written while the tree
  # was foreign-writable must not answer that question; its absence is already a
  # first-class state (rc 2), and the reinstall below rewrites it at 0600.
  if ! rm -rf "$KIRO_CLI_INSTALL_MARKER" \
    "$KIRO_CLI_UPDATE_JOURNAL" "$BIN_PREV" "$CHAT_SIDECAR_PREV" "$KIRO_CLI_INSTALL_MARKER_PREV" \
    "$BIN_PREV.absent" "$CHAT_SIDECAR_PREV.absent" "$KIRO_CLI_INSTALL_MARKER_PREV.absent"; then
    printf 'level=warn msg="failed to remove the kiro-cli install-completion marker, update journal and backups from a previously group/other-writable tools tree" dir="%s" component=entrypoint\n' "$TOOLS" >&2
  fi
  # The sweep's status is deliberately always 0 (see the function's comment), so it
  # cannot answer "is the tainted payload gone". Check the invariant directly: an
  # immutable or separately-mounted file would survive the rm and then be trusted by
  # needs_kiro_cli_install's spoofable --version probe.
  for tainted in "$TOOLS/bin"/kiro-cli*; do
    [ -e "$tainted" ] || [ -L "$tainted" ] || continue
    fatal 'a tainted kiro-cli payload survived quarantine; refusing to trust its version output' "path=\"$tainted\""
  done
  # Same assertion as the loop above, for the artifacts the sweep's glob cannot
  # reach: a surviving journal or backup is restored INTO $BIN by the recovery pass
  # a few lines below, so leaving it is strictly worse than the kiro-cli* case the
  # loop already refuses.
  for tainted in "$KIRO_CLI_INSTALL_MARKER" "$KIRO_CLI_UPDATE_JOURNAL" \
    "$BIN_PREV" "$CHAT_SIDECAR_PREV" "$KIRO_CLI_INSTALL_MARKER_PREV" \
    "$BIN_PREV.absent" "$CHAT_SIDECAR_PREV.absent" "$KIRO_CLI_INSTALL_MARKER_PREV.absent"; do
    [ -e "$tainted" ] || [ -L "$tainted" ] || continue
    fatal 'a kiro-cli update journal or backup survived quarantine; refusing to let the boot recovery restore it over the pinned binary' "path=\"$tainted\""
  done
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
# `rm -rf` on an unmatched glob is already a silent no-op returning 0 (-f suppresses
# the missing-path diagnostic), so a non-zero status here is a REAL failure -- an
# immutable attribute, EPERM, a submount under the stage dir -- against the one
# thing this sweep exists to protect. Warn like both sibling sweeps
# (sweep_legacy_dispatchers, prune_superseded_kas_runtimes) instead of discarding it.
if ! rm -rf "$TOOLS"/.kiro-cli-stage.* "$TOOLS"/.write-probe.*; then
  printf 'level=warn msg="failed to remove orphaned boot-time temp artifacts; they keep occupying the /config volume" dir="%s" component=entrypoint\n' "$TOOLS" >&2
fi

# Repair an update that never committed, BEFORE anything on this volume is asked for
# a version: an interrupted promotion can pair the old $BIN with the new chat sidecar,
# and that set's --version answer is not merely stale but actively misleading (see
# KIRO_CLI_UPDATE_JOURNAL). Runs ahead of the bare-name identity check, the drift
# predicate and the readiness decision, all of which would otherwise read the mixed
# state. Warn-not-fatal, like the sweeps around it: a repair this boot could not
# finish keeps the journal, so the next boot retries it before anything reads a
# version off the volume.
#
# The result is RECORDED rather than discarded, and it is authoritative for the rest of
# boot. A failed rollback leaves the dispatcher set unverified AND leaves the original
# journal/backups as the only record of the pre-update set, so this boot must neither
# start a new transaction over that record (the install below is skipped) nor publish
# readiness over the mixed set (the readiness decision withholds the marker). Degraded,
# never fatal: the container stays up and repairable from inside, per "Failure posture".
kiro_cli_recovery_failed=0
recover_kiro_cli_update_journal || kiro_cli_recovery_failed=1

# Same hygiene argument, applied to the one residue class the sweep above omits:
# binaries an EARLIER image version staged into $HOME/.local/bin (that install ran with
# the real HOME; the current one stages off-PATH under $TOOLS). The reinstall path's
# quarantine only reaches them when this boot installs, so a container already at the
# pin would otherwise carry them until the next version bump -- tens of MB on /config,
# and an unpinned binary one PATH-shadow behind the canonical one. Warn, don't exit:
# the pinned binary is present and leads PATH here, so this is hygiene, not an
# integrity gate (the fatal treatment stays on the reinstall paths below).
sweep_legacy_dispatchers "$HOME/.local/bin" || true
# identity mode: this site asks only "does something OTHER than $BIN win bare-name
# resolution", which is the residue question the sweep above is about. It must NOT ask
# the version question -- on the first boot after a Renovate bump $BIN legitimately
# still holds the old version, and asking here produced two WARN lines per upgrade
# (one from the helper about a suspected unremovable binary, one from this caller)
# describing a condition that is expected, benign, and corrected seconds later by
# needs_kiro_cli_install's own `level=info msg="kiro-cli version drift; reinstalling"`.
# The drifted-$BIN cases that DO matter keep their signal elsewhere: the two
# post-install sites below use full mode (where a surviving unpinned $BIN really is
# dangerous, since the sweep has run), and a failed update logs its own warn naming
# both versions.
if ! resolves_to_pinned_kiro_cli identity; then
  printf 'level=warn msg="a kiro-cli other than the pinned binary is reachable by bare name after the boot sweep; residue may remain on the volume" dir="%s/.local/bin" component=entrypoint\n' "$HOME" >&2
fi

# Third hygiene sweep, same unconditional-every-boot argument, applied to the agent
# runtimes (see the function's comment for why they escape the two above). It runs in
# the readiness section below, once the version that will ACTUALLY run is known -- see
# the call site for why that placement still keeps at most one tree on disk.

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

# Publish the readiness marker /api/health gates on. Three branches below reach
# this point (a clean install and the two failed-update fallbacks); the warn text
# names /api/health and the marker path, so a copy that drifts makes a Loki query
# built on it silently miss boots. One writer, one wording.
publish_readiness_marker() {
  if ! touch "$KIRO_CLI_READY_MARKER"; then
    printf 'level=warn msg="failed to write kiro-cli readiness marker; /api/health will report kiro-cli unavailable" marker="%s" component=entrypoint\n' "$KIRO_CLI_READY_MARKER" >&2
  fi
}

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

  # The zip is ~528 MB (2.14.1, x86_64), so a flat --max-time is a BANDWIDTH FLOOR
  # rather than a hang guard, and it applies PER ATTEMPT, so retries only repeat the
  # same doomed transfer. Stall detection expresses the condition we actually care
  # about: abort only when throughput stays under --speed-limit for --speed-time
  # consecutive seconds. --max-time is an absolute backstop only (3600s => a
  # ~150 KB/s floor, ~1.2 Mbit/s), and --retry-max-time caps the retry envelope,
  # but only by barring the START of a new attempt: one begun just under 5400s
  # still runs to its own --max-time, so the download leg's true ceiling is
  # ~9000s rather than 5400s (see the Dockerfile HEALTHCHECK comment, kept in
  # lockstep). NOTE the HEALTHCHECK --start-period (20m) no longer covers the
  # worst-case window; that degrades safely because an unhealthy state
  # never restarts this container (restart policy acts on process exit), so a very
  # slow first boot shows unhealthy and then converges once the marker is written.
  if ! curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
    --connect-timeout 20 --speed-limit 4096 --speed-time 60 \
    --max-time 3600 --retry 3 --retry-delay 5 --retry-max-time 5400 \
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
  local actual expected sha_out sha_rc
  # Bounded like every other external command in this blocking foreground path:
  # no listener exists yet, so a wedged read (failing overlay store, IO pressure)
  # would otherwise stall boot forever with no diagnostic, and restart policies
  # never fire because nothing exits. The status is captured SEPARATELY from the
  # awk pipeline for the reason kiro_cli_version documents: awk exits 0 whatever
  # its producer did, so piping straight into it loses a TERM/KILL or an EIO and
  # renders the failure as an empty actual= in the mismatch error below.
  sha_out=$(timeout --signal=TERM --kill-after=15s 300s sha256sum "$zip")
  sha_rc=$?
  if [ "$sha_rc" -ne 0 ]; then
    if [ "$sha_rc" -eq 124 ] || [ "$sha_rc" -eq 137 ]; then
      printf 'level=error msg="sha256sum of the kiro-cli zip exceeded its 300s deadline and was terminated (wedged or very slow storage?)" rc=%d component=entrypoint\n' "$sha_rc" >&2
    else
      printf 'level=error msg="failed to read the kiro-cli zip for sha256 verification; cannot verify the pinned digest" path="%s" rc=%d component=entrypoint\n' "$zip" "$sha_rc" >&2
    fi
    return 1
  fi
  actual=$(printf '%s\n' "$sha_out" | awk '{print $1}')
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

  # Same deadline reasoning as the sha256sum above: half a gigabyte written
  # through the container layer, before any listener exists.
  local unzip_rc=0
  timeout --signal=TERM --kill-after=15s 600s unzip -q "$zip" -d "$tmpdir" || unzip_rc=$?
  if [ "$unzip_rc" -ne 0 ]; then
    if [ "$unzip_rc" -eq 124 ] || [ "$unzip_rc" -eq 137 ]; then
      printf 'level=error msg="unzip of the kiro-cli archive exceeded its 600s deadline and was terminated (wedged or very slow storage?)" rc=%d component=entrypoint\n' "$unzip_rc" >&2
    else
      printf 'level=error msg="failed to extract kiro-cli zip" rc=%d component=entrypoint\n' "$unzip_rc" >&2
    fi
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

  # Same invariant the sidecar promotions below assert, on the one dispatcher the app
  # cannot run without: `-f` follows symlinks, so a link into the staging tree would
  # pass here, pass the version probe, and be moved to $BIN as a LINK -- dangling the
  # moment the EXIT trap deletes $stage/$tmpdir, after this function logged a
  # successful promotion.
  if ! is_self_contained_executable "$staged"; then
    printf 'level=error msg="install.sh did not produce a self-contained executable kiro-cli binary (absent, not executable, or a symlink whose target dies with the staging cleanup)" path="%s" rc=%d component=entrypoint\n' \
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

  # Sidecars BEFORE the canonical binary, and the whole promotion inside the update
  # journal (see KIRO_CLI_UPDATE_JOURNAL). kiro-cli dispatches `chat` to the
  # kiro-cli-chat sidecar, so a missing or WRONG-VERSION one breaks every session
  # while `kiro-cli --version` (the readiness check) still succeeds -- health would
  # report ready over a terminal that cannot start. Ordering alone cannot prevent
  # that any more: download-then-swap keeps the old set live until each rename
  # lands, so an aborted sequence pairs the new sidecar with the OLD $BIN rather
  # than leaving $BIN absent. That is what the journal is for -- every failure
  # below restores the COMPLETE old set of the three REQUIRED components, and a kill
  # is repaired on the next boot. (The optional kiro-cli-term dispatcher is outside
  # the transaction and promoted after the commit; see its block below.)
  # PRESENCE is weaker than the invariant each dispatcher has to satisfy after
  # promotion: it must still be a self-contained regular executable once the
  # EXIT trap deletes $stage. A directory passes `mv` but cannot be executed,
  # and a symlink into the staging tree becomes dangling the moment the trap
  # fires -- in both cases $BIN is promoted, --version succeeds, and readiness
  # is published over a terminal that cannot dispatch `chat`. So require the
  # shape (regular file, not a symlink, executable) rather than mere existence.
  local chat_sidecar="$stage/.local/bin/kiro-cli-chat" term_sidecar="$stage/.local/bin/kiro-cli-term"
  if ! is_self_contained_executable "$chat_sidecar"; then
    printf 'level=error msg="install.sh produced no self-contained executable kiro-cli-chat sidecar dispatcher (upstream dispatcher set changed?); kiro-cli chat cannot start without it, so refusing to promote the dispatcher" src="%s" component=entrypoint\n' \
      "$chat_sidecar" >&2
    return 1
  fi
  # Open the transaction here: the last point before the first live rename, so a
  # failure to snapshot the old set costs only the update, never the volume.
  if ! kiro_cli_update_begin; then
    return 1
  fi
  if ! mv -f "$chat_sidecar" "$CHAT_SIDECAR"; then
    printf 'level=error msg="failed to promote the kiro-cli-chat sidecar dispatcher; kiro-cli chat cannot start without it, so refusing to promote the dispatcher" src="%s" dest="%s" component=entrypoint\n' \
      "$chat_sidecar" "$CHAT_SIDECAR" >&2
    kiro_cli_update_rollback
    return 1
  fi
  # Record install COMPLETION before the commit point, atomically. The required
  # dispatcher set is on disk now (chat sidecar promoted above; kiro-cli-term is
  # optional by design), so the marker is written in the one window where "the full
  # set for this pin is installed" is about to become true and nothing has yet
  # committed. The rename is atomic on the same filesystem, so a later boot never
  # reads a half-written version string; a crash on either side of it leaves the
  # journal open, and the next boot's recovery restores the whole old set rather
  # than reasoning about which halves landed. The stage-prefixed temp name is
  # deliberate: it is already covered by the every-boot orphan sweep near the top of
  # this file, so a SIGKILL between mktemp and mv leaves nothing permanent on
  # /config.
  local marker_tmp
  if ! marker_tmp=$(mktemp "$TOOLS/.kiro-cli-stage.marker.XXXXXX"); then
    printf 'level=error msg="failed to stage the kiro-cli install-completion marker; refusing to promote an install a later boot cannot verify" marker="%s" component=entrypoint\n' \
      "$KIRO_CLI_INSTALL_MARKER" >&2
    kiro_cli_update_rollback
    return 1
  fi
  if ! printf '%s\n' "$KIRO_CLI_VERSION" >"$marker_tmp" \
    || ! mv -f "$marker_tmp" "$KIRO_CLI_INSTALL_MARKER"; then
    rm -f "$marker_tmp"
    printf 'level=error msg="failed to publish the kiro-cli install-completion marker; refusing to promote an install a later boot cannot verify" marker="%s" component=entrypoint\n' \
      "$KIRO_CLI_INSTALL_MARKER" >&2
    kiro_cli_update_rollback
    return 1
  fi
  # Promote to the canonical /config/tools/bin/ location so PATH
  # ordering (which puts /config/tools/bin first) and any in-process
  # absolute-path references resolve to the freshly installed binary.
  mv -f "$staged" "$BIN" || {
    printf 'level=error msg="failed to promote kiro-cli binary to tools bin" src="%s" dest="%s" component=entrypoint\n' "$staged" "$BIN" >&2
    kiro_cli_update_rollback
    return 1
  }
  # The full set is promoted: assert it as a SET before declaring the transaction
  # committed, so a promotion that somehow landed an unusable dispatcher rolls back
  # instead of being kept. Then close the journal -- past this point the old set is
  # gone and the new one is what recovery would keep.
  if ! kiro_cli_dispatcher_set_complete; then
    printf 'level=error msg="the promoted kiro-cli dispatcher set did not verify as complete; rolling back to the previous set" pinned=%s component=entrypoint\n' \
      "$KIRO_CLI_VERSION" >&2
    kiro_cli_update_rollback
    return 1
  fi
  kiro_cli_update_finish
  # kiro-cli-term is optional (no session path launches it), so warn rather than fail --
  # but do not stay silent about it either. Same shape check as the chat dispatcher
  # above; an unusable one is skipped instead of promoted.
  #
  # Promoted AFTER the commit, deliberately: kiro_cli_update_begin snapshots only $BIN,
  # $CHAT_SIDECAR and the marker, so a term promotion inside the transaction window
  # survives every rollback and strands a NEWER-pin dispatcher beside the restored older
  # pair -- a mixed set the completeness check and the bare-name check both look past.
  # Past this point the new set is what recovery keeps, so a term failure can only be the
  # warn it already is.
  if [ ! -e "$term_sidecar" ] && [ ! -L "$term_sidecar" ]; then
    # This pin ships no term dispatcher, so any copy on the volume belongs to an
    # older version: it is a RETIRED name, and the retired-name sweep below skips
    # kiro-cli-term unconditionally, so reclaim it here or it stays first on PATH
    # (unpinned, wrong version) for the container's lifetime. Only THIS branch can
    # prove the name is retired for this pin: an invalid staged term or a failed mv
    # (below) may coexist with a good pinned copy already in place, and this path
    # holds no version fact about it.
    #
    # -L as well as -e, the file's idiom for "absent in any form" (and load-bearing
    # here because this is the only presence test that DELETES): -e is false for a
    # DANGLING staged link, which is an INVALID term handled by the next branch, not
    # evidence that this pin retired the name.
    printf 'level=warn msg="install.sh produced no optional kiro-cli-term sidecar dispatcher (upstream dispatcher set changed?); removing any copy left by an older version" sidecar="kiro-cli-term" component=entrypoint\n' >&2
    if ! rm -rf "$TOOLS/bin/kiro-cli-term"; then
      printf 'level=warn msg="failed to remove a kiro-cli-term dispatcher left by an older version; an unpinned copy stays first on PATH" path="%s" component=entrypoint\n' \
        "$TOOLS/bin/kiro-cli-term" >&2
    fi
  elif ! is_self_contained_executable "$term_sidecar"; then
    printf 'level=warn msg="install.sh produced an invalid optional kiro-cli-term sidecar dispatcher; skipping promotion" src="%s" sidecar="kiro-cli-term" component=entrypoint\n' \
      "$term_sidecar" >&2
  elif ! mv -f "$term_sidecar" "$TOOLS/bin/kiro-cli-term"; then
    printf 'level=warn msg="failed to promote the optional kiro-cli-term sidecar dispatcher; a legacy copy on PATH may win bare-name resolution" sidecar="kiro-cli-term" dest="%s" component=entrypoint\n' \
      "$TOOLS/bin/kiro-cli-term" >&2
  fi
  printf 'level=info msg="kiro-cli installed and promoted" version=%s path="%s" component=entrypoint\n' "$KIRO_CLI_VERSION" "$BIN" >&2
)

# 0 when the PERSISTED DISPATCHER SET is complete for the pinned version: the required
# kiro-cli-chat sidecar is a self-contained regular executable (not a symlink, whose
# staging-tree target would have died with the install's EXIT trap), and the
# install-completion marker names exactly the pin. Both callers already hold $BIN's
# --version answer, so version identity is deliberately NOT re-checked here: a second
# probe would add another 10s to the foreground boot allowance the Dockerfile
# HEALTHCHECK comment sums. The sidecar is checked by SHAPE rather than by asking it
# for a version flag it need not support.
kiro_cli_dispatcher_set_complete() {
  local recorded
  # rc 1: the sidecar itself is unusable, so `kiro-cli chat` -- the command every
  # session runs -- cannot dispatch. The terminal is BROKEN, and no caller may treat
  # that as tolerable.
  if ! is_self_contained_executable "$CHAT_SIDECAR"; then
    printf 'level=warn msg="required kiro-cli-chat sidecar dispatcher is missing or not a self-contained executable; kiro-cli chat cannot dispatch" path="%s" component=entrypoint\n' \
      "$CHAT_SIDECAR" >&2
    return 1
  fi
  # Read the marker only when it is a plain file we own: a symlink here would
  # let an off-mount target answer the completeness question the sidecar shape
  # check above deliberately refuses to take on trust.
  if [ -L "$KIRO_CLI_INSTALL_MARKER" ] || [ ! -f "$KIRO_CLI_INSTALL_MARKER" ]; then
    recorded=""
  else
    recorded=$(cat "$KIRO_CLI_INSTALL_MARKER" 2>/dev/null) || recorded=""
  fi
  # rc 2: the dispatcher set is USABLE but was not completed by this pin -- an
  # inherited pre-marker volume, or a set left by an earlier version. Kept distinct
  # from rc 1 because the terminal still works, so after a failed update the readiness
  # path may serve on it rather than answering 503 over a working shell.
  if [ "$recorded" != "$KIRO_CLI_VERSION" ]; then
    printf 'level=warn msg="kiro-cli install-completion marker absent or not at the pinned version; the persisted dispatcher set was never completed by this pin" marker="%s" recorded=%s pinned=%s component=entrypoint\n' \
      "$KIRO_CLI_INSTALL_MARKER" "${recorded:-none}" "$KIRO_CLI_VERSION" >&2
    return 2
  fi
  return 0
}

# Reinstall when the binary is missing, the on-disk version drifts from
# KIRO_CLI_VERSION, or the dispatcher SET the pin describes is incomplete. The
# binaries live on the persistent /config volume, so a freshly bumped image needs
# this drift check to actually pick up the new version on restart -- and an
# inherited volume needs the set check, because a main dispatcher that answers
# --version correctly is no evidence that `kiro-cli chat` can dispatch (a
# pre-marker partial promotion, a deleted sidecar, or an interrupted install all
# leave exactly that state, and the version-only predicate repaired none of them:
# it returned 1 forever while every session exited at chat).
needs_kiro_cli_install() {
  if ! is_self_contained_executable "$BIN"; then
    return 0
  fi
  local current
  current=$(kiro_cli_version "$BIN")
  # Publish what we just measured. The failed-update fallback below needs the
  # pre-install version to name it in its warning, and probing again would add a
  # fifth 10s --version call to the foreground boot allowance the Dockerfile
  # HEALTHCHECK comment sums. Empty when $BIN was absent (nothing to name) or when
  # the probe timed out, which both callers already treat as unknown.
  kiro_cli_measured_version="$current"
  if [ "$current" != "$KIRO_CLI_VERSION" ]; then
    printf 'level=info msg="kiro-cli version drift; reinstalling" installed=%s pinned=%s component=entrypoint\n' \
      "${current:-unknown}" "$KIRO_CLI_VERSION" >&2
    return 0
  fi
  if ! kiro_cli_dispatcher_set_complete; then
    printf 'level=info msg="kiro-cli dispatcher set incomplete for the pinned version; reinstalling" pinned=%s component=entrypoint\n' \
      "$KIRO_CLI_VERSION" >&2
    return 0
  fi
  return 1
}

# install_kiro_cli asserts app.disableAutoupdates through the STAGED binary
# against the real persisted HOME and refuses to promote without it, so a
# successful install has already put the setting in force. Remember that, so
# the redundant re-assertion below cannot withhold readiness over a transient
# settings flake. (install_kiro_cli's body is a subshell, so it cannot set this
# itself -- the caller records it from the exit status.)
kiro_cli_pin_asserted_at_install=0
# The version needs_kiro_cli_install measured off $BIN, published so the
# failed-update fallback can name it without a second 10s --version probe. Empty
# when $BIN was absent or the probe timed out.
kiro_cli_measured_version=""
# Set when an update failed but a usable earlier version stayed on the volume, so the
# readiness section can publish over the OLD version instead of withholding the marker
# and leaving a working terminal answering 503 for the container's lifetime.
kiro_cli_update_failed=0
if [ "${kiro_cli_recovery_failed:-0}" -eq 1 ] \
  || [ -e "$KIRO_CLI_UPDATE_JOURNAL" ] || [ -L "$KIRO_CLI_UPDATE_JOURNAL" ]; then
  # An earlier update could not be rolled back -- or its journal survived the attempt to
  # clear it -- so the journal and backups still on the volume are the only record of
  # the previous dispatcher set. Installing now would
  # start a transaction that deletes those backups and snapshots the already-mixed live
  # set (see kiro_cli_update_begin's own guard, which refuses this independently), and
  # a promotion failure would then roll back TO the mixed set. Skip the install and let
  # the next boot retry the repair with the evidence intact; readiness is withheld
  # below either way, so the container serves degraded rather than reporting healthy
  # over an unverified set.
  # The journal is tested DIRECTLY as well as through the recovery flag, and with the
  # same `-e OR -L` predicate as kiro_cli_update_begin and the readiness chain below:
  # recovery's no-transaction branch returns 0 unconditionally, so it reports success
  # even when kiro_cli_update_finish could not remove the journal (an immutable or
  # separately-mounted entry -- the write probe proves the DIRECTORY, not the entry).
  # Without the direct test that state downloads the ~528 MB zip on every boot only for
  # kiro_cli_update_begin to refuse it afterwards, blowing the HEALTHCHECK start-period
  # for nothing while readiness is withheld anyway. (`${...:-0}` matches the readiness
  # chain: the boot flag is out of scope when the chain is sourced standalone by
  # tests/shell.)
  printf 'level=warn msg="skipping the kiro-cli install: an earlier update could not be rolled back, or its journal could not be cleared, so its journal and backups are the only record of the previous dispatcher set; readiness stays withheld until a later boot completes the repair" journal="%s" pinned=%s component=entrypoint\n' \
    "$KIRO_CLI_UPDATE_JOURNAL" "$KIRO_CLI_VERSION" >&2
elif needs_kiro_cli_install; then
  # DOWNLOAD-THEN-SWAP. install_kiro_cli fetches the ~528 MB zip, verifies it
  # against the pinned sha, stages it off PATH under $TOOLS, and only then
  # promotes by rename -- and every promotion is `mv -f`, which replaces the old
  # file in place. So nothing on the volume is destroyed before a verified
  # replacement is in hand, and no window exists where $BIN is absent.
  #
  # This deliberately REVERSES the older ordering, which quarantined $TOOLS/bin
  # first so that a failed reinstall left no binary at all rather than a stale
  # unpinned one a session might silently launch. Two things decided it the other
  # way (user call, cycle-5 deferral d-u3c4-3): the destructive order turned any
  # download failure -- blocked egress, an upstream 404 on an older pin, a link
  # slow enough to trip --speed-limit -- into a container with NO terminal where
  # it previously had a working one, boot after boot; and this container IS the
  # operator's access path, so that failure mode removes the tool you would use to
  # repair it. A working old terminal beats a dead one.
  #
  # The cost is explicit: while an update keeps failing, the running version is
  # NOT the pinned one, so the pin is advisory rather than enforced. That is made
  # loud, not silent -- the warn below names both versions, and the readiness
  # section publishes the marker with a matching warn instead of pretending the
  # container is at the pin.
  # Reuse the version needs_kiro_cli_install just measured rather than probing
  # again: this block only runs when that predicate returned 0, so the value is
  # already in hand, and a second probe would cost another 10s of foreground boot
  # allowance for a string that appears in one log line.
  kiro_cli_previous="$kiro_cli_measured_version"
  if ! install_kiro_cli; then
    if is_self_contained_executable "$BIN"; then
      kiro_cli_update_failed=1
      if [ "$kiro_cli_previous" = "$KIRO_CLI_VERSION" ]; then
        # Not a version fallback: $BIN was already at the pin and the install was a
        # REPAIR of an incomplete dispatcher set (needs_kiro_cli_install's third
        # trigger). Naming it as a kept older version sends the operator at the pin
        # literals instead of at the sidecar/marker the readiness section reports on.
        printf 'level=warn msg="kiro-cli repair install failed; the binary already at the pin stays in place, but the dispatcher set it belongs to was not completed by this pin" installed=%s pinned=%s component=entrypoint\n' \
          "$kiro_cli_previous" "$KIRO_CLI_VERSION" >&2
      else
        printf 'level=warn msg="kiro-cli update failed; keeping the version already on the volume and continuing boot (the pin is NOT in force until an update succeeds)" installed=%s pinned=%s component=entrypoint\n' \
          "${kiro_cli_previous:-unknown}" "$KIRO_CLI_VERSION" >&2
      fi
    else
      printf 'level=warn msg="kiro-cli install failed and no previous version is present; web UI starts but the terminal errors until kiro-cli is present" component=entrypoint\n' >&2
    fi
    # Belt-and-braces: the installer ran with HOME pointed at the private stage, so it
    # should never have touched $HOME/.local/bin -- but that dir is on PATH and on the
    # persistent volume, and an installer that resolves its prefix via getpwuid rather
    # than $HOME would have. Sweeping here keeps a failed install from leaving an
    # unpinned binary reachable by bare-name resolution.
    sweep_legacy_dispatchers "$HOME/.local/bin" || true
    # Only a binary at some OTHER path is fatal (rc 1). rc 2 -- $BIN itself at the
    # previous version -- is precisely the fallback this ordering exists to allow, so
    # it must not abort the boot; aborting would replace a working terminal with a
    # 10s-throttled crash loop, which is the very outcome the reorder prevents.
    kiro_cli_resolve_rc=0
    resolves_to_pinned_kiro_cli || kiro_cli_resolve_rc=$?
    if [ "$kiro_cli_resolve_rc" -eq 1 ]; then
      fatal 'an unpinned kiro-cli outside the pinned path is reachable by bare name after a failed install; refusing to leave it resolvable for the container lifetime' "dir=\"$HOME/.local/bin\""
    fi
  else
    kiro_cli_pin_asserted_at_install=1
    # Post-promotion cleanup, now that the new set is committed. Two residue classes:
    # binaries an EARLIER image staged into $HOME/.local/bin (that install ran with the
    # real HOME; the current one stages off-PATH under $TOOLS), and any dispatcher name
    # the OLD version shipped that the new one does not -- the promotions overwrite
    # kiro-cli/-chat/-term by name, so a retired name would otherwise linger unpinned.
    sweep_legacy_dispatchers "$HOME/.local/bin" || true
    for stale in "$TOOLS/bin"/kiro-cli*; do
      [ -e "$stale" ] || [ -L "$stale" ] || continue
      case "${stale##*/}" in
        kiro-cli | kiro-cli-chat | kiro-cli-term) continue ;;
      esac
      if ! rm -rf "$stale"; then
        printf 'level=warn msg="failed to remove a retired kiro-cli dispatcher name left by an older version" path="%s" component=entrypoint\n' "$stale" >&2
      fi
    done
    # Post-condition on the committed state, with the SAME rc split the failed-install
    # site above uses. rc 1 -- something at another path wins bare-name resolution --
    # is the fatal condition: sessions would silently launch an unpinned binary. rc 2
    # cannot be a genuine version mismatch here (the staged binary answered the pin
    # before promotion and `mv -f` moved that same inode), so it means the --version
    # probe itself failed or hit its 10s deadline. Aborting on that turns a transient
    # probe timeout into a crash loop that re-downloads the ~528 MB zip on every retry,
    # while the state is self-healing: the readiness section below withholds the marker
    # whenever the observed version is not the pin, so the container serves degraded
    # (unhealthy, no restart loop) and stays repairable from inside.
    kiro_cli_postinstall_resolve_rc=0
    resolves_to_pinned_kiro_cli || kiro_cli_postinstall_resolve_rc=$?
    if [ "$kiro_cli_postinstall_resolve_rc" -eq 1 ]; then
      fatal 'an unpinned kiro-cli is still reachable by bare name after a successful install; refusing to leave it resolvable for the container lifetime' "path=\"$BIN\""
    elif [ "$kiro_cli_postinstall_resolve_rc" -ne 0 ]; then
      printf 'level=warn msg="the freshly promoted kiro-cli did not answer --version at the pinned version (probe failure or deadline); unless the readiness probe below recovers, readiness is withheld and the next boot reinstalls" path="%s" pinned=%s component=entrypoint\n' "$BIN" "$KIRO_CLI_VERSION" >&2
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
if is_self_contained_executable "$BIN"; then
  kiro_setting telemetry.enabled false
  # app.disableAutoupdates is not a preference: it is what keeps the running
  # binary from replacing itself and invalidating the verified sha. Unlike the
  # best-effort settings around it, a failure here is integrity-relevant.
  if ! kiro_setting app.disableAutoupdates true; then
    if [ "$kiro_cli_pin_asserted_at_install" -eq 1 ]; then
      # This boot's install already persisted the setting against the real HOME
      # (install_kiro_cli gates promotion on it), so a failure here is a flake in
      # a redundant re-assertion, not an unenforced pin. Warn instead of
      # withholding readiness, which would leave a correctly pinned container
      # answering 503 for its lifetime and fail the CI image-smoke job.
      printf 'level=warn msg="kiro-cli auto-update re-assertion failed but this boot already enforced it before promotion; readiness retained" version=%s component=entrypoint\n' "$KIRO_CLI_VERSION" >&2
    else
      kiro_cli_pin_enforced=0
    fi
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
if is_self_contained_executable "$BIN"; then
  kiro_cli_installed=$(kiro_cli_version "$BIN")
fi
# Reclaim superseded agent runtimes now that the version that will actually run is
# known: on a successful bump that is the pin, and on a failed update it is the older
# version this boot fell back to -- whose tree must survive, or its first session pays a
# ~240 MB re-unpack after every restart. Still before the exec and still at most one
# tree on disk (kiro-cli creates the new one on its first chat launch, after this
# script is gone), so the one-tree peak the earlier pre-install placement protected is
# unchanged.
prune_superseded_kas_runtimes "${kiro_cli_installed:-$KIRO_CLI_VERSION}" || true
# Resolved before the chain below, not inside it: `if ! cmd` leaves $? holding the
# NEGATED status, so the distinction between an unusable sidecar (rc 1) and a
# marker that predates the pin (rc 2) is unreadable from inside the branch. The
# helper spawns nothing -- a file shape test plus a cat -- so calling it here costs
# no boot allowance even on paths that end up not consulting it.
kiro_cli_set_rc=0
kiro_cli_dispatcher_set_complete || kiro_cli_set_rc=$?
if [ "${kiro_cli_recovery_failed:-0}" -eq 1 ] \
  || [ -e "$KIRO_CLI_UPDATE_JOURNAL" ] || [ -L "$KIRO_CLI_UPDATE_JOURNAL" ]; then
  # FIRST, ahead of every version and set fallback below: an unresolved update
  # transaction makes the on-disk dispatcher set unverified BY CONSTRUCTION -- an old
  # $BIN can sit beside an already-promoted new chat sidecar, and neither the version
  # probe nor the set check version-probes the sidecar. Both the "looks clean" branch
  # (right version, complete set) and the two failed-update fallbacks would otherwise
  # publish readiness over exactly that state: the clean branch never consults the
  # journal at all, and a failed rollback can leave the mixed set looking whole.
  # Withhold instead, and say so -- the next boot's recovery pass repairs the set and
  # publishes then. (`${...:-0}` because the readiness chain is also sourced standalone
  # by tests/shell, where the boot flag above is out of scope; a symlink counts as an
  # open journal for the same reason recovery distrusts one.)
  printf 'level=warn msg="an unresolved kiro-cli update transaction is on the volume, so the dispatcher set is unverified; readiness marker withheld and /api/health will report kiro-cli unavailable until a later boot completes the repair" journal="%s" installed=%s pinned=%s component=entrypoint\n' \
    "$KIRO_CLI_UPDATE_JOURNAL" "${kiro_cli_installed:-none}" "$KIRO_CLI_VERSION" >&2
elif [ "$kiro_cli_installed" != "$KIRO_CLI_VERSION" ]; then
  if [ "$kiro_cli_update_failed" -eq 1 ] && [ -n "$kiro_cli_installed" ] && [ "$kiro_cli_set_rc" -ne 1 ] \
    && [ ! -e "$KIRO_CLI_UPDATE_JOURNAL" ] && [ ! -L "$KIRO_CLI_UPDATE_JOURNAL" ]; then
    # An update failed and the previous version is still installed and answering
    # --version. The terminal genuinely works, so readiness describes the terminal:
    # withholding here would mean a container that boots, serves a working shell, and
    # still reports 503 for its lifetime -- the availability trade taken deliberately
    # in the install block above. The pin is NOT in force; that is what the warn says,
    # and the version is named so Loki shows exactly what is running.
    # set_rc 1 is excluded deliberately: an executable $BIN is not a working terminal
    # when the chat sidecar it dispatches to is unusable, and the fallback must
    # describe a COMPLETE old dispatcher set, not merely a launchable main dispatcher
    # (set_rc 2 -- the marker naming the pre-update version -- is the fallback's own
    # expected state and still publishes).
    # A still-OPEN update journal is excluded for the same reason: it means the
    # promotion neither committed nor rolled back, so the on-disk set is unverified
    # by construction -- an old $BIN can sit beside an already-promoted NEW chat
    # sidecar, which the set check deliberately never version-probes. Every commit
    # and every completed rollback closes the journal (kiro_cli_update_finish), so
    # this only excludes a double fault (failed update AND failed rollback); the
    # next boot's recovery pass repairs the set and publishes then.
    printf 'level=warn msg="serving a kiro-cli version older than the pin after a failed update; readiness published because the terminal works, but the pin is NOT in force until an update succeeds" installed=%s pinned=%s component=entrypoint\n' \
      "$kiro_cli_installed" "$KIRO_CLI_VERSION" >&2
    publish_readiness_marker
  else
    # Withholding the marker is otherwise a silent signal: /api/health answers 503
    # and the container sits `unhealthy` forever (readiness, not liveness) with no
    # reason in Loki. Log the observed version so a wedged --version (timeout) is
    # distinguishable from a missing binary or a genuine version mismatch.
    printf 'level=warn msg="kiro-cli not verified at pinned version; readiness marker withheld and /api/health will report kiro-cli unavailable" installed=%s pinned=%s component=entrypoint\n' \
      "${kiro_cli_installed:-none}" "$KIRO_CLI_VERSION" >&2
  fi
elif [ "$kiro_cli_set_rc" -ne 0 ]; then
  if [ "$kiro_cli_update_failed" -eq 1 ] && [ "$kiro_cli_set_rc" -eq 2 ] \
    && [ ! -e "$KIRO_CLI_UPDATE_JOURNAL" ] && [ ! -L "$KIRO_CLI_UPDATE_JOURNAL" ]; then
    # $BIN is at the pin and the chat sidecar is usable; only the completion marker
    # does not name this pin (an inherited pre-marker volume). The update that would
    # have written it failed, so serve the working terminal rather than answering 503
    # over it. rc 1 -- an unusable sidecar -- deliberately does NOT land here: there
    # the terminal really is broken, so readiness must still be withheld. An open
    # update journal is excluded here for the same reason as in the branch above: an
    # un-rolled-back promotion leaves a set nothing has verified.
    printf 'level=warn msg="kiro-cli dispatcher set predates this pin and the update that would complete it failed; readiness published because the terminal works" version=%s component=entrypoint\n' \
      "$KIRO_CLI_VERSION" >&2
    publish_readiness_marker
  else
    # $BIN is at the pin, but the dispatcher SET is not complete: `kiro-cli --version`
    # succeeds while `kiro-cli chat` -- the command every session runs -- cannot
    # dispatch. Readiness must describe the terminal, not the version probe, or health
    # stays green over a container whose every session exits immediately. The helper
    # already logged which half is missing (sidecar or completion marker).
    printf 'level=warn msg="kiro-cli dispatcher set incomplete for the pinned version; readiness marker withheld and /api/health will report kiro-cli unavailable" version=%s component=entrypoint\n' \
      "$KIRO_CLI_VERSION" >&2
  fi
elif [ "$kiro_cli_pin_enforced" -ne 1 ]; then
  # Right version on disk, but auto-update could not be turned off: the binary
  # may replace itself mid-session and invalidate the pinned sha, so the version
  # just observed guarantees nothing for the container's lifetime. Withhold
  # readiness for the same reason a version mismatch does.
  printf 'level=warn msg="kiro-cli auto-update could not be disabled; readiness marker withheld because the binary may replace itself and invalidate the pinned digest" version=%s component=entrypoint\n' \
    "$KIRO_CLI_VERSION" >&2
else
  printf 'level=info msg="kiro-cli verified at pinned version; publishing readiness marker" version=%s component=entrypoint\n' "$KIRO_CLI_VERSION" >&2
  publish_readiness_marker
fi

# OS packages (APT_PACKAGES env, e.g. "python3 gcc libc6-dev"). apt state
# lives in the ephemeral container layer — never on /config — so it is
# re-applied on every container start: compose-level intent, not volume
# intent. Everything else in /config/tools is owned by the server's
# toolbelt engine (manifest: /config/tools.json v2), which converges in
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
    timeout --signal=TERM --kill-after=30s 300s apt-get update -qq || apt_update_rc=$?
    if [ "$apt_update_rc" -eq 124 ] || [ "$apt_update_rc" -eq 137 ]; then
      # 124/137 = the 300s deadline (TERM, then the --kill-after SIGKILL fallback),
      # named distinctly for the same reason every sibling timeout here does: a
      # stalled mirror and an index apt rejected outright call for different
      # operator action, and the generic wording cannot tell them apart.
      printf 'level=warn msg="apt-get update exceeded its 300s deadline and was terminated; APT_PACKAGES install may fail and the known-name check is skipped" rc=%d component=entrypoint\n' "$apt_update_rc" >&2
    elif [ "$apt_update_rc" -ne 0 ]; then
      printf 'level=warn msg="apt-get update failed; APT_PACKAGES install may fail and the known-name check is skipped" rc=%d component=entrypoint\n' "$apt_update_rc" >&2
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
    apt_gate_ran=0
    if [ "$apt_update_rc" -eq 0 ]; then
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
        printf 'level=warn msg="apt-cache pkgnames exceeded its 60s deadline and was terminated; installing APT_PACKAGES without the known-name check" rc=%d component=entrypoint\n' "$apt_names_rc" >&2
      fi
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
      elif [ "$apt_names_rc" -ne 124 ] && [ "$apt_names_rc" -ne 137 ]; then
        printf 'level=warn msg="apt package index unreadable; installing APT_PACKAGES without the known-name check" component=entrypoint\n' >&2
      fi
      [ -z "$apt_names" ] || rm -f "$apt_names"
    fi

    # Whenever the gate could NOT run -- a failed apt-get update above OR an
    # unreadable index -- skipping it is still the right failure mode: rejecting
    # every token would turn a transient problem into "none of your packages
    # installed" plus a misleading per-token typo warning, and the grammar still
    # holds. But the pre-gate behaviour is exactly what leaves the 337-package
    # regex blowup described above reachable, so it degrades with ONE narrowing.
    #
    # '.' is the only apt pattern metacharacter the grammar admits ('?' and '*' are
    # outside its character class), so a dotted token is the only one that can be
    # reinterpreted as a regex -- and it is precisely the token the gate exists to
    # verify as literal. Dropping just those removes the blowup while every plain
    # name still installs, which is the common case and the reason the
    # skip-everything option was rejected.
    #
    # Handled here rather than inside either branch so the two ways of losing the
    # gate cannot drift apart: the likelier one is a PARTIAL apt-get update failure
    # (some mirrors fine, non-zero exit, index still usable), which is also the only
    # state where the blowup is actually reachable -- with no index at all, apt
    # resolves nothing and a regex matches nothing either.
    #
    # The cost is narrow and self-healing: a real dotted name (docker.io,
    # python3.13) waits for a boot whose index is readable, which is a boot where
    # the install was going to be unreliable anyway. Per "a broken state must be
    # able to heal itself", the next boot's gate installs it.
    if [ "$apt_gate_ran" -eq 0 ] && [ "${#apt_pkgs[@]}" -gt 0 ]; then
      ungated_pkgs=()
      for pkg in "${apt_pkgs[@]}"; do
        if [[ "$pkg" == *.* ]]; then
          warn_skipped_apt_token 'skipping dotted APT_PACKAGES token while the known-name check is unavailable (a dot is an apt regex metacharacter; retry once the package index is readable)' "$pkg"
        else
          ungated_pkgs+=("$pkg")
        fi
      done
      apt_pkgs=("${ungated_pkgs[@]}")
    fi
  fi
  if [ "${#apt_pkgs[@]}" -gt 0 ]; then
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

# Hand the image's PATH back so the server and its PTY sessions keep the engine-managed
# /config/tools/bin first, as the Dockerfile ENV and the toolbelt engine expect.
PATH="$SESSION_PATH"
export PATH
exec /app/web-terminal-kiro
