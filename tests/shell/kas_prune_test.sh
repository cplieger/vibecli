#!/usr/bin/env bash
# prune_superseded_kas_runtimes(): reclaim the ~240 MB agent-server runtime each
# kiro-cli version unpacks, keeping only the pinned one.
#
# This function is a root `rm -rf` against a path derived from the environment, so
# the redirect cases carry the weight: a symlinked store, an unset HOME, a version
# string that could widen the keep-pattern. It is also hygiene, never an integrity
# gate — it warns and continues rather than failing boot, because disk cleanup must
# not brick a container.
# Lint directives for this whole file, each against a stated guarantee rather than
# an assumption:
#   SC2015 - the assertion form `[ cond ] && ok "..." || no "..."` cannot mis-fire,
#     because lib.sh's ok/no return 0 unconditionally by design (see their comment).
#   SC2034 - the variables set below are the INPUTS to entrypoint.sh code that is
#     extracted and sourced at RUNTIME, so shellcheck cannot see the reads.
# shellcheck disable=SC2015,SC2034
set -u

# shellcheck source-path=SCRIPTDIR
. "$(dirname -- "$0")/lib.sh"
new_workdir >/dev/null

load_function logfmt_value
load_function prune_superseded_kas_runtimes

KIRO_CLI_VERSION="2.14.2"

# Fresh fake volume per scenario. XDG_DATA_HOME drives the resolution, matching how
# kiro-cli locates its own data dir.
setup() {
  ROOT=$(mktemp -d "$WORK/vol.XXXXXX")
  export XDG_DATA_HOME="$ROOT/share"
  KAS="$XDG_DATA_HOME/kiro-cli/kas"
  mkdir -p "$KAS"
}

# --- 1. ordinary prune: superseded versions go, the pinned one stays -------------
setup
mkdir -p "$KAS/2.14.2-abc" "$KAS/2.13.0-def" "$KAS/2.12.1-ghi"
: >"$KAS/2.13.0-def.lock"
prune_superseded_kas_runtimes >/dev/null 2>&1
[ -d "$KAS/2.14.2-abc" ] && ok "pinned runtime kept" || no "pinned runtime kept" "it was deleted"
[ ! -d "$KAS/2.13.0-def" ] && [ ! -d "$KAS/2.12.1-ghi" ] \
  && ok "superseded runtimes pruned" || no "superseded runtimes pruned" "still present"
[ ! -e "$KAS/2.13.0-def.lock" ] && ok "the superseded .lock sibling pruned too" \
  || no ".lock sibling" "still present"

# --- 1b. the keep version is an ARGUMENT, not always the pin ---------------------
# A failed update keeps SERVING the version already on the volume, so the call site
# passes the running version and this tree must survive while the pinned-but-absent
# one does not. Without this case every invocation defaulted to the pin, so dropping
# `$1` (or the call site's argument) left all assertions green while restoring the
# repeated ~240 MB prune/re-unpack on every boot.
setup
mkdir -p "$KAS/2.14.2-pin" "$KAS/2.13.0-running"
prune_superseded_kas_runtimes "2.13.0" >/dev/null 2>&1
[ -d "$KAS/2.13.0-running" ] && [ ! -d "$KAS/2.14.2-pin" ] \
  && ok "failed-update fallback keeps the running version rather than the pin" \
  || no "running-version keep" "running tree was pruned or the non-running pin tree survived"

# --- 2. non-version-keyed entries are kiro-cli's, not ours ----------------------
setup
mkdir -p "$KAS/2.14.2-abc" "$KAS/unpack-scratch" "$KAS/index"
: >"$KAS/store.lock"
prune_superseded_kas_runtimes >/dev/null 2>&1
if [ -d "$KAS/unpack-scratch" ] && [ -d "$KAS/index" ] && [ -e "$KAS/store.lock" ]; then
  ok "unrecognized (non version-keyed) entries left alone"
else
  no "unrecognized entries" "the pruner deleted another program's state"
fi

# --- 3. THE SECURITY CASE: a symlinked store must not redirect a root rm -rf ----
#
# The victim tree's contents are DELIBERATELY version-keyed and non-pinned
# ("2.13.0-victim"), i.e. exactly the shape the pruner deletes. An earlier version
# of this test planted a directory named "precious", which the pruner skips anyway
# because it is not version-keyed -- so the assertion passed even with every
# symlink guard removed, and proved nothing. A guard test has to plant bait the
# unguarded code would actually take.
#
# Bait has to satisfy the EARLIER guards too, which the data-dir case got wrong for
# longer: the pruner returns at `[ -d "$kas_dir" ]` before it looks at any symlink,
# so a victim with no `kas` child was never reached and that case also passed with
# every guard removed. Each case below plants the version-keyed entries at the
# exact path the resolved $kas_dir names.
plant_victim() {
  mkdir -p "$1/2.13.0-victim" && : >"$1/2.13.0-victim/data"
}

# Survival alone cannot say WHICH guard refused, and for this threat the two are
# redundant: realpath resolves a symlink away, so every redirect the -L check
# catches ALSO fails the containment check. No input isolates -L by outcome, and
# removing it on its own left this file 10/10 green. What the guards do not share is
# what they SAY, so each case asserts its own refusal line; drop the -L check and
# the symlink cases report the containment refusal instead, and fail here.
guard_said() {
  grep -q "$1" "$WORK/warn.log"
}

prune_quietly() {
  prune_superseded_kas_runtimes 2>"$WORK/warn.log" >/dev/null
}

setup
VICTIM="$ROOT/victim"
plant_victim "$VICTIM"
rm -rf "$KAS"
mkdir -p "$XDG_DATA_HOME/kiro-cli"
ln -s "$VICTIM" "$KAS" # kas -> an arbitrary tree
prune_quietly
[ -f "$VICTIM/2.13.0-victim/data" ] && guard_said 'is a symlink' \
  && ok "symlinked kas store refused BY the symlink guard; the victim tree survived" \
  || no "symlinked kas store" "the pruner deleted through the symlink, or a different guard caught it"

setup
VICTIM="$ROOT/victim2"
# The victim's version-keyed entries sit under a real `kas` child, because that is
# what $kas_dir resolves to once `kiro-cli` is the symlink -- without it the `-d`
# check returns first and no guard is exercised at all.
plant_victim "$VICTIM/kas"
rm -rf "$XDG_DATA_HOME/kiro-cli"
ln -s "$VICTIM" "$XDG_DATA_HOME/kiro-cli" # the data dir itself is the symlink
prune_quietly
[ -f "$VICTIM/kas/2.13.0-victim/data" ] && guard_said 'is a symlink' \
  && ok "symlinked data dir refused BY the symlink guard; the victim tree survived" \
  || no "symlinked data dir" "the pruner deleted through the symlink, or a different guard caught it"

# The containment check is a SECOND, independent guard, and this case isolates it:
# NO symlink is involved anywhere, so the -L guard above cannot fire. A
# non-canonical XDG_DATA_HOME (one carrying "..", which an operator env var
# legitimately can) makes realpath disagree with the literal path the case pattern
# is built from, and the pruner refuses rather than deleting against a path it
# cannot confirm.
setup
mkdir -p "$ROOT/real-share"
XDG_DATA_HOME="$ROOT/real-share/../real-share"
KAS="$XDG_DATA_HOME/kiro-cli/kas"
mkdir -p "$KAS"
plant_victim "$KAS"
prune_quietly
[ -f "$KAS/2.13.0-victim/data" ] && guard_said 'does not resolve inside the data dir' \
  && ok "non-canonical data-dir path refused BY the containment guard (no symlink involved)" \
  || no "containment check" "pruned against a path realpath could not confirm, or a different guard caught it"

# --- 4. degenerate inputs must not fail the boot --------------------------------
setup
prune_superseded_kas_runtimes >/dev/null 2>&1
[ $? -eq 0 ] && ok "empty store returns 0" || no "empty store" "non-zero return"

setup
rm -rf "$XDG_DATA_HOME"
prune_superseded_kas_runtimes >/dev/null 2>&1
[ $? -eq 0 ] && ok "absent data dir returns 0" || no "absent data dir" "non-zero return"

setup
unset XDG_DATA_HOME
HOME_SAVED="${HOME:-}"
unset HOME
prune_superseded_kas_runtimes >/dev/null 2>&1
rc=$?
export HOME="$HOME_SAVED"
[ "$rc" -eq 0 ] && ok "unset HOME returns 0 instead of aborting under set -u" \
  || no "unset HOME" "returned $rc"

report
