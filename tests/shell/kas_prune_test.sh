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

# shellcheck disable=SC1090
. "$(extract_function prune_superseded_kas_runtimes)"

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
plant_victim() {
  mkdir -p "$1/2.13.0-victim" && : >"$1/2.13.0-victim/data"
}

setup
VICTIM="$ROOT/victim"
plant_victim "$VICTIM"
rm -rf "$KAS"
mkdir -p "$XDG_DATA_HOME/kiro-cli"
ln -s "$VICTIM" "$KAS" # kas -> an arbitrary tree
prune_superseded_kas_runtimes >/dev/null 2>&1
[ -f "$VICTIM/2.13.0-victim/data" ] \
  && ok "symlinked kas store refused; the victim tree survived" \
  || no "symlinked kas store" "the pruner deleted through the symlink (root rm -rf)"

setup
VICTIM="$ROOT/victim2"
plant_victim "$VICTIM"
rm -rf "$XDG_DATA_HOME/kiro-cli"
ln -s "$VICTIM" "$XDG_DATA_HOME/kiro-cli" # the data dir itself is the symlink
prune_superseded_kas_runtimes >/dev/null 2>&1
[ -f "$VICTIM/2.13.0-victim/data" ] \
  && ok "symlinked data dir refused; the victim tree survived" \
  || no "symlinked data dir" "the pruner deleted through the symlink (root rm -rf)"

# The containment check is a SECOND, independent guard, and this case isolates it:
# NO symlink is involved anywhere, so the -L guard above cannot fire. A
# non-canonical XDG_DATA_HOME (one carrying "..", which an operator env var
# legitimately can) makes realpath disagree with the literal path the case pattern
# is built from, and the pruner refuses rather than deleting against a path it
# cannot confirm.
#
# Isolating it matters: the two guards are redundant, so removing EITHER alone
# leaves the tree intact. That redundancy is what let the earlier vacuous version
# of this test go unnoticed, and it is why the outcome is asserted from two
# independent directions instead of once.
setup
mkdir -p "$ROOT/real-share"
XDG_DATA_HOME="$ROOT/real-share/../real-share"
KAS="$XDG_DATA_HOME/kiro-cli/kas"
mkdir -p "$KAS"
plant_victim "$KAS"
prune_superseded_kas_runtimes >/dev/null 2>&1
[ -f "$KAS/2.13.0-victim/data" ] \
  && ok "non-canonical data-dir path refused (no symlink involved)" \
  || no "containment check" "pruned against a path realpath could not confirm"

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
