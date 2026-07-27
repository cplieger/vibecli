#!/usr/bin/env bash
# secure_tools_dir(): tighten what we can, and never brick boot over a tree the
# entrypoint does not own.
#
# The third argument encodes the app's failure posture (see the steering doc's
# "Failure posture" section). owned=1 is for the three directories the entrypoint
# creates and a reinstall repairs — /config, $TOOLS, $TOOLS/bin — where aborting is
# right because the state is ours and self-healing. owned=0 is for the legacy PATH
# segments it never creates, never repairs, and which hold no integrity-gated
# binary: this is a dev box whose operator reshapes /config on purpose, and `fatal`
# sleeps 10s and exits, so a boot that aborts on operator-owned state leaves no way
# in to fix it.
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

load_function secure_tools_dir

# fatal() is the abort under test: record the call and return non-zero so the caller
# unwinds the way `exit` would, without killing this harness.
FATALED=0
fatal() {
  FATALED=1
  return 1
}
tools_tree_was_writable=0

# run <owned> <shape-setup...> -> sets FATALED and RC
attempt() {
  local dir=$1 owned=$2
  FATALED=0
  tools_tree_was_writable=0
  secure_tools_dir "$dir" 0 "$owned" >/dev/null 2>&1
  RC=$?
}

mk() {
  ROOT=$(mktemp -d "$WORK/t.XXXXXX")
  printf '%s' "$ROOT"
}

# --- unowned (legacy PATH segments): must NEVER abort ---------------------------
R=$(mk) && ln -s /nonexistent-target "$R/seg"
attempt "$R/seg" 0
[ "$FATALED" -eq 0 ] && ok "unowned symlink: warns, does not abort" \
  || no "unowned symlink" "aborted boot on a dir the entrypoint does not own"

R=$(mk) && : >"$R/seg"
attempt "$R/seg" 0
[ "$FATALED" -eq 0 ] && ok "unowned plain file: warns, does not abort" \
  || no "unowned plain file" "aborted boot"

R=$(mk) && mkdir -p "$R/seg" && chmod 0777 "$R/seg"
attempt "$R/seg" 0
if [ "$FATALED" -eq 0 ]; then
  ok "unowned world-writable: warns, does not abort"
else
  no "unowned world-writable" "aborted boot"
fi
# ...and it still TIGHTENS the mode, which is the part worth keeping.
MODE=$(stat -c '%a' "$R/seg" 2>/dev/null)
[ $((8#$MODE & 0022)) -eq 0 ] && ok "unowned world-writable: still tightened to $MODE" \
  || no "unowned tightening" "mode left at $MODE"

R=$(mk) && mkdir -p "$R/seg" && chmod 0755 "$R/seg"
attempt "$R/seg" 0
[ "$FATALED" -eq 0 ] && [ "$RC" -eq 0 ] && ok "unowned already-clean: no-op" \
  || no "unowned clean" "rc=$RC fataled=$FATALED"

# --- owned (/config, $TOOLS, $TOOLS/bin): must STILL abort ----------------------
R=$(mk) && ln -s /nonexistent-target "$R/owned"
attempt "$R/owned" 1
[ "$FATALED" -eq 1 ] && ok "owned symlink: still aborts" \
  || no "owned symlink" "did not abort -- the security gate was weakened"

R=$(mk) && : >"$R/owned"
attempt "$R/owned" 1
[ "$FATALED" -eq 1 ] && ok "owned plain file: still aborts" \
  || no "owned plain file" "did not abort"

R=$(mk) && mkdir -p "$R/owned" && chmod 0755 "$R/owned"
attempt "$R/owned" 1
[ "$FATALED" -eq 0 ] && ok "owned already-clean: no-op" || no "owned clean" "aborted"

# The owned + arm=1 path must still arm the kiro-cli quarantine on a writable tree.
R=$(mk) && mkdir -p "$R/owned" && chmod 0777 "$R/owned"
FATALED=0
tools_tree_was_writable=0
secure_tools_dir "$R/owned" 1 1 >/dev/null 2>&1
[ "$tools_tree_was_writable" -eq 1 ] && ok "owned writable + arm=1: quarantine armed" \
  || no "quarantine arm" "tools_tree_was_writable not set"

# The unowned path must NOT arm the quarantine (these trees never hold kiro-cli).
R=$(mk) && mkdir -p "$R/seg" && chmod 0777 "$R/seg"
attempt "$R/seg" 0
[ "$tools_tree_was_writable" -eq 0 ] && ok "unowned writable: quarantine NOT armed" \
  || no "unowned quarantine" "armed a kiro-cli quarantine for a tree that holds none"

report
