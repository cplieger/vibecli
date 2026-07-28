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
#   SC2329 - the stat/chmod stubs below are invoked INDIRECTLY, by the extracted
#     function they shadow, which shellcheck cannot see.
# shellcheck disable=SC2015,SC2329
set -u

# shellcheck source-path=SCRIPTDIR
. "$(dirname -- "$0")/lib.sh"
new_workdir >/dev/null

load_function secure_tools_dir

# fatal() is the abort under test: record the call and return non-zero instead of
# killing this harness. It does NOT unwind the way `exit` would -- every call site in
# secure_tools_dir is a bare `fatal ...`, so the function keeps running and the later
# guards fire too (a dangling symlink at an owned dir records THREE refusals in one
# call). FATALED therefore only answers "something refused"; FATAL_FIRST records the
# refusal production would have exited on, and that is the oracle the owned cases use
# wherever more than one guard can catch the same bait.
FATALED=0
FATAL_FIRST=""
fatal() {
  FATALED=1
  [ -n "$FATAL_FIRST" ] || FATAL_FIRST=$1
  return 1
}
tools_tree_was_writable=0

# run <owned> <shape-setup...> -> sets FATALED, RC, and WARNLOG
# stderr is kept per attempt: several assertions below claim a WARNING, and a
# warning claim that only inspects FATALED stays green when the warn line itself
# is deleted -- the loud degraded-mode signal is the contract, so the log is the
# observable.
attempt() {
  local dir=$1 owned=$2
  FATALED=0
  FATAL_FIRST=""
  tools_tree_was_writable=0
  WARNLOG="$WORK/warn.log"
  secure_tools_dir "$dir" 0 "$owned" >/dev/null 2>"$WARNLOG"
  RC=$?
}

warned() {
  grep -Fq "$1" "$WARNLOG"
}

mk() {
  ROOT=$(mktemp -d "$WORK/t.XXXXXX")
  printf '%s' "$ROOT"
}

# --- unowned (legacy PATH segments): must NEVER abort ---------------------------
R=$(mk) && ln -s /nonexistent-target "$R/seg"
attempt "$R/seg" 0
[ "$FATALED" -eq 0 ] && warned 'is a symlink; skipping it' \
  && ok "unowned symlink: warns, does not abort" \
  || no "unowned symlink" "fataled=$FATALED, warn log: $(cat "$WARNLOG")"

R=$(mk) && : >"$R/seg"
attempt "$R/seg" 0
[ "$FATALED" -eq 0 ] && warned 'is not a directory; skipping it' \
  && ok "unowned plain file: warns, does not abort" \
  || no "unowned plain file" "fataled=$FATALED, warn log: $(cat "$WARNLOG")"

R=$(mk) && mkdir -p "$R/seg" && chmod 0777 "$R/seg"
attempt "$R/seg" 0
if [ "$FATALED" -eq 0 ] && warned 'permits group/other writes; tightening it (no kiro-cli quarantine'; then
  ok "unowned world-writable: warns, does not abort"
else
  no "unowned world-writable" "fataled=$FATALED, warn log: $(cat "$WARNLOG")"
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
# The refusal MESSAGE is the oracle here, not FATALED: a symlink also fails the
# not-a-directory check when it dangles, and fails the mode check when it does not
# (stat does not dereference, and a symlink's own mode is 0777), so no bait isolates
# the -L guard by outcome -- with the branch deleted this case stayed green. Naming
# the message is what makes it able to fail, the same reason kas_prune_test.sh
# asserts which refusal its two redundant guards emitted.
R=$(mk) && ln -s /nonexistent-target "$R/owned"
attempt "$R/owned" 1
[ "$FATAL_FIRST" = 'refusing to use a symlinked tools directory; its target may be outside the /config mount' ] \
  && ok "owned symlink: aborts BY the symlink guard" \
  || no "owned symlink" "first refusal was '$FATAL_FIRST', not the symlink guard -- the security gate was weakened"

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

# --- the owned fail-CLOSED postconditions: mode that cannot be PROVED clean -------
# These three are the point of the whole gate: the tree holds the first-on-PATH
# kiro-cli, so an unprovable or unfixable mode must stop the boot. Each failure is
# forced with a scoped stub for exactly one call shape; the filesystem cases above
# keep using the real commands.

# stat fails outright: the mode cannot be read, so it cannot be proved clean.
R=$(mk) && mkdir -p "$R/owned" && chmod 0755 "$R/owned"
stat() { return 1; }
attempt "$R/owned" 1
unset -f stat
[ "$FATALED" -eq 1 ] && ok "owned unreadable mode: fails closed instead of assuming clean" \
  || no "owned unreadable mode" "did not abort when stat failed"

# chmod is a no-op (an immutable or foreign-fs tree): the re-read still sees the
# write bits, and an owned tree that RESISTS tightening must stop the boot.
R=$(mk) && mkdir -p "$R/owned" && chmod 0777 "$R/owned"
chmod() { return 0; }
attempt "$R/owned" 1
unset -f chmod
[ "$FATALED" -eq 1 ] && ok "owned tighten-resistant tree: fails closed on the re-read" \
  || no "owned tighten-resistant" "kept trusting a tree that stayed group/other-writable"

# stat succeeds before tightening and fails after: the RESULT cannot be verified.
# The call count lives in a FILE because the function runs inside the extracted
# code's command substitutions -- a shell variable incremented there dies with the
# subshell and every call would see count 0.
R=$(mk) && mkdir -p "$R/owned" && chmod 0777 "$R/owned"
: >"$WORK/statcalls"
stat() {
  printf 'x\n' >>"$WORK/statcalls"
  [ "$(wc -l <"$WORK/statcalls")" -ge 2 ] && return 1
  command stat "$@"
}
attempt "$R/owned" 1
unset -f stat
[ "$FATALED" -eq 1 ] && ok "owned unverifiable tightening: fails closed on the second stat" \
  || no "owned unverifiable tightening" "trusted a tighten it could not re-read"

report
