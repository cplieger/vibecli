#!/usr/bin/env bash
# secure_tools_dir(): tighten what we can, and never brick boot over a tree the
# entrypoint does not own.
#
# The third argument encodes the app's failure posture (see the steering doc's
# "Failure posture" section). owned=1 is for the NINE directories the entrypoint
# creates itself — /config, $TOOLS, $TOOLS/bin, $TOOLS/opt, $TOOLS/npm,
# $TOOLS/npm/bin, $TOOLS/python, $TOOLS/python/bin and $TOOLS/kiro-cli-versions,
# which is exactly the make_config_dir list outside $HOME. Two properties put a
# directory in that set and both are needed: the entrypoint CREATES it, so a
# symlink or a plain file there is unambiguously anomalous rather than the
# operator's shape, and a reinstall REPAIRS its contents (the toolbelt engine
# reinstalls a tool it finds missing, the kiro-cli manager reinstalls from the
# pinned archive), so refusing to boot costs a download rather than data.
#
# The npm and python roots are in that set for the same reason $TOOLS/bin is:
# $TOOLS/bin leads PATH and its entries are symlinks INTO opt/, npm/bin/ and
# python/bin/, so root executes what those trees hold — and no leaf-file chmod
# stops a foreign host user who can write the ROOT from replacing a launcher.
#
# owned=0 is for $TOOLS/go and $TOOLS/go/bin, i.e. GOPATH/bin and its parent: on
# PATH but never created and never repaired here, and holding no integrity-gated
# binary (a `go install` lands whatever the operator asked for). This is a dev box
# whose operator reshapes /config on purpose, and `fatal` sleeps 10s and exits, so
# a boot that aborts on operator-owned state leaves no way in to fix it.
#
# Two halves below, and the second is not optional. The BEHAVIOURAL half drives the
# extracted function against temp dirs, one owned value at a time. The CALL-SITE
# half reads the shipped boot path and pins WHICH directory gets which value —
# nothing about the function's own behaviour can see that, so without it, flipping
# a fail-closed root to warn-only is a silent one-token edit.
#
# Lint directives for this whole file, each against a stated guarantee rather than
# an assumption:
#   SC2015 - the assertion form `[ cond ] && ok "..." || no "..."` cannot mis-fire,
#     because lib.sh's ok/no return 0 unconditionally by design (see their comment).
#   SC2016 - the call-site expectations below must stay single-quoted: they compare
#     the LITERAL text of the shipped script ($TOOLS as written, unexpanded).
#   SC2329 - the stat/chmod stubs below are invoked INDIRECTLY, by the extracted
#     function they shadow, which shellcheck cannot see.
# shellcheck disable=SC2015,SC2016,SC2329
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

# --- owned + arm=0: the package-manager roots' live shape -----------------------
# All four npm/python roots are called `secure_tools_dir <dir> 0 1`, a COMBINATION
# neither block above states: fail-closed like an owned tree, but no kiro-cli
# quarantine, because a launcher tree never holds the pinned CLI. So a
# group/other-writable one must be tightened, must NOT arm the taint (that would
# re-download kiro-cli over an unrelated tree's mode), and must NOT abort — the
# mode is fixable, and only an UNFIXABLE state earns a fatal.
R=$(mk) && mkdir -p "$R/npm" && chmod 0777 "$R/npm"
attempt "$R/npm" 1
MODE=$(stat -c '%a' "$R/npm" 2>/dev/null)
if [ "$FATALED" -eq 0 ] && [ $((8#$MODE & 0022)) -eq 0 ] && [ "$tools_tree_was_writable" -eq 0 ] \
  && warned 'permits group/other writes; tightening it (no kiro-cli quarantine'; then
  ok "owned + arm=0 writable (the npm/python shape): tightened to $MODE, no quarantine, no abort"
else
  no "owned arm=0 writable" "fataled=$FATALED mode=$MODE armed=$tools_tree_was_writable log: $(cat "$WARNLOG")"
fi

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

# --- the CALL SITES: which directories are fail-closed --------------------------
# Everything above tests the function GIVEN an owned value. This half tests the
# mapping, which is where the real risk lives: the policy is one token per call
# site, so demoting a fail-closed root to warn-only is a two-character edit that
# no behavioural assertion can notice.
#
# Field 4 of a call is the `owned` argument; ABSENT means the function's own
# default (`owned=${3:-1}`), which is how the five original roots are written, so
# the parse has to supply that default rather than reading a missing field as 0.
call_pairs() {
  grep -E '^[[:space:]]*secure_tools_dir ' "$ENTRYPOINT" \
    | sed 's/^[[:space:]]*//' \
    | awk '{ owned = ($4 == "" ? 1 : $4); gsub(/"/, "", $2); print $2, owned }'
}

# A precondition, not an assertion: with no call sites parsed, every set
# comparison below would compare two empty sets and report green.
CALLS=$(call_pairs)
if [ -z "$CALLS" ]; then
  printf 'harness error: no secure_tools_dir call sites parsed out of %s\n' "$ENTRYPOINT" >&2
  exit 1
fi

# The whole fail-closed set, as a set: this fails both when a root is demoted and
# when a NEW one is added, because either way the three places that describe this
# policy (the function's doc comment, the steering doc, this file) have drifted
# from the code. Both sides go through the same `LC_ALL=C sort`, so the assertion
# is about membership and never about the collation order of `$` versus `/`.
OWNED_EXPECTED=$(printf '%s\n' \
  /config '$TOOLS' '$TOOLS/bin' '$TOOLS/opt' \
  '$TOOLS/npm' '$TOOLS/npm/bin' '$TOOLS/python' '$TOOLS/python/bin' \
  '$TOOLS/kiro-cli-versions' | LC_ALL=C sort)
OWNED_ACTUAL=$(printf '%s\n' "$CALLS" | awk '$2 == 1 { print $1 }' | LC_ALL=C sort)
if [ "$OWNED_ACTUAL" = "$OWNED_EXPECTED" ]; then
  ok "the fail-closed (owned=1) set is exactly the nine directories the entrypoint creates"
else
  no "owned=1 set drifted" "expected [$(printf '%s' "$OWNED_EXPECTED" | tr '\n' ' ')] but the boot path has [$(printf '%s' "$OWNED_ACTUAL" | tr '\n' ' ')] -- if intended, update secure_tools_dir's doc comment and web-terminal-kiro.md 'Failure posture' in the same change"
fi

# Named individually as well as in the set above, because these four are the ones
# whose membership is not self-evident, and a per-root failure says WHY.
for pm in '$TOOLS/npm' '$TOOLS/npm/bin' '$TOOLS/python' '$TOOLS/python/bin'; do
  printf '%s\n' "$CALLS" | grep -qxF -- "$pm 1" \
    && ok "$pm is fail-closed (owned=1)" \
    || no "$pm owned argument" "not called with owned=1; \$TOOLS/bin symlinks into this tree and root executes what it finds there, so warn-only lets a foreign host user who can write this root replace a launcher"
done

# And the warn-only side, pinned in both directions: exactly one call site passes
# owned=0, it is the loop variable, and the loop feeding it iterates exactly
# GOPATH/bin and its parent. Without the second half, "only $path_dir is
# warn-only" would stay green while the loop was widened to sweep a fail-closed
# root into it.
OWNED0=$(printf '%s\n' "$CALLS" | awk '$2 == 0 { print $1 }' | LC_ALL=C sort)
[ "$OWNED0" = '$path_dir' ] \
  && ok "exactly one warn-only call site, and it is the legacy-PATH-segment loop" \
  || no "owned=0 set drifted" "warn-only call sites are [$(printf '%s' "$OWNED0" | tr '\n' ' ')], expected only the \$path_dir loop"

grep -qF 'for path_dir in "$TOOLS/go" "$TOOLS/go/bin"; do' "$ENTRYPOINT" \
  && ok "the warn-only loop iterates exactly \$TOOLS/go and \$TOOLS/go/bin" \
  || no "warn-only loop contents" "the loop feeding the owned=0 call no longer iterates exactly GOPATH/bin and its parent"

report
