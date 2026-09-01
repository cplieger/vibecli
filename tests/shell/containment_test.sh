#!/usr/bin/env bash
# enable_session_containment() and the capability-drop re-exec that follows it.
#
# Neither branch is reachable in a healthy image smoke: the remount succeeds only
# with CAP_SYS_ADMIN and fails only without it, so the image test sees exactly one
# of the two. The re-exec block matters most, because its failure mode is a
# container that cannot boot, on every start, in an image whose public compose
# example adds NO capability -- so its contract is "never fatal, whatever the
# environment", asserted here against the real text of entrypoint.sh.
#
# Lint directives, each against a stated guarantee:
#   SC2015 - `[ cond ] && ok || no` cannot mis-fire: lib.sh's ok/no return 0
#     unconditionally by design.
#   SC2016 - the entrypoint-text assertions must stay single-quoted (literal
#     text, "$0"/"$@" unexpanded).
#   SC2329 - the `mount` stubs below are invoked INDIRECTLY by the extracted
#     function, which shellcheck cannot see.
# shellcheck disable=SC2015,SC2016,SC2329
set -u

# shellcheck source-path=SCRIPTDIR
. "$(dirname -- "$0")/lib.sh"
new_workdir >/dev/null

load_function logfmt_value
load_function enable_session_containment

# --- 1. the success path: a writable tree reports the REMOUNT, nothing more -----
# `mount` is the only external command the function runs. The cgroup root is a
# PARAMETER so this case can hand it a temp dir. The function inspects nothing
# inside the tree: vacating the root and enabling controllers belong to the
# server's NewContainment, whose verifyOwnRoot REFUSES a root holding any
# non-"wt-" child directory -- a leaf created here would disable containment.
mount() { return 0; }
mkdir -p "$WORK/cg"
out=$(enable_session_containment "$WORK/cg" 2>&1)
rc=$?
[ "$rc" -eq 0 ] && ok "a successful remount returns 0" \
  || no "a successful remount returns 0" "rc=$rc"
case "$out" in
  *level=info*"remounted rw"*) ok "success logs the remount at info" ;;
  *) no "success logs the remount at info" "got: $out" ;;
esac
# Pins the shipped defect: the message once claimed "per-session process
# containment available" on the strength of the remount alone, while the server
# failed with EBUSY six seconds later (measured on borgcube, image v2.7.7) and
# every session ran uncontained. This script proves the MOUNT; only the server
# can report containment, and it does.
case "$out" in
  *containment\ available*) no "the remount report must not claim containment is available" "got: $out" ;;
  *) ok "the remount report does not claim containment is available" ;;
esac
case "$out" in
  *"by the server"*) ok "the remount report names the server as the reporter of the verdict" ;;
  *) no "the remount report names who reports the verdict" "got: $out" ;;
esac

# --- 2. the refusal path: warn, non-zero, and NEVER fatal -----------------------
# A container without the capability takes this path on every boot, so `fatal`
# (or any exit) here would break the public compose example for every user.
mount() { return 32; }
out=$(enable_session_containment "$WORK/cg" 2>&1)
rc=$?
[ "$rc" -ne 0 ] && ok "a refused remount reports failure to its caller" \
  || no "a refused remount reports failure" "rc=0"
case "$out" in
  *level=warn*) ok "refusal logs at warn, not error" ;;
  *) no "refusal logs at warn" "got: $out" ;;
esac
case "$out" in
  *level=error* | *fatal*) no "refusal is never fatal" "the message escalates: $out" ;;
  *) ok "refusal is never fatal" ;;
esac
case "$out" in
  *SYS_ADMIN*) ok "the refusal warn names the capability to add" ;;
  *) no "the refusal warn names the capability" "got: $out" ;;
esac
# 2a. mount's message is the only text in this line the script did not author;
# each assertion here is red-checked (fails with its rule removed). A lone
# trailing backslash escapes the closing quote and swallows hint=; a bare CR
# splits/overwrites the record; an unescaped quote closes the error field early
# and lets mount's text forge a logfmt key.
#
# shellcheck disable=SC1003  # the trailing \\ is a literal backslash for printf
# to emit -- the malformed value under test, not an attempt to escape a quote.
mount() {
  printf 'mount: /x: "denied" a\r\\' >&2
  return 32
}
out=$(enable_session_containment "$WORK/cg" 2>&1)
case "$out" in
  *'\\" hint='*) ok "a backslash is doubled, so the error field closes and hint= survives" ;;
  *) no "a backslash is doubled before the field closes" "got: $out" ;;
esac
case "$out" in
  *$'\r'*) no "a carriage return must not reach the log record" "got: $out" ;;
  *) ok "a carriage return is replaced, not passed through" ;;
esac
case "$out" in
  *'"denied"'*) no "mount's own double quote must not reach the log record" "got: $out" ;;
  *) ok "a double quote is neutralized, so it cannot close the error field early" ;;
esac
unset -f mount

# --- 2b. the function creates NOTHING inside the cgroup root --------------------
# An earlier fix created an `init` leaf and migrated the root's pids into it to
# clear cgroup v2's no-internal-process constraint. Read against the engine's
# terminal/containment_linux.go, that is both redundant AND harmful:
# NewContainment's own vacateRoot already does this, and its verifyOwnRoot (which
# runs first) refuses the whole root the moment it holds a child not prefixed
# "wt-" -- so an `init` leaf disables containment on exactly the hosts where it
# would have worked.
mount() { return 0; }
mkdir -p "$WORK/cg2"
printf '1\n' >"$WORK/cg2/cgroup.procs"
# Snapshot recursively, not just the root's own entries: the removed migration
# wrote below the root, which a flat `ls -A` would miss.
before=$(find "$WORK/cg2" | sort)
out=$(enable_session_containment "$WORK/cg2" 2>&1)
rc=$?
[ "$rc" -eq 0 ] && ok "an occupied root still returns 0 (hygiene, never fatal)" \
  || no "an occupied root returns 0" "rc=$rc"
[ "$(find "$WORK/cg2" | sort)" = "$before" ] \
  && ok "the remount writes nothing below the cgroup root, so verifyOwnRoot cannot refuse it" \
  || no "the remount writes nothing below the cgroup root" "tree changed"
# An occupied root is now ORDINARY (the server vacates it), so this must not warn.
case "$out" in
  *level=warn*) no "an occupied root must not warn: the server vacates it" "got: $out" ;;
  *) ok "an occupied root does not warn; it is the expected pre-vacate state" ;;
esac
unset -f mount

# --- 3. the caller tolerates a refusal ------------------------------------------
grep -Eq 'enable_session_containment \|\| true' "$ENTRYPOINT" \
  && ok "the call site swallows a refusal (|| true)" \
  || no "the call site swallows a refusal" "a non-zero return could end boot"

# --- 4. the drop happens BEFORE the server is exec'd ---------------------------
# The point of re-execing early is to not hold CAP_SYS_ADMIN across a
# network-fetched install (kiro-cli's archive, any `apt:` tool entry), so the
# capability must drop before the server starts.
#
# Every anchor below carries the `^[^#]*` guard: a PROSE mention is not the
# statement. A comment saying `exec setpriv` once broke six assertions here at
# once, because head -1 happily returned the comment's line number.
exec_line=$(grep -nE '^[^#]*exec setpriv' "$ENTRYPOINT" | head -1 | cut -d: -f1)
server_line=$(grep -nE '^[^#]*exec .*/(web-terminal-kiro|app)' "$ENTRYPOINT" | tail -1 | cut -d: -f1)
[ -n "$exec_line" ] && [ -n "$server_line" ] && [ "$exec_line" -lt "$server_line" ] \
  && ok "the capability is dropped before the server is exec'd" \
  || no "the capability is dropped before the server is exec'd" "setpriv at $exec_line, server at $server_line"

# --- 4b. the function is DEFINED before it is CALLED ---------------------------
# bash resolves a function at call time, so a call above the definition reports
# "command not found", the `|| true` swallows it, and containment silently never
# enables -- no error, no symptom. This exact mistake was made and caught here.
def_line=$(grep -n '^enable_session_containment() {' "$ENTRYPOINT" | head -1 | cut -d: -f1)
call_line=$(grep -n 'enable_session_containment || true' "$ENTRYPOINT" | head -1 | cut -d: -f1)
[ -n "$def_line" ] && [ -n "$call_line" ] && [ "$def_line" -lt "$call_line" ] \
  && ok "enable_session_containment is defined before it is called" \
  || no "enable_session_containment is defined before it is called" \
    "def at ${def_line:-none}, call at ${call_line:-none}: the call would silently no-op"

# --- 5. the drop is PRE-FLIGHTED, because it is an exec ------------------------
# An `exec setpriv` that fails ends the container. Two real failure modes on an
# image this repo does not fully control: setpriv absent, or dropping from the
# BOUNDING set needing CAP_SETPCAP, which a non-root/capability-reduced container
# lacks. Both must be discovered by a throwaway invocation before the exec.
grep -Eq '^[^#]*if setpriv .*--bounding-set=-sys_admin.* -- true' "$ENTRYPOINT" \
  && ok "the drop is pre-flighted before the exec" \
  || no "the drop is pre-flighted before the exec" "a failing setpriv would end the container"
preflight_line=$(grep -nE '^[^#]*setpriv .* -- true' "$ENTRYPOINT" | head -1 | cut -d: -f1)
[ -n "$preflight_line" ] && [ "$preflight_line" -lt "$exec_line" ] \
  && ok "the pre-flight runs before the exec" \
  || no "the pre-flight runs before the exec" "preflight at ${preflight_line:-none}, exec at $exec_line"
# When the drop is impossible, the two cases are NOT the same decision:
#   cap not held  -> nothing to drop; warn and continue (the public compose
#                    example's path on every boot; must never be fatal).
#   cap held      -> continuing runs the server AND every terminal session with
#                    CAP_SYS_ADMIN for the container's life -- the standing
#                    privilege the re-exec exists to remove. Fail closed.
tail_block=$(awk -v s="$exec_line" 'NR>s && NR<s+22' "$ENTRYPOINT")
printf '%s' "$tail_block" | grep -Eq 'CapEff' \
  && ok "the impossible-drop path inspects whether the capability is actually held" \
  || no "the impossible-drop path inspects CapEff" "it cannot tell fail-open from fail-closed"
printf '%s' "$tail_block" | grep -Eq 'fatal ' \
  && ok "holding an undroppable CAP_SYS_ADMIN is fatal, not a warn" \
  || no "holding an undroppable CAP_SYS_ADMIN is fatal" "the server would run with it held"
printf '%s' "$tail_block" | grep -Eq 'level=warn.*not held' \
  && ok "not holding it warns and continues (the public compose example path)" \
  || no "not holding it warns and continues" "the default compose path must not be fatal"

# --- 6. the re-exec cannot loop -------------------------------------------------
# It re-runs this same script, so the marker is the only thing between one drop
# and an infinite exec loop. Must be set BEFORE the exec and exported (the child
# is a fresh process).
marker_line=$(grep -n 'CONTAINMENT_CAPS_DROPPED=1' "$ENTRYPOINT" | head -1 | cut -d: -f1)
[ -n "$marker_line" ] && [ "$marker_line" -lt "$exec_line" ] \
  && ok "the loop marker is set before the exec" \
  || no "the loop marker is set before the exec" "marker at ${marker_line:-none}, exec at $exec_line"
grep -Eq 'export CONTAINMENT_CAPS_DROPPED=1' "$ENTRYPOINT" \
  && ok "the loop marker is exported so the re-exec sees it" \
  || no "the loop marker is exported" "an unexported marker cannot survive exec, so boot would loop"
grep -Eq '\$\{CONTAINMENT_CAPS_DROPPED:-\}" != "1"' "$ENTRYPOINT" \
  && ok "the guard tests the marker" \
  || no "the guard tests the marker" "no marker test found"

# --- 7. the re-exec preserves the script's arguments --------------------------
grep -Eq 'exec setpriv .* -- "\$0" "\$@"' "$ENTRYPOINT" \
  && ok "the re-exec forwards \$0 and \$@ intact" \
  || no "the re-exec forwards \$0 and \$@" "arguments would be lost across the drop"

# --- 8. the drop names both capability sets -----------------------------------
# Dropping from the inheritable set alone leaves it in the bounding set, so a
# later setuid execve could regain it. Both are required for the drop to be real.
line=$(grep -m1 -E '^[^#]*exec setpriv' "$ENTRYPOINT")
case "$line" in
  *--bounding-set=-sys_admin*--inh-caps=-sys_admin*) ok "the drop clears bounding AND inheritable" ;;
  *) no "the drop clears bounding AND inheritable" "got: $line" ;;
esac

report
