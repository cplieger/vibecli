#!/usr/bin/env bash
# enable_session_containment() and the capability-drop re-exec that follows it.
#
# Neither branch is reachable in a healthy image smoke: the remount succeeds only
# with CAP_SYS_ADMIN and fails only without it, so the image test sees exactly one
# of the two and never the other. That is what these cases cover.
#
# The re-exec block carries more weight than the function, because it is the one
# piece whose failure mode is a container that cannot boot: it runs before /config
# is even checked, on every start, in an image whose public compose example adds NO
# capability. Its contract is therefore "never fatal, whatever the environment",
# and that is asserted here against the real text of entrypoint.sh rather than
# against a description of it.
# Lint directives, each against a stated guarantee rather than an assumption:
#   SC2015 - the assertion form `[ cond ] && ok "..." || no "..."` cannot mis-fire,
#     because lib.sh's ok/no return 0 unconditionally by design.
#   SC2016 - the entrypoint-text assertions below must stay single-quoted: they
#     compare the LITERAL text of the shipped script ("$0" / "$@" as written,
#     unexpanded).
#   SC2329 - the `mount` stubs below are invoked INDIRECTLY, by the extracted
#     function they shadow, which shellcheck cannot see.
# shellcheck disable=SC2015,SC2016,SC2329
set -u

# shellcheck source-path=SCRIPTDIR
. "$(dirname -- "$0")/lib.sh"
new_workdir >/dev/null

load_function enable_session_containment

# --- 1. the success path: a writable tree reports availability -------------------
# `mount` is the only external command the function runs, so stubbing it is the
# whole environment.
mount() { return 0; }
out=$(enable_session_containment 2>&1)
rc=$?
[ "$rc" -eq 0 ] && ok "a successful remount returns 0" \
  || no "a successful remount returns 0" "rc=$rc"
case "$out" in
  *level=info*containment\ available*) ok "success logs at info" ;;
  *) no "success logs at info" "got: $out" ;;
esac

# --- 2. the refusal path: warn, non-zero, and NEVER fatal -----------------------
# A container without the capability takes this path on every single boot, so a
# `fatal` here (or any exit) would be an unbootable image for every user of the
# public compose example.
mount() { return 32; }
out=$(enable_session_containment 2>&1)
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
# The warn must name the remedy, since the operator cannot infer cap_add from a
# mount failure.
case "$out" in
  *SYS_ADMIN*) ok "the refusal warn names the capability to add" ;;
  *) no "the refusal warn names the capability" "got: $out" ;;
esac
unset -f mount

# --- 3. the caller tolerates a refusal ------------------------------------------
# The call site must not let a non-zero return end the script. `set -u` is on and
# `set -e` is not, but a bare call inside an `if` chain could still propagate, so
# assert the `|| true` is really there.
grep -Eq 'enable_session_containment \|\| true' "$ENTRYPOINT" \
  && ok "the call site swallows a refusal (|| true)" \
  || no "the call site swallows a refusal" "a non-zero return could end boot"

# --- 4. the drop happens BEFORE the apt phase ----------------------------------
# The whole point of re-execing early is to not hold CAP_SYS_ADMIN across a
# network-fetched package install. If the exec ever moves below the apt block this
# silently becomes a much wider capability window, with no functional symptom.
# Every anchor below carries the same `^[^#]*` guard as the apt one: a PROSE mention
# of the statement is not the statement. Adding a comment to entrypoint.sh that said
# `exec setpriv` broke six assertions in this file at once (2026-08), because head -1
# happily returned the comment's line number.
exec_line=$(grep -nE '^[^#]*exec setpriv' "$ENTRYPOINT" | head -1 | cut -d: -f1)
# Match the real invocation, not the several comments that mention it: the command
# runs under `timeout`, which no comment in this file does.
apt_line=$(grep -nE '^[^#]*timeout .*apt-get update' "$ENTRYPOINT" | head -1 | cut -d: -f1)
[ -n "$exec_line" ] && [ -n "$apt_line" ] && [ "$exec_line" -lt "$apt_line" ] \
  && ok "the capability is dropped before the apt phase" \
  || no "the capability is dropped before the apt phase" "exec at $exec_line, apt at $apt_line"

# --- 4b. the function is DEFINED before it is CALLED ---------------------------
# Regression: bash resolves a function at call time, so a call placed above the
# definition does not fail loudly. It reports "command not found", the `|| true`
# swallows it, and the container boots with containment silently never enabled --
# no error, no symptom, no containment. This exact mistake was made and caught
# here, which is why the assertion is text-level rather than behavioral.
def_line=$(grep -n '^enable_session_containment() {' "$ENTRYPOINT" | head -1 | cut -d: -f1)
call_line=$(grep -n 'enable_session_containment || true' "$ENTRYPOINT" | head -1 | cut -d: -f1)
[ -n "$def_line" ] && [ -n "$call_line" ] && [ "$def_line" -lt "$call_line" ] \
  && ok "enable_session_containment is defined before it is called" \
  || no "enable_session_containment is defined before it is called" \
    "def at ${def_line:-none}, call at ${call_line:-none}: the call would silently no-op"

# --- 5. the drop is PRE-FLIGHTED, because it is an exec ------------------------
# An `exec setpriv` that fails does not degrade, it ends the container. Two real
# ways it fails on an image this repo does not fully control: setpriv absent, and
# dropping from the BOUNDING set requiring CAP_SETPCAP, which a non-root or
# capability-reduced container lacks. Both must be discovered by a throwaway
# invocation BEFORE the exec, never by the exec itself.
grep -Eq '^[^#]*if setpriv .*--bounding-set=-sys_admin.* -- true' "$ENTRYPOINT" \
  && ok "the drop is pre-flighted before the exec" \
  || no "the drop is pre-flighted before the exec" "a failing setpriv would end the container"
preflight_line=$(grep -nE '^[^#]*setpriv .* -- true' "$ENTRYPOINT" | head -1 | cut -d: -f1)
[ -n "$preflight_line" ] && [ "$preflight_line" -lt "$exec_line" ] \
  && ok "the pre-flight runs before the exec" \
  || no "the pre-flight runs before the exec" "preflight at ${preflight_line:-none}, exec at $exec_line"
# When the drop is impossible, the two cases are NOT the same decision, and the
# split is the security boundary:
#   cap not held  -> nothing to drop; warn and continue (the public compose example
#                    takes this path on every boot, so it must never be fatal).
#   cap held      -> continuing would run the server AND every user terminal with
#                    CAP_SYS_ADMIN for the container's life, which is the standing
#                    privilege the re-exec exists to remove. Fail closed.
# Asserted on the real text because neither branch is reachable in a healthy image.
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
# It re-runs this same script, so the marker is the only thing between one drop and
# an infinite exec loop. Assert it is set BEFORE the exec, and exported (the child
# is a fresh process, so an unexported marker would not survive).
marker_line=$(grep -n 'KWEB_CONTAINMENT_CAPS_DROPPED=1' "$ENTRYPOINT" | head -1 | cut -d: -f1)
[ -n "$marker_line" ] && [ "$marker_line" -lt "$exec_line" ] \
  && ok "the loop marker is set before the exec" \
  || no "the loop marker is set before the exec" "marker at ${marker_line:-none}, exec at $exec_line"
grep -Eq 'export KWEB_CONTAINMENT_CAPS_DROPPED=1' "$ENTRYPOINT" \
  && ok "the loop marker is exported so the re-exec sees it" \
  || no "the loop marker is exported" "an unexported marker cannot survive exec, so boot would loop"
grep -Eq '\$\{KWEB_CONTAINMENT_CAPS_DROPPED:-\}" != "1"' "$ENTRYPOINT" \
  && ok "the guard tests the marker" \
  || no "the guard tests the marker" "no marker test found"

# --- 7. the re-exec preserves the script's arguments --------------------------
# The server receives "$@" from this script; an exec that dropped them would change
# behavior for any operator passing arguments through the image entrypoint.
grep -Eq 'exec setpriv .* -- "\$0" "\$@"' "$ENTRYPOINT" \
  && ok "the re-exec forwards \$0 and \$@ intact" \
  || no "the re-exec forwards \$0 and \$@" "arguments would be lost across the drop"

# --- 8. the drop names both capability sets -----------------------------------
# Dropping from the inheritable set alone leaves it in the bounding set, so a later
# setuid execve could regain it. Both are required for the drop to be real.
line=$(grep -m1 -E '^[^#]*exec setpriv' "$ENTRYPOINT")
case "$line" in
  *--bounding-set=-sys_admin*--inh-caps=-sys_admin*) ok "the drop clears bounding AND inheritable" ;;
  *) no "the drop clears bounding AND inheritable" "got: $line" ;;
esac

report
