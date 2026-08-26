#!/usr/bin/env bash
# warn_if_not_root(): the boot-time report that this image is root-by-design.
#
# Unreachable from tests/image-smoke.sh, which runs the image the supported way
# (no `user:` line) and therefore only ever sees the silent branch. The branch
# under test is the one an operator reaches by adding `user: "1000:1000"` out of
# *arr habit, and its entire value is the WORDING: the run continues either way,
# so a test that only checked "did it warn" would pass against a message that
# names none of the four things about to break.
# Lint directives, each against a stated guarantee rather than an assumption:
#   SC2015 - the assertion form `[ cond ] && ok "..." || no "..."` cannot mis-fire,
#     because lib.sh's ok/no return 0 unconditionally by design.
# shellcheck disable=SC2015
set -u

# shellcheck source-path=SCRIPTDIR
. "$(dirname -- "$0")/lib.sh"
new_workdir >/dev/null

load_function warn_if_not_root

# --- 1. root is silent ----------------------------------------------------------
# The supported path runs on every healthy boot, so a stray line here would be
# noise in every container log the fleet produces.
out=$(warn_if_not_root 0 0 2>&1)
rc=$?
[ -z "$out" ] && ok "a root run logs nothing" || no "a root run logs nothing" "got: $out"
[ "$rc" -eq 0 ] && ok "a root run returns 0" || no "a root run returns 0" "rc=$rc"

# --- 2. a non-root run warns, and NEVER escalates -------------------------------
# Fatal here would be worse than the mistake it reports: `fatal` sleeps and exits,
# so the operator loses the shell they would use to remove the `user:` line. This is
# the assertion that keeps a future "harden the entrypoint" pass from flipping it.
out=$(warn_if_not_root 1000 1000 2>&1)
rc=$?
[ "$rc" -eq 0 ] && ok "a non-root run still returns 0 (boot continues)" \
  || no "a non-root run returns 0" "rc=$rc: one set -e away from ending boot"
case "$out" in
  *level=warn*) ok "a non-root run logs at warn" ;;
  *) no "a non-root run logs at warn" "got: $out" ;;
esac
case "$out" in
  *level=error* | *fatal*) no "the report never escalates to fatal" "got: $out" ;;
  *) ok "the report never escalates to fatal" ;;
esac

# --- 3. the warn carries the identity it observed -------------------------------
# Without the uid, an operator reading the log cannot tell this fired for the
# container's own user rather than for something it spawned.
case "$out" in
  *uid=1000*gid=1000*) ok "the warn reports the observed uid and gid" ;;
  *) no "the warn reports uid and gid" "got: $out" ;;
esac

# --- 4. the warn names the CAUSE, not just the symptom --------------------------
# The whole reason this function exists: four subsystems fail with four misleading
# messages, and none of them mentions the compose line responsible. If the remedy
# is not in this string, the function has no reason to be in the boot path.
case "$out" in
  *"user: line"*) ok "the warn names the compose user: line as the remedy" ;;
  *) no "the warn names the compose user: line" "got: $out" ;;
esac

# --- 5. the warn names each consequence ----------------------------------------
# Asserted individually rather than as one blob: these are four independent
# failures, and a rewrite that drops one silently makes that one unattributable
# again. ssh is first because it is the only one with no workaround.
for want in 'No user exists for uid' 'apt installs' 'containment' 'chmod'; do
  case "$out" in
    *"$want"*) ok "the warn names the '$want' consequence" ;;
    *) no "the warn names the '$want' consequence" "got: $out" ;;
  esac
done

# --- 6. the hint stays inside its logfmt field ---------------------------------
# The hint quotes an error message verbatim. logfmt closes a quoted field on the
# first unescaped double quote, so a literal one inside would truncate the field and
# hand the rest to a log parser as garbage keys. The file's own
# warn_skipped_apt_token rewrites quotes for this reason; this asserts the hint
# followed suit.
hint=${out#*hint=\"}
hint=${hint%%\"*}
case "$hint" in
  *'No user exists for uid'*) ok "the hint body survives logfmt field extraction" ;;
  *) no "the hint body survives extraction" "field truncated early: $hint" ;;
esac

# --- 7. the check runs BEFORE the work it explains -----------------------------
# A report that lands after make_config_dir has already exited is a report nobody
# reads: /config is checked with a fatal, so the misleading message wins the race
# and this one never prints. Ordering is the feature, asserted on the real text
# because a healthy image never takes the branch.
call_line=$(grep -n '^warn_if_not_root$' "$ENTRYPOINT" | head -1 | cut -d: -f1)
cfg_line=$(grep -nE '^[^#]*make_config_dir "/config"' "$ENTRYPOINT" | head -1 | cut -d: -f1)
[ -z "$cfg_line" ] && cfg_line=$(grep -nE '^[^#]*make_config_dir ' "$ENTRYPOINT" | head -1 | cut -d: -f1)
[ -n "$call_line" ] && [ -n "$cfg_line" ] && [ "$call_line" -lt "$cfg_line" ] \
  && ok "the identity report runs before the /config work it explains" \
  || no "the identity report runs before the /config work" \
    "warn at ${call_line:-none}, make_config_dir at ${cfg_line:-none}"

# --- 8. defined before called --------------------------------------------------
# Same regression the containment block paid for: bash resolves a function at call
# time, so a call above its definition reports "command not found" and, with stderr
# already full of boot chatter, silently reports nothing useful.
def_line=$(grep -n '^warn_if_not_root() {' "$ENTRYPOINT" | head -1 | cut -d: -f1)
[ -n "$def_line" ] && [ -n "$call_line" ] && [ "$def_line" -lt "$call_line" ] \
  && ok "warn_if_not_root is defined before it is called" \
  || no "warn_if_not_root is defined before it is called" \
    "def at ${def_line:-none}, call at ${call_line:-none}"

report
