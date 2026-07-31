#!/usr/bin/env bash
# move_legacy_tool_metadata(): the one-time relocation of toolbelt's three
# metadata files from /config into the tools tree they describe.
#
# The weight is on what it must NOT do. tools.json is HAND-AUTHORED intent
# (enabling a tool is a file edit plus a restart), so a move that overwrites the
# live file, follows a planted symlink into the tree the server writes through,
# or records itself as done after failing is user-data loss rather than untidiness
# -- and every one of those is silent, because the boot continues either way.
#
# The marker is never named here, deliberately: the once-per-volume contract is
# asserted through BEHAVIOUR (a second call must ignore a re-planted file), so a
# rename of the marker cannot make these cases pass while the guarantee is gone,
# and neither can dropping the marker write.
#
# Lint directives, each against a stated guarantee:
#   SC2015 - the assertion form `[ cond ] && ok "..." || no "..."` cannot mis-fire,
#     because lib.sh's ok/no return 0 unconditionally by design (see their comment).
# shellcheck disable=SC2015
set -u

# shellcheck source-path=SCRIPTDIR
. "$(dirname -- "$0")/lib.sh"
new_workdir >/dev/null

load_function move_legacy_tool_metadata

# Fresh fake volume per scenario: FROM stands in for /config, TO for
# /config/tools (which the boot path has already created and hardened by the time
# the function runs).
setup() {
  ROOT=$(mktemp -d "$WORK/vol.XXXXXX")
  FROM="$ROOT/config"
  TO="$FROM/tools"
  mkdir -p "$TO"
}

move_quietly() {
  move_legacy_tool_metadata "$FROM" "$TO" 2>"$WORK/log" >/dev/null
}

said() {
  grep -q "$1" "$WORK/log"
}

# --- 1. moves what exists, skips what does not ----------------------------------
setup
printf '{"version":2,"tools":{"gopls":{}}}\n' >"$FROM/tools.json"
printf '{"state":1}\n' >"$FROM/tools-state.json"
# tool-catalog.cached.json deliberately absent: a volume that never fetched a
# catalog has only the other two, and a missing file must be a skip rather than a
# failure that withholds the completion record.
move_quietly
[ -f "$TO/tools.json" ] && [ ! -e "$FROM/tools.json" ] \
  && ok "the hand-authored manifest moved into the tools tree" \
  || no "manifest moved" "tools.json is still in the old location, or never arrived in the new one"
grep -q gopls "$TO/tools.json" \
  && ok "the moved manifest keeps its contents (the operator's enabled tools)" \
  || no "manifest contents" "the file arrived empty or rewritten"
[ -f "$TO/tools-state.json" ] && [ ! -e "$FROM/tools-state.json" ] \
  && ok "the engine-owned state moved with it" \
  || no "state moved" "tools-state.json did not move"
[ ! -e "$TO/tool-catalog.cached.json" ] \
  && ok "an absent catalog cache is skipped, not created" \
  || no "absent catalog cache" "something was created for a file that never existed"

# --- 2. a file already at the destination is NEVER overwritten -------------------
# The destination copy is the one the engine reads today, so it wins. An earlier
# shape of this migration would have clobbered it with the stale /config copy.
setup
printf 'STALE\n' >"$FROM/tools.json"
printf 'LIVE\n' >"$TO/tools.json"
move_quietly
grep -q LIVE "$TO/tools.json" \
  && ok "a manifest already in the tools tree is left untouched" \
  || no "no overwrite" "the stale copy overwrote the live manifest"
[ -f "$FROM/tools.json" ] \
  && ok "the stale copy is left on disk rather than deleted (the operator's file, not ours)" \
  || no "stale copy kept" "the old file was removed"
said 'exists in BOTH' \
  && ok "the both-present case says so, so the leftover is not a silent puzzle" \
  || no "both-present warning" "nothing was logged about the duplicate"

# --- 3. once per volume: a second call must not move a re-planted file ----------
# THE bait for the marker. Without it every boot rescans /config, and a file the
# operator legitimately re-creates there (an editor backup, a restored copy) would
# be swallowed into the tools tree behind their back.
setup
printf 'FIRST\n' >"$FROM/tools.json"
move_quietly
printf 'REPLANTED\n' >"$FROM/tools-state.json"
move_quietly
[ -f "$FROM/tools-state.json" ] && [ ! -e "$TO/tools-state.json" ] \
  && ok "a completed migration does not run again (the re-planted file stays where the operator put it)" \
  || no "runs once per volume" "the second call moved a file, so the completion record is not gating it"

# --- 4. THE FAILURE CASE: a failed move must not be recorded as done -------------
# `mv` is stubbed rather than provoked, because this suite runs as root on some
# machines and root ignores the mode bits that would otherwise make a move fail --
# a case that cannot fail for the maintainer is not evidence.
setup
printf 'INTENT\n' >"$FROM/tools.json"
mv() { return 1; }
move_quietly
[ -f "$FROM/tools.json" ] && [ ! -e "$TO/tools.json" ] \
  && ok "a failed move leaves the source file alone" \
  || no "failed move" "the file vanished or arrived despite mv failing"
said 'not recording' \
  && ok "the failure says the migration was not recorded" \
  || no "withheld-record warning" "nothing said the completion record was withheld"
unset -f mv
move_quietly
[ -f "$TO/tools.json" ] \
  && ok "the next boot RETRIES after a failure (no completion record was written)" \
  || no "retry after failure" "the failed pass recorded itself as complete, so the operator's manifest is stranded forever"

# --- 5. never move a symlink: it would redirect what the engine writes -----------
# Bait the unguarded code would take: [ -f ] DEREFERENCES, so a symlink to a real
# file passes it and `mv` relocates the LINK, after which the engine's writes to
# <tools>/tools.json land wherever the link points -- outside the mount, or on a
# file the container does not own.
setup
VICTIM="$ROOT/victim.json"
printf 'VICTIM\n' >"$VICTIM"
ln -s "$VICTIM" "$FROM/tools.json"
move_quietly
[ ! -e "$TO/tools.json" ] && [ -L "$FROM/tools.json" ] \
  && ok "a symlinked metadata file is refused, not relocated into the tools tree" \
  || no "symlinked source file" "the link was moved into the tree the engine writes through"
grep -q VICTIM "$VICTIM" \
  && ok "the symlink's target is untouched" \
  || no "symlink target" "the target file was modified"
said 'refusing to move a symlinked' \
  && ok "the refusal names the symlink, not some other guard" \
  || no "symlink refusal message" "a different guard fired, or none did"

# --- 6. neither directory may be a symlink --------------------------------------
# The destination is proven on the boot path (make_config_dir + secure_tools_dir),
# but this function is also its own unit, and a symlinked destination would place
# the operator's manifest outside the /config mount entirely.
setup
printf 'INTENT\n' >"$FROM/tools.json"
ELSEWHERE="$ROOT/elsewhere"
mkdir -p "$ELSEWHERE"
rm -rf "$TO"
ln -s "$ELSEWHERE" "$TO"
move_quietly
[ ! -e "$ELSEWHERE/tools.json" ] && [ -f "$FROM/tools.json" ] \
  && ok "a symlinked destination directory is refused; nothing is moved through it" \
  || no "symlinked destination" "the manifest was moved through a link, outside the tree this script hardened"
said 'one of the directories is missing or is a symlink' \
  && ok "the directory refusal fired (not the per-file one)" \
  || no "directory refusal message" "a different guard fired, or none did"

# --- 7. degenerate inputs must not fail the boot --------------------------------
setup
move_legacy_tool_metadata "$FROM" "$TO" >/dev/null 2>&1
[ $? -eq 0 ] && ok "a volume with nothing to move returns 0" || no "nothing to move" "non-zero return"

setup
rm -rf "$FROM"
move_legacy_tool_metadata "$FROM" "$TO" >/dev/null 2>&1
[ $? -eq 0 ] && ok "an absent source directory returns 0" || no "absent source" "non-zero return"

setup
printf 'INTENT\n' >"$FROM/tools.json"
rm -rf "$TO"
move_legacy_tool_metadata "$FROM" "$TO" >/dev/null 2>&1
rc=$?
[ "$rc" -eq 0 ] && [ -f "$FROM/tools.json" ] \
  && ok "an absent destination directory returns 0 and moves nothing" \
  || no "absent destination" "returned $rc, or moved a file into a directory that does not exist"

report
