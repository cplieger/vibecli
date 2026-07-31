#!/usr/bin/env bash
# warn_legacy_tool_metadata(): tell the operator that tool metadata left at its
# pre-$TOOLS location is IGNORED, and touch nothing.
#
# The tool manifest moved from /config into /config/tools as a clean break, so an
# upgraded volume keeps three unread files at the old paths while the engine seeds
# a fresh manifest beside the tree. The engine cannot report that (from its side
# the volume looks fresh), which is the whole reason this notice exists — and the
# reason its behaviour is worth pinning is that the function it replaced DID move
# those files. The no-op assertion below is what stops that migration coming back
# by accident.
#
# Lint directives for this whole file, each against a stated guarantee rather than
# an assumption:
#   SC2015 - the assertion form `[ cond ] && ok "..." || no "..."` cannot mis-fire,
#     because lib.sh's ok/no return 0 unconditionally by design (see their comment).
#   SC2329 - the fatal stub below is invoked INDIRECTLY, by the extracted function
#     it shadows, which shellcheck cannot see. It must never be reached; that is
#     the assertion.
# shellcheck disable=SC2015,SC2329
set -u

# shellcheck source-path=SCRIPTDIR
. "$(dirname -- "$0")/lib.sh"
new_workdir >/dev/null

load_function warn_legacy_tool_metadata

# fatal() must never be called: this notice runs on the boot path of a container
# whose /config the operator is expected to reshape, and `fatal` sleeps 10s and
# exits. Record instead of exiting so a regression reports as a failed assertion
# rather than a killed harness.
FATALED=0
fatal() {
  FATALED=1
  return 1
}

# run <old-dir> <new-dir> -> sets RC and WARNLOG
# stderr is kept per attempt because every assertion here is about the MESSAGE:
# an assertion that only inspected the status would stay green with the printf
# deleted, and the printf is the entire product of this function.
attempt() {
  FATALED=0
  WARNLOG="$WORK/warn.log"
  warn_legacy_tool_metadata "$1" "$2" >/dev/null 2>"$WARNLOG"
  RC=$?
}

warned() {
  grep -Fq "$1" "$WARNLOG"
}

# A fresh pair of dirs per case, with $2.. seeded as legacy files at the OLD path.
mk() {
  ROOT=$(mktemp -d "$WORK/t.XXXXXX")
  OLD="$ROOT/config"
  NEW="$ROOT/config/tools"
  mkdir -p "$NEW"
  local name
  for name in "$@"; do
    printf '{"seeded":"%s"}\n' "$name" >"$OLD/$name"
  done
}

# A stable, content-aware description of both trees, so "moved nothing, deleted
# nothing, created nothing" is asserted over the FILES rather than over a count.
# Sizes and a checksum are included because a migration that rewrote a file in
# place (or truncated it) would leave the path list identical.
snapshot() {
  find "$ROOT" -mindepth 1 -printf '%y %P %s\n' | sort
  find "$ROOT" -type f -exec md5sum {} + | sed "s#$ROOT#.#" | sort
}

# --- a volume that never had the old layout: say nothing ------------------------
# Silence is the contract on every fresh volume and on every boot after the
# operator has cleared the files, which is the majority of boots forever. A
# notice that fires unconditionally is noise in exactly the place this app asks
# an operator to read (see web-terminal-kiro.md "Failure posture").
mk
attempt "$OLD" "$NEW"
[ "$RC" -eq 0 ] && [ ! -s "$WARNLOG" ] \
  && ok "no legacy metadata: silent, rc=0" \
  || no "clean volume" "rc=$RC, log: $(cat "$WARNLOG")"

# --- one legacy file: warn, and name THAT file ---------------------------------
# The file list is the actionable half of the message: the remedy is "delete the
# old files", and an operator cannot act on a warning that does not say which.
mk tools.json
attempt "$OLD" "$NEW"
if [ "$RC" -eq 0 ] && warned 'files="tools.json"'; then
  ok "one legacy file: warns and names it"
else
  no "one legacy file" "rc=$RC, log: $(cat "$WARNLOG")"
fi

# --- the message states that the file is IGNORED and what to do ----------------
# Both halves are load-bearing and neither is implied by the other: without
# "ignored" the operator reads a warning about a file the container might still be
# using, and without the remedy they have no reason to think their enabled tools
# need re-applying.
warned 'IGNORED' && ok "the notice says the old file is ignored" \
  || no "ignored wording" "log: $(cat "$WARNLOG")"
warned 'Re-apply your selections in the new manifest, then delete the old files' \
  && ok "the notice states the operator's remedy" \
  || no "remedy wording" "log: $(cat "$WARNLOG")"

# --- all three files: ONE line, naming all three -------------------------------
# One line rather than one per file: this fires on every boot until the operator
# clears the files, so three lines a boot would train them to skip it.
mk tools.json tools-state.json tool-catalog.cached.json
attempt "$OLD" "$NEW"
LINES=$(wc -l <"$WARNLOG")
if [ "$LINES" -eq 1 ] && warned 'files="tools.json tools-state.json tool-catalog.cached.json"'; then
  ok "all three legacy files: one line naming all three"
else
  no "three legacy files" "lines=$LINES, log: $(cat "$WARNLOG")"
fi

# It never fails boot. Asserted on the case that produces the most work, so a
# future guard added to the busiest path is covered.
[ "$FATALED" -eq 0 ] && [ "$RC" -eq 0 ] \
  && ok "the notice never aborts boot" \
  || no "boot abort" "fataled=$FATALED rc=$RC"

# --- it is a NOTICE: nothing is moved, deleted or created ----------------------
# THE assertion of this file. The predecessor mv'd these three files into the
# tools tree and recorded a marker; a clean break means the boot path does none of
# that, and only a before/after comparison of both trees can tell the difference
# (the warning above is identical either way). Content-aware, so an in-place
# rewrite fails it too.
#
# The tree is re-seeded FRESH here rather than reusing the case above: the bait a
# migration would take is three files sitting at the OLD path, and a second call
# on a tree the first call already moved is a no-op for a migration too. Measured
# — with the mv reintroduced, comparing around the second call passed.
mk tools.json tools-state.json tool-catalog.cached.json
BEFORE="$WORK/before.txt"
AFTER="$WORK/after.txt"
snapshot >"$BEFORE"
attempt "$OLD" "$NEW"
snapshot >"$AFTER"
if diff -q "$BEFORE" "$AFTER" >/dev/null; then
  ok "both trees byte-identical afterwards: nothing moved, deleted or created"
else
  no "notice mutated the volume" "$(diff "$BEFORE" "$AFTER" | head -8)"
fi

# Specifically: the new location must still be empty. The tree comparison above
# already covers a `mv`, but this states the invariant an operator would check
# first — the manifest the engine reads is the one it seeded, not one this script
# put there — and it also catches a marker file, which is a CREATE the comparison
# would report only as an unexplained diff.
NEWCOUNT=$(find "$NEW" -mindepth 1 | wc -l)
[ "$NEWCOUNT" -eq 0 ] \
  && ok "the new location is untouched (no file, no marker)" \
  || no "new location written" "$NEWCOUNT entries appeared under the new dir"

# --- a DANGLING symlink at the old path is still reported ----------------------
# [ -e ] dereferences, so a link whose target is gone would slip past an -e-only
# test — and it is the likelier leftover of the two: an operator who deleted the
# old file through a link they had set up ends up in exactly this state, with a
# stray entry still to clear.
mk
ln -s /nonexistent-target "$OLD/tools-state.json"
attempt "$OLD" "$NEW"
if [ "$RC" -eq 0 ] && warned 'files="tools-state.json"'; then
  ok "dangling symlink at the old path: still reported"
else
  no "dangling symlink" "rc=$RC, log: $(cat "$WARNLOG")"
fi
# ...and it is reported without being followed: the link is still a link, and its
# target was not created. Acting through it is what the removed migration had to
# guard against; not acting at all is why this one does not.
[ -L "$OLD/tools-state.json" ] && [ ! -e "/nonexistent-target" ] \
  && ok "the symlink is left as a symlink and its target is not created" \
  || no "symlink followed" "the notice acted through the link"

# --- an unrelated file at the old path is NOT reported -------------------------
# The three names are the engine's; /config holds other things (home/, tools/,
# whatever the operator left there), and a notice that fired on any of them would
# ask an operator to delete files that are still in use.
mk
printf 'x\n' >"$OLD/settings.json"
printf 'x\n' >"$OLD/tools.json.bak"
attempt "$OLD" "$NEW"
[ "$RC" -eq 0 ] && [ ! -s "$WARNLOG" ] \
  && ok "unrelated files at the old path: silent" \
  || no "unrelated files" "rc=$RC, log: $(cat "$WARNLOG")"

report
