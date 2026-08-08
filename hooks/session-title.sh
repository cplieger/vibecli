#!/bin/sh
# Tell the web-terminal server which kiro-cli session belongs to this tab.
#
# Runs as a kiro-cli hook (SessionStart and UserPromptSubmit; see
# entrypoint.sh's seed_session_title_hook). It is the only place the two
# identities meet:
#
#   KWEB_SESSION_ID     the tab's id, injected into this session's child
#                       environment by the server's session factory and
#                       inherited by every descendant including this hook
#   session_id          kiro-cli's own session id, handed to a hook on stdin
#
# The server cannot learn the pairing any other way: kiro-cli does not accept a
# session id from its environment (KIRO_SESSION_ID is a variable it EXPORTS to
# hooks, not one it reads), and nothing in the process tree or the session file
# names the tab. With the pair on disk the server reads that session's own
# session.json for its title. See sessiontitle.go.
#
# Runs on EVERY prompt, not just at session start, so switching sessions inside
# one tab (/chat, /tangent) re-points the mapping instead of stranding it.
#
# Exits 0 unconditionally. A hook's non-zero exit can block the user's prompt
# (UserPromptSubmit treats exit 2 as a block), and a tab label is never worth
# refusing to send a message over.

set -u

# Nothing to do outside a web-terminal session (the operator running kiro-cli
# from `docker exec` gets no injected id, and a global hook fires there too).
[ -n "${KWEB_SESSION_ID:-}" ] || exit 0
[ -n "${KWEB_TITLE_STATE_DIR:-}" ] || exit 0

# Read the hook payload and pull out kiro's session id. Deliberately a fixed
# extraction rather than a JSON parser: this runs on a Debian base with no
# guaranteed jq, and the payload is machine-written by kiro-cli. A shape change
# yields an empty match, which the guard below turns into a silent no-op (the
# tab keeps the server's automatic name) rather than a wrong mapping.
# Stream stdin straight through the extraction. Two reasons not to buffer it first: this
# hook fires on EVERY UserPromptSubmit in every tab and the payload carries the user's
# whole prompt, so `$(cat)` plus `printf '%s'` held two full copies of an unbounded
# machine-written blob to produce a ~45-byte result; and `grep -o` reports matches
# leftmost-first, so `head -n 1` now takes the FIRST "session_id" in the payload. The old
# `sed 's/.*"session_id"...'` was greedy, so on a single-line payload it took the LAST one.
kiro_session=$(grep -ao '"session_id"[[:space:]]*:[[:space:]]*"[^"]*"' \
  | head -n 1 \
  | sed 's/.*"\([^"]*\)"$/\1/')

case "$kiro_session" in
  sess_*) ;;
  *) exit 0 ;;
esac

# The tab id becomes a filename, so refuse anything that is not the server's own
# id alphabet rather than letting it walk out of the state directory. The server
# validates this again on read; both sides check because neither owns this file
# exclusively.
case "$KWEB_SESSION_ID" in
  *[!A-Za-z0-9_-]* | '') exit 0 ;;
esac

mkdir -p "$KWEB_TITLE_STATE_DIR" 2>/dev/null || exit 0

# Write via a temp file and rename so the server never reads a half-written
# mapping. The temp name carries $$ so two tabs starting together cannot collide.
tmp="$KWEB_TITLE_STATE_DIR/.$KWEB_SESSION_ID.$$"
printf '%s\n' "$kiro_session" >"$tmp" 2>/dev/null || exit 0
mv -f "$tmp" "$KWEB_TITLE_STATE_DIR/$KWEB_SESSION_ID" 2>/dev/null || rm -f "$tmp"

exit 0
