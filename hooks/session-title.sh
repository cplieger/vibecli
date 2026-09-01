#!/bin/sh
# Tell the web-terminal server which kiro-cli session belongs to this tab.
#
# Runs as a kiro-cli hook (SessionStart, UserPromptSubmit; config seeded by
# entrypoint.sh). Pairs WT_TITLE_HANDLE (minted by the server, injected into this
# session's env) with kiro-cli's own session_id (handed to the hook on stdin) — the
# only place the two identities meet. See sessionEnv/sessiontitle.go for the read
# side. kiro-cli does not accept a session id from its environment, so the pairing
# can only be learned this way.
#
# The handle is deliberately not the tab id: the tab id is the /ws capability
# token, and naming this mapping file after it would put a live credential in a
# directory neither the server nor kiro-cli owns.
#
# Exits 0 unconditionally — a hook's non-zero exit can block the user's prompt
# (UserPromptSubmit treats exit 2 as a block), and a tab label is never worth that.

set -u

# No injected handle outside a web-terminal session (e.g. `docker exec`).
[ -n "${WT_TITLE_HANDLE:-}" ] || exit 0
[ -n "${WT_TITLE_STATE_DIR:-}" ] || exit 0

# Fixed extraction rather than a JSON parser: a shape change in kiro-cli's payload
# must degrade to an empty match (silent no-op, automatic name kept), never a wrong
# mapping. `head -n 1` takes the FIRST match because grep -o reports leftmost-first;
# the payload streams straight into the pipeline rather than being buffered, since
# it carries the user's whole prompt on every keystroke submit.
kiro_session=$(grep -ao '"session_id"[[:space:]]*:[[:space:]]*"[^"]*"' \
  | head -n 1 \
  | sed 's/.*"\([^"]*\)"$/\1/')

case "$kiro_session" in
  sess_*) ;;
  *) exit 0 ;;
esac

# The handle becomes a filename; refuse anything outside the server's own handle
# alphabet before it can walk out of the state directory. This is the only
# alphabet check on the value (see sessionEnv/sessiontitle.go readMapping).
case "$WT_TITLE_HANDLE" in
  *[!A-Za-z0-9_-]*) exit 0 ;;
esac

mkdir -p "$WT_TITLE_STATE_DIR" 2>/dev/null || exit 0

# Write via a temp file and rename so the server never reads a half-written
# mapping; $$ avoids a collision between two tabs starting together.
tmp="$WT_TITLE_STATE_DIR/.$WT_TITLE_HANDLE.$$"
printf '%s\n' "$kiro_session" >"$tmp" 2>/dev/null || exit 0
mv -f "$tmp" "$WT_TITLE_STATE_DIR/$WT_TITLE_HANDLE" 2>/dev/null || rm -f "$tmp"

exit 0
