#!/bin/sh
# Concatenate the UI package's per-feature CSS splits (listed in
# css/MANIFEST; blank lines and #-comments skipped, unterminated
# final line handled) into the served bundle.
# Usage: css-bundle.sh <ui-css-dir> <out-file>
set -eu
css_dir="${1:?usage: css-bundle.sh <ui-css-dir> <out-file>}"
out="${2:?usage: css-bundle.sh <ui-css-dir> <out-file>}"
# Assemble beside the destination and rename only after every manifest member
# was read, so a missing/unreadable CSS split fails the build without
# replacing the previously usable bundle with a partial file. mktemp in the
# output directory keeps the rename atomic.
tmp=$(mktemp "${out}.XXXXXX")
trap 'rm -f "$tmp"' EXIT
# A trapped signal must terminate the run (the EXIT trap then cleans up);
# a cleanup-only signal handler would resume assembly with $tmp deleted
# and mv a partial bundle.
trap 'exit 1' HUP INT TERM
css_root=$(realpath "$css_dir")
# The per-entry regular-file guard below cannot protect the MANIFEST
# itself: opening a FIFO for the loop redirect blocks the build forever,
# the same crafted-tarball class the entry guard closes. Resolved and
# contained under css_root on the SAME terms as an entry (in-tree symlink
# to a regular file passes; symlink to a FIFO, or out of the css dir,
# refuses), so a crafted css/MANIFEST symlink cannot redirect the read.
manifest=$(realpath -e "${css_dir}/MANIFEST") || {
  printf 'css-bundle: MANIFEST does not resolve, refusing: %s\n' "${css_dir}/MANIFEST" >&2
  exit 1
}
case "$manifest" in
  "${css_root}"/*) ;;
  *)
    printf 'css-bundle: MANIFEST resolves outside css dir, refusing: %s\n' "$manifest" >&2
    exit 1
    ;;
esac
if [ ! -f "$manifest" ]; then
  printf 'css-bundle: MANIFEST is not a regular file, refusing: %s\n' "$manifest" >&2
  exit 1
fi
# Counts the members actually assembled, solely so an empty or fully-commented
# MANIFEST (which never enters the loop) is refused at the bottom. Counting
# states that condition directly rather than inferring it from the assembled
# file's size, which the per-member separator below (one newline per member)
# turns into an indirect proxy for "did we assemble anything". Each member's OWN
# non-emptiness is enforced per-entry inside the loop, so a truncated tarball
# whose required feature stylesheet is zero bytes fails there, not here: an
# aggregate "at least one member had bytes" test would pass it.
member_count=0
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in '' | \#*) continue ;; esac
  case "$line" in
    /* | ../* | */../* | */.. | ..)
      printf 'css-bundle: MANIFEST entry escapes css dir, refusing: %s\n' "$line" >&2
      exit 1
      ;;
  esac
  # Resolve symlinks and re-assert containment: the literal guard above
  # cannot see a symlink shipped inside a crafted UI tarball.
  entry=$(realpath -e "${css_dir}/${line}") || {
    printf 'css-bundle: MANIFEST entry does not resolve: %s\n' "$line" >&2
    exit 1
  }
  case "$entry" in
    "${css_root}"/*) ;;
    *)
      printf 'css-bundle: MANIFEST entry resolves outside css dir, refusing: %s\n' "$line" >&2
      exit 1
      ;;
  esac
  # Containment alone still admits a FIFO/device/directory shipped in a
  # crafted UI tarball; cat on a FIFO blocks the build forever. Only regular
  # files (including resolved in-tree symlinks) are readable bundle members.
  if [ ! -f "$entry" ]; then
    printf 'css-bundle: MANIFEST entry is not a regular file, refusing: %s\n' "$line" >&2
    exit 1
  fi
  # Every MANIFEST entry is an independently required build input (each is one
  # feature's stylesheet), so a zero-byte member — the truncated or
  # mis-published UI tarball — fails the build here instead of publishing a
  # bundle silently missing that feature's styling.
  if [ ! -s "$entry" ]; then
    printf 'css-bundle: MANIFEST entry is empty, refusing: %s\n' "$line" >&2
    exit 1
  fi
  member_count=$((member_count + 1))
  # A member without a trailing newline would otherwise fuse its last line
  # into the next member's first; CSS is whitespace-insensitive between
  # rules, so an unconditional separator is free.
  cat "$entry" >>"$tmp"
  printf '\n' >>"$tmp"
done <"$manifest"
# An empty or fully-commented MANIFEST (a truncated/mis-published UI tarball)
# would otherwise install an empty bundle that nothing downstream catches.
[ "$member_count" -gt 0 ] || {
  printf 'css-bundle: MANIFEST lists no members (empty or fully-commented?): %s\n' "$manifest" >&2
  exit 1
}
mv "$tmp" "$out"
trap - EXIT HUP INT TERM
