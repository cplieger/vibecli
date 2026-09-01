#!/bin/sh
# Concatenate the UI package's per-feature CSS splits (listed in css/MANIFEST;
# blank lines and #-comments skipped) into the served bundle.
# Usage: css-bundle.sh <ui-css-dir> <out-file>
set -eu
css_dir="${1:?usage: css-bundle.sh <ui-css-dir> <out-file>}"
out="${2:?usage: css-bundle.sh <ui-css-dir> <out-file>}"
# Assemble beside the destination and rename only after every manifest member
# is read, so a missing/unreadable split fails the build without replacing the
# previously usable bundle; mktemp in the output dir keeps the rename atomic.
tmp=$(mktemp "${out}.XXXXXX")
trap 'rm -f "$tmp"' EXIT
# A trapped signal must terminate the run; a cleanup-only handler would resume
# assembly with $tmp already deleted and mv a partial bundle.
trap 'exit 1' HUP INT TERM
# The css dir itself comes from a tarball-controlled path component, so a
# crafted tarball shipping `css` as a symlink could move the containment
# boundary anywhere. Refuse a symlinked or non-directory root.
if [ -L "$css_dir" ] || [ ! -d "$css_dir" ]; then
  printf 'css-bundle: css dir is a symlink or not a directory, refusing: %s\n' "$css_dir" >&2
  exit 1
fi
css_root=$(realpath "$css_dir")
# Resolved and contained under css_root on the same terms as a manifest entry
# below (opening a FIFO for the loop redirect would otherwise block forever).
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
# Counts assembled members so an empty/fully-commented MANIFEST is refused
# below, independent of each member's own non-emptiness check inside the loop.
member_count=0
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in '' | \#*) continue ;; esac
  # realpath collapses '..' and follows symlinks, so a leading '/', a '..'
  # escape, and a shipped symlink all resolve to the same containment check.
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
  # Containment alone still admits a FIFO/device/directory; cat on a FIFO
  # would block forever. Only regular files are readable bundle members.
  if [ ! -f "$entry" ]; then
    printf 'css-bundle: MANIFEST entry is not a regular file, refusing: %s\n' "$line" >&2
    exit 1
  fi
  # Each entry is an independently required feature stylesheet, so a
  # zero-byte member (truncated/mis-published tarball) fails the build here.
  if [ ! -s "$entry" ]; then
    printf 'css-bundle: MANIFEST entry is empty, refusing: %s\n' "$line" >&2
    exit 1
  fi
  member_count=$((member_count + 1))
  # A member without a trailing newline would fuse its last line into the
  # next member's first; CSS is whitespace-insensitive between rules.
  cat "$entry" >>"$tmp"
  printf '\n' >>"$tmp"
done <"$manifest"
[ "$member_count" -gt 0 ] || {
  printf 'css-bundle: MANIFEST lists no members (empty or fully-commented?): %s\n' "$manifest" >&2
  exit 1
}
mv "$tmp" "$out"
trap - EXIT HUP INT TERM
