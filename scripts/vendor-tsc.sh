#!/usr/bin/env bash
# Compile ONE vendored @cplieger TS package's src tree into the served
# static/vendor/<name>/ directory. Canonical recipe, shared by the Dockerfile
# builder and scripts/dev-build.sh so the image and the dev binary cannot end up
# compiled with different flags -- a dev/prod parity break no pin gate can see.
#
# -type f, not a bare -name: a directory, symlink or FIFO named *.ts in a
# mis-published or crafted vendored tarball would otherwise be handed to tsc, and
# a FIFO blocks the build forever with no deadline -- the same class
# scripts/css-bundle.sh refuses per MANIFEST entry for the CSS half of this build.
#
# Usage: vendor-tsc.sh <tsc-binary> <label> <src-dir> <out-dir>
set -euo pipefail
usage='usage: vendor-tsc.sh <tsc-binary> <label> <src-dir> <out-dir>'
tsc=${1:?$usage}
label=${2:?$usage}
src=${3:?$usage}
out=${4:?$usage}

mapfile -t sources < <(find "$src" -type f -name '*.ts')
[ "${#sources[@]}" -gt 0 ] || {
  printf 'ERROR %s-src-empty: no *.ts under %s (tarball or checkout layout changed?)\n' \
    "$label" "$src" >&2
  exit 1
}

"$tsc" \
  --module ESNext \
  --target ESNext \
  --moduleResolution bundler \
  --outDir "$out" \
  --rootDir "$src" \
  --skipLibCheck \
  --strict \
  "${sources[@]}"
