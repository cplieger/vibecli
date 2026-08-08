#!/bin/sh
# Assert every module the served page loads was emitted non-empty. Canonical
# recipe, shared by the Dockerfile builder and scripts/dev-build.sh: a tsconfig
# outDir/rootDir change or a lib src-layout move otherwise yields a clean build
# whose page 404s at runtime.
#
# The vendor targets are DERIVED from static/index.html's own importmap (the same
# extraction tests/image-smoke.conf's smoke_verify() runs against the SERVED
# page), so adding an importmap entry cannot leave a build path unchecked. The
# emit list used to be hardcoded twice -- once here, once in dev-build.sh -- and
# a new entry could ship a page that 404s the module it just added. static/app.js
# is asserted separately: it is the <script type=module src>, not an importmap
# entry.
#
# Usage: assert-emit.sh [index.html] [static-dir]
set -eu
page=${1:-static/index.html}
root=${2:-static}

targets=$(sed -n '/<script type="importmap">/,/<\/script>/p' "$page" \
  | grep -o '"/[^"]*"' | tr -d '"')
[ -n "$targets" ] || {
  printf 'ERROR importmap-empty: no importmap targets found in %s\n' "$page" >&2
  exit 1
}

for t in /app.js $targets; do
  [ -s "${root}${t}" ] || {
    printf 'ERROR tsc-emit-missing: %s is absent or empty after the tsc steps, so %s would 404 at runtime (outDir/rootDir or vendored src layout drift?)\n' \
      "${root}${t}" "$t" >&2
    exit 1
  }
done
