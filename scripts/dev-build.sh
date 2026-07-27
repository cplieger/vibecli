#!/usr/bin/env bash
# Local dev build of web-terminal-kiro against the LOCAL (working-tree) engine + UI:
# produces ./web-terminal-kiro-dev-bin with static assets embedded, built from the
# sibling ../web-terminal-engine (engine) and ../web-terminal-ui (UI) checkouts
# instead of the published Go module / npm packages — the way to try unpublished
# engine/UI changes against the real app. Run the binary directly
# (KWEB_WORK_DIR=... ./web-terminal-kiro-dev-bin; see CONTRIBUTING "Local dev setup").
#
# Not for CI or release. go.work and web-terminal-kiro-dev-bin are gitignored.
# Override the sibling checkouts with ENGINE_DIR=... / UI_DIR=...
set -euo pipefail
cd "$(dirname "$0")/.."
ENGINE_DIR="${ENGINE_DIR:-../web-terminal-engine}"
UI_DIR="${UI_DIR:-../web-terminal-ui}"
ENGINE_PKG="static-src/node_modules/@cplieger/web-terminal-engine"
UI_PKG="static-src/node_modules/@cplieger/web-terminal-ui"
# The TS7 native compiler comes from static-src's @typescript/native devDep.
TSC="static-src/node_modules/.bin/tsc"
[ -x "$TSC" ] || {
  printf "error: %s not found — run 'cd static-src && npm install' first\n" "$TSC" >&2
  exit 1
}
# Validate every required checkout input BEFORE go.work is written or the
# destructive node_modules overlay below starts, so a missing sibling checkout
# or a typo'd ENGINE_DIR/UI_DIR override fails cleanly instead of half-deleting
# the installed packages (repaired only by a fresh npm install).
for required in \
  "$ENGINE_DIR/web/package.json" \
  "$UI_DIR/package.json" "$UI_DIR/css/MANIFEST"; do
  [ -f "$required" ] || {
    printf 'error: required local checkout input is not a regular file: %s\n' "$required" >&2
    exit 1
  }
done
for required in "$ENGINE_DIR/web/src" "$UI_DIR/src"; do
  [ -d "$required" ] || {
    printf 'error: required local checkout source directory not found: %s\n' "$required" >&2
    exit 1
  }
done
# A src directory that EXISTS but holds no file the overlay would copy is the
# same failure the image build gates on (engine-src-empty / ui-src-empty), and
# it has to be caught here too: step [2/6] deletes both installed package src
# trees before copying, so an empty (or test-only) source tree otherwise slips
# past preflight and leaves node_modules broken — cp exits on a literal
# unmatched *.ts, or tsc exits 1 with no input files, in both cases only after
# the destructive overlay. Mirror each copy loop's own exclusions (matched on
# the basename, so a checkout path containing 'fuzz' is not itself excluded) so
# preflight and execution cannot drift.
[ -n "$(find "$ENGINE_DIR/web/src" -type d -name 'test-helpers' -prune -o \
  -type f -name '*.ts' ! -name '*.test.ts' ! -name '*fuzz*' ! -name '*fc-strict-setup*' -print -quit)" ] || {
  printf 'error: engine-src-empty: no eligible *.ts under %s (wrong ENGINE_DIR or src layout change?)\n' \
    "$ENGINE_DIR/web/src" >&2
  exit 1
}
[ -n "$(find "$UI_DIR/src" -type f -name '*.ts' \
  ! -name '*.test.ts' ! -name '*fuzz*' ! -name '*fc-strict-setup*' -print -quit)" ] || {
  printf 'error: ui-src-empty: no eligible *.ts under %s (wrong UI_DIR or src layout change?)\n' \
    "$UI_DIR/src" >&2
  exit 1
}

printf '[1/6] go.work -> local engine (replace published module with %s)\n' "$ENGINE_DIR"
# Mirror go.mod's go directive and engine module path so neither can drift (a
# hardcoded version here broke the build when go.mod moved to a newer patch; a
# hardcoded /v2 module path silently no-opped the replace after the v3 bump).
GO_DIRECTIVE="$(sed -n 's/^go /go /p' go.mod | head -n1)"
[ -n "$GO_DIRECTIVE" ] || {
  printf 'error: go directive not found in go.mod\n' >&2
  exit 1
}
ENGINE_MOD="$(sed -n 's|.*\(github.com/cplieger/web-terminal-engine/v[0-9]*\) .*|\1|p' go.mod | head -n1)"
[ -n "$ENGINE_MOD" ] || {
  printf 'error: engine module path not found in go.mod\n' >&2
  exit 1
}
cat >go.work <<EOF
${GO_DIRECTIVE}

use .

replace ${ENGINE_MOD} => ${ENGINE_DIR}
EOF

printf '[2/6] overlay local engine + UI TS into the bundler-resolved packages\n'
rm -rf "$ENGINE_PKG/src" "$UI_PKG/src"
mkdir -p "$ENGINE_PKG/src" "$UI_PKG/src"
cp "$ENGINE_DIR/web/package.json" "$ENGINE_PKG/package.json"
# Recursive, matching the UI loop below: the engine's src tree is flat today, but a
# future nested module must not be silently dropped (the emit assertions only check
# index.js, so the miss would surface as a runtime 404, not a build failure).
# Match the basename, not the full path: ENGINE_DIR is user-overridable and a
# checkout path containing 'fuzz' must not skip every source file. src/test-helpers/
# is pruned as a directory: recursion would otherwise pull test-support modules
# (which carry no *.test.ts basename) into the vendor emit and make the dev build
# depend on test-only code typechecking under --strict. The published tarball
# excludes them, so this keeps the local overlay matching what the image gets.
(cd "$ENGINE_DIR/web/src" && find . -type d -name 'test-helpers' -prune -o \
  -type f -name '*.ts' ! -name '*.test.ts' ! -name '*fuzz*' ! -name '*fc-strict-setup*' -print0) \
  | while IFS= read -r -d '' f; do
    mkdir -p "$ENGINE_PKG/src/$(dirname "$f")"
    cp "$ENGINE_DIR/web/src/$f" "$ENGINE_PKG/src/$f"
  done
cp "$UI_DIR/package.json" "$UI_PKG/package.json"
# The UI ships a nested src tree (src/kernel/, src/features/) since v3, so copy
# recursively, preserving subdirectories and excluding tests.
(cd "$UI_DIR/src" && find . -type f -name '*.ts' ! -name '*.test.ts' ! -name '*fuzz*' ! -name '*fc-strict-setup*' -print0) \
  | while IFS= read -r -d '' f; do
    mkdir -p "$UI_PKG/src/$(dirname "$f")"
    cp "$UI_DIR/src/$f" "$UI_PKG/src/$f"
  done

printf '[3/6] tsc: app -> static/app.js (resolves @cplieger/web-terminal-ui)\n'
# Drop the previous emit first so the assertion after step [4/6] observes THIS
# run's output: static/app.js is gitignored but persistent, so an outDir/rootDir
# change would otherwise leave a stale file that satisfies the check. The vendor
# dirs below already get the same treatment via rm -rf. (The image build is
# immune: .dockerignore keeps static/*.js out of the build context.)
rm -f static/app.js
"$TSC" --project static-src/tsconfig.json

printf '[4/6] tsc: engine + UI libs -> static/vendor/\n'
rm -rf static/vendor/cplieger-web-terminal-engine static/vendor/cplieger-web-terminal-ui
# Compile the whole overlaid engine tree (flat today; recursive so a future nested
# engine module is not silently dropped, matching the UI handling below).
mapfile -t engine_ts < <(find "$ENGINE_PKG/src" -name '*.ts')
"$TSC" --module ESNext --target ESNext --moduleResolution bundler \
  --outDir static/vendor/cplieger-web-terminal-engine \
  --rootDir "$ENGINE_PKG/src" --skipLibCheck --strict "${engine_ts[@]}"
# Compile the whole nested UI src tree (index.ts + presets.ts + kernel/ +
# features/); find collects every .ts (the overlay already excluded tests).
mapfile -t ui_ts < <(find "$UI_PKG/src" -name '*.ts')
"$TSC" --module ESNext --target ESNext --moduleResolution bundler \
  --outDir static/vendor/cplieger-web-terminal-ui \
  --rootDir "$UI_PKG/src" --skipLibCheck --strict "${ui_ts[@]}"
# Assert the emit produced every module static/index.html loads: a tsconfig
# outDir/rootDir change or a lib src-layout move otherwise yields a clean
# build whose page 404s at runtime.
for emitted in static/app.js \
  static/vendor/cplieger-web-terminal-engine/index.js \
  static/vendor/cplieger-web-terminal-ui/index.js \
  static/vendor/cplieger-web-terminal-ui/presets.js; do
  [ -s "$emitted" ] || {
    printf 'error: expected emit is absent or empty: %s (outDir/rootDir or lib src layout drift?)\n' "$emitted" >&2
    exit 1
  }
done

printf '[5/6] fonts (Monaspace Nerd Font, cached) + CSS bundle (from UI package)\n'
# Single source of truth: the Dockerfile's Renovate-managed NERDFONT_* ARGs.
# Stop at whitespace or a `#` trailer: the repo's other manually-bumped sha
# pins (GO_SHA256_*, TOOL_CATALOG_SHA256) carry a `# <name> <version>`
# Renovate anchor, and swallowing one here would feed garbage to sha256sum.
FONT_VER="$(sed -n 's/^ARG NERDFONT_VERSION=\([^[:space:]#]*\).*/\1/p' Dockerfile)"
FONT_SHA256="$(sed -n 's/^ARG NERDFONT_SHA256=\([^[:space:]#]*\).*/\1/p' Dockerfile)"
: "${FONT_VER:?failed to parse NERDFONT_VERSION from Dockerfile}"
: "${FONT_SHA256:?failed to parse NERDFONT_SHA256 from Dockerfile}"
# Key the cache dir by version AND integrity pin so a NERDFONT_VERSION bump —
# or a same-version NERDFONT_SHA256 correction — misses the cache instead of
# silently reusing stale fonts (old cache dirs are tiny and rare enough to
# leave behind). A .complete marker inside the keyed dir gates reuse: it is
# written only after every face extracted non-empty, so a tar interrupted
# mid-face (which can leave all four pathnames present, the last truncated)
# self-heals with a full retry on the next build instead of embedding a
# corrupt face.
FONT_CACHE="${HOME}/.cache/web-terminal-kiro-fonts/${FONT_VER}-${FONT_SHA256}"
FONT_CACHE_MARKER="$FONT_CACHE/.complete"
# Same single-source-of-truth rule as the NERDFONT_* pins above: the face set is the
# Dockerfile's tar member list. Hardcoding it here drifts SILENTLY (extracting the old
# four faces still succeeds), so the dev binary would embed a different font set than the
# image and only show it as tofu at runtime.
mapfile -t fonts < <(sed -n \
  's/^[[:space:]]*\(MonaspiceNeNerdFontMono-[A-Za-z]*\.otf\).*/\1/p' Dockerfile)
[ "${#fonts[@]}" -gt 0 ] || {
  printf 'error: failed to parse the Monaspace face list from Dockerfile\n' >&2
  exit 1
}
mkdir -p "$FONT_CACHE"
need_fonts=0
[ -f "$FONT_CACHE_MARKER" ] || need_fonts=1
for font in "${fonts[@]}"; do
  [ -s "$FONT_CACHE/$font" ] || need_fonts=1
done
if [ "$need_fonts" = 1 ]; then
  printf '  downloading Monaspace %s...\n' "$FONT_VER"
  rm -f "$FONT_CACHE_MARKER"
  mona_tmp="$(mktemp)"
  trap 'rm -f "$mona_tmp"' EXIT
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 20 --max-time 300 --retry 3 --retry-delay 5 -fsSL \
    "https://github.com/ryanoasis/nerd-fonts/releases/download/${FONT_VER}/Monaspace.tar.xz" \
    -o "$mona_tmp"
  printf '%s  %s\n' "$FONT_SHA256" "$mona_tmp" | sha256sum -c -
  tar -xJ -C "$FONT_CACHE" -f "$mona_tmp" "${fonts[@]}"
  rm -f "$mona_tmp"
  for font in "${fonts[@]}"; do
    [ -s "$FONT_CACHE/$font" ] || {
      printf 'error: extracted font is missing or empty: %s\n' "$FONT_CACHE/$font" >&2
      exit 1
    }
  done
  : >"$FONT_CACHE_MARKER"
fi
# Recreate the generated destination so a face dropped from the Dockerfile list
# does not survive in the dev tree: the image build starts from a clean builder
# and extracts only the current members, but a dev build reuses the working tree
# and `cp` cannot delete what the source list no longer names — the stale OTF
# would keep landing in the //go:embed static tree. $FONT_CACHE stays persistent.
rm -rf static/vendor/fonts
mkdir -p static/vendor/fonts
for font in "${fonts[@]}"; do
  cp "$FONT_CACHE/$font" static/vendor/fonts/
done

sh scripts/css-bundle.sh "$UI_DIR/css" static/style.css

printf '[6/6] go build (CGO off, host arch = image arch)\n'
CGO_ENABLED=0 go build -trimpath -o web-terminal-kiro-dev-bin .
printf 'OK -> %s/web-terminal-kiro-dev-bin (%s)\n' "$(pwd)" "$(du -h web-terminal-kiro-dev-bin | cut -f1)"
