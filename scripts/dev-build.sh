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
  "$ENGINE_DIR/web/package.json" "$ENGINE_DIR/web/src" \
  "$UI_DIR/package.json" "$UI_DIR/src" "$UI_DIR/css/MANIFEST"; do
  [ -e "$required" ] || {
    printf 'error: required local checkout input not found: %s\n' "$required" >&2
    exit 1
  }
done

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
for f in "$ENGINE_DIR"/web/src/*.ts; do
  # Match the basename, not the full path: ENGINE_DIR is user-overridable
  # and a checkout path containing 'fuzz' must not skip every source file.
  case "${f##*/}" in *.test.ts | *fuzz* | *fc-strict-setup*) continue ;; esac
  cp "$f" "$ENGINE_PKG/src/"
done
cp "$UI_DIR/package.json" "$UI_PKG/package.json"
# The UI ships a nested src tree (src/kernel/, src/features/) since v3, so copy
# recursively, preserving subdirectories and excluding tests.
(cd "$UI_DIR/src" && find . -name '*.ts' ! -name '*.test.ts' ! -name '*fuzz*' ! -name '*fc-strict-setup*' -print0) \
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
"$TSC" --module ESNext --target ESNext --moduleResolution bundler \
  --outDir static/vendor/cplieger-web-terminal-engine \
  --rootDir "$ENGINE_PKG/src" --skipLibCheck --strict "$ENGINE_PKG/src"/*.ts
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
FONT_VER="$(sed -n 's/^ARG NERDFONT_VERSION=//p' Dockerfile)"
FONT_SHA256="$(sed -n 's/^ARG NERDFONT_SHA256=//p' Dockerfile)"
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
fonts=(
  MonaspiceNeNerdFontMono-Regular.otf
  MonaspiceNeNerdFontMono-Bold.otf
  MonaspiceNeNerdFontMono-Italic.otf
  MonaspiceNeNerdFontMono-BoldItalic.otf
)
mkdir -p "$FONT_CACHE" static/vendor/fonts
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
for font in "${fonts[@]}"; do
  cp "$FONT_CACHE/$font" static/vendor/fonts/
done

sh scripts/css-bundle.sh "$UI_DIR/css" static/style.css

printf '[6/6] go build (CGO off, host arch = image arch)\n'
CGO_ENABLED=0 go build -trimpath -o web-terminal-kiro-dev-bin .
printf 'OK -> %s/web-terminal-kiro-dev-bin (%s)\n' "$(pwd)" "$(du -h web-terminal-kiro-dev-bin | cut -f1)"
