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
  "$ENGINE_DIR/web/package.json" "$ENGINE_DIR/web/wire-compatibility.json" \
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
# the destructive overlay. Match the basename, not the full path (so a checkout
# path containing 'fuzz' is not itself excluded); src/test-helpers/ is pruned as a
# DIRECTORY because recursion would otherwise pull test-support modules (which
# carry no *.test.ts basename) into the vendor emit and make the dev build depend
# on test-only code typechecking under --strict — the published tarball excludes
# them, so this keeps the local overlay matching what the image gets. The list
# captured here IS the list step [2/6] copies, so preflight and execution cannot
# drift.
mapfile -d '' -t engine_src < <(cd "$ENGINE_DIR/web/src" && find . \
  -type d -name 'test-helpers' -prune -o \
  -type f -name '*.ts' ! -name '*.test.ts' ! -name '*fuzz*' ! -name '*fc-strict-setup*' -print0)
[ "${#engine_src[@]}" -gt 0 ] || {
  printf 'error: engine-src-empty: no eligible *.ts under %s (wrong ENGINE_DIR or src layout change?)\n' \
    "$ENGINE_DIR/web/src" >&2
  exit 1
}
mapfile -d '' -t ui_src < <(cd "$UI_DIR/src" && find . \
  -type f -name '*.ts' ! -name '*.test.ts' ! -name '*fuzz*' ! -name '*fc-strict-setup*' -print0)
[ "${#ui_src[@]}" -gt 0 ] || {
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
# The wire-compatibility manifest is a PACKAGE-ROOT file, so the src overlay
# below does not carry it: without this copy the gate would read whatever the
# installed tarball shipped — stale for an unpublished local engine, which is
# exactly the case the gate exists for. The engine generates it from
# web/src/wire-manifest.ts, so a local checkout has it (preflight asserts so
# before the destructive overlay starts).
cp "$ENGINE_DIR/web/wire-compatibility.json" "$ENGINE_PKG/wire-compatibility.json"
# Copy the list captured in preflight (recursive, matching the UI loop below: the
# engine's src tree is flat today, but a future nested module must not be silently
# dropped — the emit assertions only check index.js, so the miss would surface as a
# runtime 404, not a build failure).
for f in "${engine_src[@]}"; do
  mkdir -p "$ENGINE_PKG/src/$(dirname "$f")"
  cp "$ENGINE_DIR/web/src/$f" "$ENGINE_PKG/src/$f"
done
cp "$UI_DIR/package.json" "$UI_PKG/package.json"
# The UI ships a nested src tree (src/kernel/, src/features/) since v3, so the
# captured list is recursive and preserves subdirectories.
for f in "${ui_src[@]}"; do
  mkdir -p "$UI_PKG/src/$(dirname "$f")"
  cp "$UI_DIR/src/$f" "$UI_PKG/src/$f"
done

# Wire-floor gate, mirroring the Dockerfile step after its vendor fetch: the Go
# half comes from go.work (the LOCAL engine) and the client half from the overlay
# above, so a dev build of an unpublished engine is exactly where the two floors
# can disagree. Without this the pairing fails at first connect (close 4002) with
# /api/health green and no build-time diagnostic. Built and then invoked, never
# `go run`, which collapses the gate's exit 2 ("the gate cannot read the client's
# declaration, do NOT bump a pin") into a plain 1. The client half is read from
# the engine's own manifest by the gate itself (encoding/json), so this script
# parses nothing.
wirecheck_bin="$(mktemp)"
# The gate's whole purpose is to EXIT non-zero (1 on a floor violation, 2 on a broken
# extraction), and under set -euo pipefail either exit -- like a failing go build --
# skips the rm below, leaking a multi-megabyte binary per failing run. Trap it, then
# disarm once the binary is removed: EXIT traps do not stack (a later step arming its
# own would silently replace this one), so no step may leave one armed past its use.
trap 'rm -f "$wirecheck_bin"' EXIT
go build -o "$wirecheck_bin" ./scripts/wirecheck
"$wirecheck_bin" -manifest "$ENGINE_PKG/wire-compatibility.json"
rm -f "$wirecheck_bin"
trap - EXIT

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
# Canonical recipe: scripts/vendor-tsc.sh, shared with the Dockerfile builder, so
# the dev binary and the image cannot end up compiled with different flags. It
# collects the whole tree recursively (the engine's is flat today; a future nested
# module must not be silently dropped) and carries the <label>-src-empty gate.
bash scripts/vendor-tsc.sh "$TSC" engine "$ENGINE_PKG/src" \
  static/vendor/cplieger-web-terminal-engine
bash scripts/vendor-tsc.sh "$TSC" ui "$UI_PKG/src" \
  static/vendor/cplieger-web-terminal-ui
# Assert the emit produced every module static/index.html loads: a tsconfig
# outDir/rootDir change or a lib src-layout move otherwise yields a clean
# build whose page 404s at runtime. Canonical recipe: scripts/assert-emit.sh,
# shared with the Dockerfile builder, and it DERIVES the target list from the
# page's own importmap rather than restating it here.
sh scripts/assert-emit.sh

printf '[5/6] fonts (Monaspace Neon NF webfonts, cached) + CSS bundle (from UI package)\n'
# Single source of truth: the Dockerfile's Renovate-managed MONASPACE_* ARGs
# and its fetch layer. Stop at whitespace or a `#` trailer: the repo's other
# manually-bumped sha pins (GO_SHA256_*, TOOL_CATALOG_SHA256) carry a
# `# <name> <version>` Renovate anchor, and swallowing one here would feed
# garbage to sha256sum.
FONT_VER="$(sed -n 's/^ARG MONASPACE_VERSION=\([^[:space:]#]*\).*/\1/p' Dockerfile)"
: "${FONT_VER:?failed to parse MONASPACE_VERSION from Dockerfile}"
# Face set: every vendored .woff2 filename the Dockerfile names (family-free
# match, same anti-drift rule as the old tar member list — a face renamed or
# dropped in the image must change this list in lockstep, or the dev binary
# would embed a different font set than the image and only show it as tofu at
# runtime).
mapfile -t fonts < <(grep -oE 'static/vendor/fonts/[A-Za-z0-9.-]+\.woff2' Dockerfile | sed 's|.*/||' | sort -u)
[ "${#fonts[@]}" -gt 0 ] || {
  printf 'error: failed to parse the Monaspace face list from Dockerfile\n' >&2
  exit 1
}
# Fetch base: the repin marker's URL template (the same literal Renovate's
# postUpgradeTask reads), {version} substituted — so the URL too is
# single-sourced in the Dockerfile.
FONT_URL_TMPL="$(sed -n 's|^# repin: dep=githubnext/monaspace url=\(.*\)/[^/]*$|\1|p' Dockerfile | head -n1)"
: "${FONT_URL_TMPL:?failed to parse the monaspace repin URL from Dockerfile}"
FONT_BASE_URL="${FONT_URL_TMPL//\{version\}/$FONT_VER}"
# Per-face pins, keyed by the face token in the filename
# (MonaspaceNeonNF-<Face>.woff2 -> ARG MONASPACE_<FACE>_SHA256). The cache dir
# is keyed by version AND a digest of all four pins so a MONASPACE_VERSION
# bump — or a same-version sha correction — misses the cache instead of
# silently reusing stale fonts. A .complete marker inside the keyed dir gates
# reuse: it is written only after every face downloaded AND verified, so an
# interrupted fetch self-heals with a full retry on the next build instead of
# embedding a corrupt face.
declare -A font_sha
combined=""
for font in "${fonts[@]}"; do
  face="${font##*-}"
  face="${face%.woff2}"
  arg_name="MONASPACE_$(printf '%s' "$face" | tr '[:lower:]' '[:upper:]')_SHA256"
  sha="$(sed -n "s/^ARG ${arg_name}=\([^[:space:]#]*\).*/\1/p" Dockerfile)"
  [ -n "$sha" ] || {
    printf 'error: failed to parse %s from Dockerfile\n' "$arg_name" >&2
    exit 1
  }
  font_sha["$font"]="$sha"
  combined="${combined}${sha}"
done
FONT_CACHE="${HOME}/.cache/web-terminal-kiro-fonts/${FONT_VER}-$(printf '%s' "$combined" | sha256sum | cut -c1-16)"
FONT_CACHE_MARKER="$FONT_CACHE/.complete"
mkdir -p "$FONT_CACHE"
need_fonts=0
[ -f "$FONT_CACHE_MARKER" ] || need_fonts=1
for font in "${fonts[@]}"; do
  [ -s "$FONT_CACHE/$font" ] || need_fonts=1
done
if [ "$need_fonts" = 1 ]; then
  printf '  downloading Monaspace Neon NF %s...\n' "$FONT_VER"
  rm -f "$FONT_CACHE_MARKER"
  for font in "${fonts[@]}"; do
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 20 --max-time 300 --retry 3 --retry-delay 5 -fsSL \
      "${FONT_BASE_URL}/${font}" -o "$FONT_CACHE/$font"
    printf '%s  %s\n' "${font_sha[$font]}" "$FONT_CACHE/$font" | sha256sum -c -
    [ -s "$FONT_CACHE/$font" ] || {
      printf 'error: downloaded font is missing or empty: %s\n' "$FONT_CACHE/$font" >&2
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
