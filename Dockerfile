# check=error=true

# --- Builder stage: compile Go server + vendor the web-terminal engine/UI TS ---
FROM debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS builder

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# Official Go tarballs currently set GOTOOLCHAIN=auto in $GOROOT/go.env; keep it
# explicit here so the builder's policy does not depend on that packaged default. A
# downloaded toolchain is checksum-database verified, so the tarball sha gate keeps
# its meaning when go.mod requires a newer toolchain.
ENV GOTOOLCHAIN=auto

# hadolint ignore=DL3008
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    ca-certificates curl xz-utils && rm -rf /var/lib/apt/lists/*

# Go for building the web server. GO_VERSION and both per-arch tarball sha256
# pins move together, maintained by Renovate: the golang-amd64 / golang-arm64
# custom datasources (in cplieger/.github default.json) read go.dev's
# ?mode=json and rewrite GO_SHA256_AMD64 / GO_SHA256_ARM64 alongside GO_VERSION
# in one grouped "golang toolchain" PR (CI builds amd64 and arm64 natively).
# The `# go<version>` trailer on each sha line is the anchor Renovate uses to
# resolve that arch's digest — do not hand-edit; Renovate owns these lines.
# renovate: datasource=golang-version depName=golang
ARG GO_VERSION=1.26.5
# renovate: datasource=custom.golang-amd64 depName=golang-amd64
ARG GO_SHA256_AMD64=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053  # go1.26.5
# renovate: datasource=custom.golang-arm64 depName=golang-arm64
ARG GO_SHA256_ARM64=fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49  # go1.26.5
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
      amd64) GO_SHA256="$GO_SHA256_AMD64" ;; \
      arm64) GO_SHA256="$GO_SHA256_ARM64" ;; \
      *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac && \
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 20 --max-time 300 --retry 3 --retry-delay 5 -fsSL -o /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" && \
    printf '%s  /tmp/go.tar.gz\n' "$GO_SHA256" | sha256sum -c - && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# tsc — the TypeScript 7 native compiler (a Go binary) — compiles the browser
# client at build time (emit lands in static/app.js for go:embed). Matches
# apps/vibekit's approach. Now that TS7 shipped stable, the native compiler is
# the `typescript` package's per-platform `tsc`
# (@typescript/typescript-linux-<arch>, published in lockstep with the
# metapackage). Runtime LSPs are not baked — the toolbelt engine installs
# them on demand from the /config/tools.json manifest.
# renovate: datasource=npm depName=typescript
ARG TS_VERSION=7.0.2
# sha256 of the platform-specific tsc tarball, per arch. npm publishes SHA-512
# (dist.integrity), not this SHA-256, so Renovate bumps TS_VERSION but cannot
# move these — the manual-sha-bump rule in cplieger/.github (scoped to this
# repo) labels the PR with the recompute commands. Update both alongside
# TS_VERSION (the linux-x64 and linux-arm64 packages publish in lockstep).
# Upstream toolchain vuln tracking: the pinned 7.0.2 tsc binaries were built
# with Go 1.26.4 + golang.org/x/text v0.38.0, which govulncheck -mode=binary
# flags for GO-2026-5970 / GO-2026-5856 / GO-2026-4970. The compiler lives
# only in this discarded builder stage, so the residual risk is build/CI
# denial of service on crafted compiler input — nothing vulnerable ships in
# the runtime image. No rebuilt upstream package exists yet (7.0.2 is npm's
# latest). On the next TS native-compiler release: bump TS_VERSION and both
# shas together, then verify `go version -m` on both downloaded tsc binaries
# shows Go >= 1.26.5 and x/text >= v0.39.0, and re-run
# `govulncheck -mode=binary` as the gate. Never drop these sha256 checks or
# substitute an unpinned latest package while waiting.
ARG TS_SHA256_X64=7ecad6f67377e831856367ab062ef394f21506a611405bf8ac0ff039348637d3
ARG TS_SHA256_ARM64=c83d931ac9dd7549cde6e71246aa9d6a9812843023df3e277fe3b5dcf41dd0ea
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
      amd64) TS_ARCH="x64";   TS_SHA256="$TS_SHA256_X64" ;; \
      arm64) TS_ARCH="arm64"; TS_SHA256="$TS_SHA256_ARM64" ;; \
      *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac && \
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 20 --max-time 300 --retry 3 --retry-delay 5 -fsSL -o /tmp/tsc.tgz \
      "https://registry.npmjs.org/@typescript/typescript-linux-${TS_ARCH}/-/typescript-linux-${TS_ARCH}-${TS_VERSION}.tgz" && \
    printf '%s  /tmp/tsc.tgz\n' "$TS_SHA256" | sha256sum -c - && \
    tar -xz -C /tmp -f /tmp/tsc.tgz && \
    rm /tmp/tsc.tgz

# Nerd Font. kiro-cli's diff UI uses nerd-font private-use-area
# glyphs (line markers, file-type icons). System monospace fonts
# don't carry these, so they render as tofu (black squares) in
# the terminal display. Bundling one Mono-width Nerd Font + serving
# it via @font-face fixes that. The four MonaspiceNe Nerd Font Mono
# faces grow the web-terminal-kiro binary via go:embed and ship gzipped
# over the wire.
# renovate: datasource=github-releases depName=ryanoasis/nerd-fonts
ARG NERDFONT_VERSION=v3.4.0
# sha256 of Monaspace.tar.xz for this tag. GitHub release assets are MUTABLE (a
# retag can swap the bytes under a fixed tag), so this gate is the real
# integrity anchor here. Update alongside NERDFONT_VERSION.
ARG NERDFONT_SHA256=5fdb97828e1a23fd28ea5ed0e7d15cdebb77ef079aaa48b93f1526764b40ef8c

WORKDIR /build
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/go/pkg/mod go mod download
# Only the files the network-heavy steps below actually need are copied
# before them, so a source edit doesn't invalidate the catalog compile,
# font fetch, or npm vendor fetch layers. The full tree lands after.
COPY required-tools.txt ./

# Bake the published tool catalog as the first-boot/offline fallback.
# The catalog (install knowledge for ~700 tools joined from the mise +
# aqua registries by cplieger/tool-catalog's daily publisher; both
# registries' MIT license texts travel INSIDE the JSON) is DATA on a
# daily upstream cadence — the runtime engine refreshes it at boot and
# on a schedule (TOOL_CATALOG_REFRESH), so this baked copy only serves
# a container that has never reached the publisher. Fetched from an
# IMMUTABLE release asset and gated on TOOL_CATALOG_SHA256 before use:
# `latest/download` was mutable, and TLS authenticates GitHub, not the
# artifact, so a swapped release asset (compromised publisher account)
# could replace the catalog between otherwise identical builds. That
# matters because catalog entries carry install recipes (including the
# `manual` shell-command source) executed by the root-running tool
# engine. `toolcatalog verify` below is a SEMANTIC coverage gate, not an
# authenticity one: it asserts every required-tools.txt name resolves to
# usable install knowledge for linux amd64+arm64 — a published catalog
# that drops a seed or migration tool FAILS THE BUILD here, and the
# runtime refresh re-runs the same check before every swap. The two
# checks cover different threats; both run, authenticity first.
# TOOL_CATALOG_VERSION + TOOL_CATALOG_SHA256 move together in one
# Renovate PR (the `# tool-catalog <version>` trailer is the digest's
# version anchor — same trailer model as the kiro-cli/golang per-arch sha
# pins; the grouping + digest recompute rule lives in cplieger/.github's
# default.json, never in this repo's inherited renovate.json). The
# publisher's cadence is daily; the pin means the baked fallback is a
# REVIEWED catalog, while the runtime refresh keeps a running container
# current.
# renovate: datasource=github-releases depName=cplieger/tool-catalog
ARG TOOL_CATALOG_VERSION=v2026.07.24.1907
ARG TOOL_CATALOG_SHA256=651d11d218a313a029d7a7ad15eedccdaa1c2c7a48aad39661c33d0684b864cb # tool-catalog v2026.07.24.1907
ARG TOOL_CATALOG_URL=https://github.com/cplieger/tool-catalog/releases/download/${TOOL_CATALOG_VERSION}/tool-catalog.json
# renovate: datasource=go depName=github.com/cplieger/toolbelt/v2
# This is the SAME module go.mod requires (the runtime engine that re-verifies
# required-tools.txt before every catalog swap), pinned a second time here to
# select the build-time `toolcatalog verify` binary. The toolbelt-pin-gate in
# the RUN below asserts the two pins are equal, so the build gate and the
# runtime gate can never become different verifiers — same fail-loud treatment
# the engine/UI/tsc pin pairs get against static-src/package.json.
ARG TOOLBELT_TOOLCATALOG_VERSION=v2.2.8
# hadolint ignore=DL3062
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    TOOLBELT_GOMOD=$(sed -n 's|^[[:space:]]*github.com/cplieger/toolbelt/v2 \(v[0-9][^[:space:]]*\).*|\1|p' go.mod | head -n1) && \
    : "${TOOLBELT_GOMOD:?toolbelt-pin-gate: no github.com/cplieger/toolbelt/v2 require found in go.mod}" && \
    if [ "$TOOLBELT_GOMOD" != "$TOOLBELT_TOOLCATALOG_VERSION" ]; then \
      echo "ERROR toolbelt-pin-mismatch: go.mod requires github.com/cplieger/toolbelt/v2 ${TOOLBELT_GOMOD} but Dockerfile ARG TOOLBELT_TOOLCATALOG_VERSION=${TOOLBELT_TOOLCATALOG_VERSION}; the build-time catalog verifier must be the same version as the runtime engine that re-verifies before every swap" >&2; exit 1; \
    fi && \
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 20 --max-time 300 --retry 3 --retry-delay 5 -fsSL -o /tmp/tool-catalog.json "${TOOL_CATALOG_URL}" && \
    printf '%s  /tmp/tool-catalog.json\n' "$TOOL_CATALOG_SHA256" | sha256sum -c - && \
    go run "github.com/cplieger/toolbelt/v2/cmd/toolcatalog@${TOOLBELT_TOOLCATALOG_VERSION}" \
      verify -catalog /tmp/tool-catalog.json -require required-tools.txt

# Fetch Nerd Font for the monospace terminal display.
RUN mkdir -p static/vendor/fonts && \
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 20 --max-time 300 --retry 3 --retry-delay 5 -fsSL -o /tmp/mona.tar.xz \
      "https://github.com/ryanoasis/nerd-fonts/releases/download/${NERDFONT_VERSION}/Monaspace.tar.xz" && \
    printf '%s  /tmp/mona.tar.xz\n' "$NERDFONT_SHA256" | sha256sum -c - && \
    tar -xJ -C static/vendor/fonts -f /tmp/mona.tar.xz \
        MonaspiceNeNerdFontMono-Regular.otf \
        MonaspiceNeNerdFontMono-Bold.otf \
        MonaspiceNeNerdFontMono-Italic.otf \
        MonaspiceNeNerdFontMono-BoldItalic.otf && \
    rm /tmp/mona.tar.xz

# Fetch the engine + UI TypeScript from the npm registry. Both publish TS
# source only (no precompiled JS) — same pattern as @cplieger/reactive,
# matching how local TS files in static-src/ are treated. Extracted side by
# side under static-src/node_modules/@cplieger so tsc's bundler resolution
# finds the engine when compiling the UI's `@cplieger/web-terminal-engine` import.
# Integrity note: unlike the Go, tsc, and Nerd Font fetches above, the two
# @cplieger npm tarballs are NOT sha256-pinned. npm published package versions
# are immutable (the registry refuses to re-publish an existing version), and
# both are first-party packages fetched over pinned TLS (--proto '=https'
# --tlsv1.2 below). The residual risk (a registry-side byte-swap or a
# first-party npm account takeover) is accepted here; add per-package sha256
# ARGs + `sha256sum -c` for parity with the tsc gate if that risk is later
# deemed in scope (at the cost of a manual sha bump on each engine/UI release).
# renovate: datasource=npm depName=@cplieger/web-terminal-engine
ARG CPLIEGER_WEB_TERMINAL_ENGINE_VERSION=3.2.0
# renovate: datasource=npm depName=@cplieger/web-terminal-ui
ARG CPLIEGER_WEB_TERMINAL_UI_VERSION=5.0.0
# Pin gate (client-bundle parity): the SERVED client bundle is built from the
# ARG-pinned npm tarballs above while static-src/package.json pins what local
# dev compiles against — nothing else fails when they disagree, which is
# exactly how v1.1.3 shipped a 2.4.0 client against a 2.5.0 server. Assert
# engine ARG == package.json engine pin and UI ARG == package.json UI pin
# (the docker-builds dev/prod parity rule) BEFORE fetching, so a manual bump
# that misses a pin dies here with a named error. go.mod is deliberately NOT
# compared: the engine's Go module and npm package version independently per
# release (a Go-only release moves the tag without publishing npm, so lockstep
# is not satisfiable); wire compatibility across the two halves is the
# engine's own contract (wire_binary protocol version + the conformance
# suite), not a version-string equality — asserted mechanically by the
# wire-floor gate after the vendor fetch below. Renovate moves the
# ARG+package.json pins in one grouped PR on the routine path; this gate
# catches the human bypass. The tsc compiler pair (ARG TS_VERSION vs
# static-src/package.json's @typescript/native pin) is asserted for the same
# dev/prod-parity reason: the served bundle must be compiled by the same tsc
# version local dev typechecked against.
COPY static-src/package.json static-src/package.json
RUN ENGINE_NPM=$(sed -n 's|.*"@cplieger/web-terminal-engine": "\([^"]*\)".*|\1|p' static-src/package.json) && \
    UI_NPM=$(sed -n 's|.*"@cplieger/web-terminal-ui": "\([^"]*\)".*|\1|p' static-src/package.json) && \
    : "${ENGINE_NPM:?pin-gate: no @cplieger/web-terminal-engine pin found in static-src/package.json}" && \
    : "${UI_NPM:?pin-gate: no @cplieger/web-terminal-ui pin found in static-src/package.json}" && \
    if [ "$ENGINE_NPM" != "$CPLIEGER_WEB_TERMINAL_ENGINE_VERSION" ]; then \
      echo "ERROR engine-pin-mismatch: static-src/package.json pins @cplieger/web-terminal-engine ${ENGINE_NPM} but Dockerfile ARG CPLIEGER_WEB_TERMINAL_ENGINE_VERSION=${CPLIEGER_WEB_TERMINAL_ENGINE_VERSION}" >&2; exit 1; \
    fi && \
    if [ "$UI_NPM" != "$CPLIEGER_WEB_TERMINAL_UI_VERSION" ]; then \
      echo "ERROR ui-pin-mismatch: static-src/package.json pins @cplieger/web-terminal-ui ${UI_NPM} but Dockerfile ARG CPLIEGER_WEB_TERMINAL_UI_VERSION=${CPLIEGER_WEB_TERMINAL_UI_VERSION}" >&2; exit 1; \
    fi && \
    TSC_NPM=$(sed -n 's|.*"@typescript/native": "npm:typescript@\([^"]*\)".*|\1|p' static-src/package.json) && \
    : "${TSC_NPM:?pin-gate: no @typescript/native pin found in static-src/package.json}" && \
    if [ "$TSC_NPM" != "$TS_VERSION" ]; then \
      echo "ERROR tsc-pin-mismatch: static-src/package.json pins @typescript/native npm:typescript@${TSC_NPM} but Dockerfile ARG TS_VERSION=${TS_VERSION}" >&2; exit 1; \
    fi && \
    mkdir -p static-src/node_modules/@cplieger/web-terminal-engine static-src/node_modules/@cplieger/web-terminal-ui && \
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 20 --max-time 300 --retry 3 --retry-delay 5 -fsSL -o /tmp/engine.tgz "https://registry.npmjs.org/@cplieger/web-terminal-engine/-/web-terminal-engine-${CPLIEGER_WEB_TERMINAL_ENGINE_VERSION}.tgz" && \
    tar -xz -C static-src/node_modules/@cplieger/web-terminal-engine --strip-components=1 -f /tmp/engine.tgz && \
    rm /tmp/engine.tgz && \
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 20 --max-time 300 --retry 3 --retry-delay 5 -fsSL -o /tmp/ui.tgz "https://registry.npmjs.org/@cplieger/web-terminal-ui/-/web-terminal-ui-${CPLIEGER_WEB_TERMINAL_UI_VERSION}.tgz" && \
    tar -xz -C static-src/node_modules/@cplieger/web-terminal-ui --strip-components=1 -f /tmp/ui.tgz && \
    rm /tmp/ui.tgz

# Full source tree, after every network fetch above so source edits reuse
# those layers. .dockerignore excludes static-src/node_modules/ and
# static/vendor/, so the pinned fetches above are never overlaid by local
# dev copies.
COPY . ./

# Wire-floor gate (cross-language compatibility): go.mod's engine module and
# the ARG-pinned npm client version independently (see the pin gate above),
# so their pairing is governed by the engine's exported wire-compatibility
# floors, not version strings. Assert both directional floors at build time —
# a declared-incompatible pairing would refuse every session at first connect
# (close code 4002) while /api/health stays green, so fail HERE instead.
# Client constants come from the vendored artifact fetched above (published
# source, frozen export shape); server constants come from the engine's
# public Go API inside scripts/wirecheck (no source scraping on the Go half).
# hadolint ignore=DL3062
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    WIRE_TS=static-src/node_modules/@cplieger/web-terminal-engine/src/wire-compatibility.ts && \
    CLIENT_REV=$(sed -n 's|^export const WIRE_PROTOCOL_VERSION = \([0-9]\{1,\}\);.*|\1|p' "$WIRE_TS") && \
    CLIENT_MIN_SERVER=$(sed -n 's|^export const MIN_SUPPORTED_SERVER_WIRE_VERSION = \([0-9]\{1,\}\);.*|\1|p' "$WIRE_TS") && \
    : "${CLIENT_REV:?wire-floor-gate: WIRE_PROTOCOL_VERSION not found in the vendored engine artifact (source layout changed?)}" && \
    : "${CLIENT_MIN_SERVER:?wire-floor-gate: MIN_SUPPORTED_SERVER_WIRE_VERSION not found in the vendored engine artifact (source layout changed?)}" && \
    go run ./scripts/wirecheck -client-rev "$CLIENT_REV" -client-min-server "$CLIENT_MIN_SERVER"

# Compile client TypeScript and the engine + UI libs in a single layer.
# Must run before the binary build because main.go's `//go:embed static`
# captures static/ at `go build` time.
#
# Step 1: tsc --project compiles app TS — tsconfig.json's outDir is
# "../static", so tsc writes static/app.js directly into the embed tree.
# The lib import (`@cplieger/web-terminal-ui`) is preserved in the emit as a
# bare specifier; the browser resolves it via the importmap in
# static/index.html.
#
# Steps 2+3: compile the engine and UI TS source into static/vendor/ so the
# browser can fetch the compiled JS via the importmap. Internal imports (the
# UI's bare `@cplieger/web-terminal-engine` and both packages' relative `./*.js`) are
# preserved and resolve via the importmap + vendored dirs at runtime.
RUN mapfile -t ui_ts < <(find static-src/node_modules/@cplieger/web-terminal-ui/src -name '*.ts') && \
    mapfile -t engine_ts < <(find static-src/node_modules/@cplieger/web-terminal-engine/src -name '*.ts') && \
    { [ "${#ui_ts[@]}" -gt 0 ] \
      || { echo "ERROR ui-src-empty: no *.ts under the vendored @cplieger/web-terminal-ui src tree (tarball layout changed?)" >&2; exit 1; }; } && \
    { [ "${#engine_ts[@]}" -gt 0 ] \
      || { echo "ERROR engine-src-empty: no *.ts under the vendored @cplieger/web-terminal-engine src tree (tarball layout changed?)" >&2; exit 1; }; } && \
    /tmp/package/lib/tsc --project static-src/tsconfig.json && \
    /tmp/package/lib/tsc \
        --module ESNext \
        --target ESNext \
        --moduleResolution bundler \
        --outDir static/vendor/cplieger-web-terminal-engine \
        --rootDir static-src/node_modules/@cplieger/web-terminal-engine/src \
        --skipLibCheck \
        --strict \
        "${engine_ts[@]}" && \
    /tmp/package/lib/tsc \
        --module ESNext \
        --target ESNext \
        --moduleResolution bundler \
        --outDir static/vendor/cplieger-web-terminal-ui \
        --rootDir static-src/node_modules/@cplieger/web-terminal-ui/src \
        --skipLibCheck \
        --strict \
        "${ui_ts[@]}" && \
    for emitted in static/app.js \
        static/vendor/cplieger-web-terminal-engine/index.js \
        static/vendor/cplieger-web-terminal-ui/index.js \
        static/vendor/cplieger-web-terminal-ui/presets.js; do \
      [ -s "$emitted" ] || { echo "ERROR tsc-emit-missing: $emitted is absent or empty after the tsc steps; static/index.html's script and importmap targets would 404 at runtime (outDir/rootDir or vendored src layout drift?)" >&2; exit 1; }; \
    done

# Concatenate the UI package's per-feature CSS splits into the served bundle
# (canonical recipe: scripts/css-bundle.sh, shared with scripts/dev-build.sh).
RUN sh scripts/css-bundle.sh static-src/node_modules/@cplieger/web-terminal-ui/css static/style.css

# Build the Go binary with static assets embedded via go:embed.
# CGO disabled so the binary runs on any glibc.
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /web-terminal-kiro .

# --- Final stage: minimal runtime with kiro-cli + git ---
FROM debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Baked-in dependencies. kiro-cli itself is downloaded on first boot
# by entrypoint.sh (licensing prevents us from baking it into the
# image); everything else is stable utility surface web-terminal-kiro or the
# interactive user needs:
#   - bash: the entrypoint interpreter (entrypoint.sh is a bash
#     script; Debian's /bin/sh is dash)
#   - ca-certificates + curl + unzip: kiro-cli installer + HTTPS trust
#   - git: source control from inside the terminal (gh is NOT baked; it
#     is opt-in via /config/tools.json)
#   - openssh-client: git over ssh (and gh over ssh once gh is enabled)
#   - jq + less: standard kiro-cli diagnostic dependencies
#   - libasound2: kiro-cli dlopens libasound.so.2 at runtime. It is NOT
#     declared in kiro-cli's .deb manifest (which only lists GUI deps:
#     libayatana-appindicator3-1, libwebkit2gtk-4.1-0, libgtk-3-0) — it
#     gets pulled transitively via libwebkit2gtk on the desktop install.
#     Our headless zip variant bypasses apt entirely, so without this
#     line kiro-cli aborts on first invocation with
#     "error while loading shared libraries: libasound.so.2: cannot open
#     shared object file". Surfaced once kiro-cli >= 2.6 started
#     exercising the code path.
#   - xz-utils: .tar.xz extraction for tools the toolbelt engine
#     installs at runtime (several aqua/mise catalog entries ship
#     .tar.xz archives)
#
# Session persistence is handled by the shared web-terminal-engine
# vt package — the server keeps an authoritative cell buffer and
# replays the current snapshot on each WS reconnect. No external
# multiplexer (tmux/dtach) is required.
# hadolint ignore=DL3008
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    jq \
    less \
    libasound2 \
    openssh-client \
    unzip \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Language servers and developer tools (gh, linters, runtimes) are NOT
# baked into the image: the server's toolbelt engine installs them from
# the /config/tools.json manifest (schema v2) against the image-baked
# catalog. First boot seeds disabled templates (gopls,
# typescript-language-server, pyright, rust-analyzer, gh) — enable one by
# flipping "disabled": false and restarting, or through the loopback tools API.
# This keeps the image
# ~32 MB slimmer and free of the daily LSP-bump rebuild churn.

# kiro-cli installs under $HOME/.local. Home is under /config so the
# install survives container restarts.
ENV HOME=/config/home
# PATH leads with the engine-managed bin dir. The two `runtimes/{go,node}/bin`
# segments are GONE: the audit they were gated on ran on the borgcube volume
# (2026-07) and found they held only go/gofmt and node/npm/npx, every one already
# resolving through tools/bin to the engine's opt/<tool>/<ver>/ trees, so both
# trees were deleted (265 MB) after symlinking the one exception, corepack, into
# tools/bin. Keeping them on PATH after that bought nothing and cost real exposure:
# they sit ahead of /usr/bin, are never created or repaired by this entrypoint, and
# a binary planted while such a tree was group/other-writable stays executable by
# root even after the mode is tightened (chmod stops new writes, it does not
# re-verify existing files). Removing the segments removes that path instead of
# policing it. Restoring a pre-toolbelt backup volume is the one case that
# regresses; the remedy is the same one the audit used, symlink the exception into
# tools/bin.
# tools/go/bin STAYS: it is GOPATH/bin (see ENV GOPATH below), the landing site for
# any `go install` run without the engine's GOBIN, and 18 binaries live there on the
# real volume. Its residual exposure is accepted rather than hardened -- deleting a
# user's own go-installed tools is the productivity harm the dev-box failure posture
# forbids (web-terminal-kiro.md), and anyone able to plant there already holds
# /config/home/.ssh and the auth tokens.
# GOROOT/GOBIN are gone: the engine installs Go under versioned opt/go/<ver>/ trees
# with a bin/go symlink and the toolchain derives GOROOT itself; go-installed tools
# land in the bin dir via the engine's own GOBIN env at install time.
ENV PATH="/config/tools/bin:/config/tools/go/bin:/config/home/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV GOPATH="/config/tools/go"
ENV KWEB_WORK_DIR=/workspace
ENV KWEB_ADDR=:9848

# Repoint root's pw_dir to /config/home so OpenSSH (which resolves "~"
# via getpwuid, NOT $HOME) reads and writes ~/.ssh/known_hosts under
# the persisted volume. Without this, every container recreation wipes
# the host-key cache.
RUN sed -i 's|^root:x:0:0:root:/root:|root:x:0:0:root:/config/home:|' /etc/passwd && \
    grep -q '^root:.*:/config/home:' /etc/passwd

COPY --from=builder /web-terminal-kiro /app/web-terminal-kiro
COPY --from=builder /tmp/tool-catalog.json /app/tool-catalog.json
COPY --chmod=755 entrypoint.sh /opt/web-terminal-kiro/entrypoint.sh

WORKDIR /workspace
EXPOSE 9848

# start-period is the SELECTED startup tolerance for reaching a HEALTHY
# /api/health, which means a completed kiro-cli install; it satisfies the
# smoke-harness sizing rule (tests/image-smoke.conf SMOKE_TIMEOUT 1260 = 1200 +
# two 30s probe intervals). KEPT AT 20m across the move of the installer into the
# server: the work the budget has to cover is the same ~528MB download plus
# install, and only its PLACE changed.
#
# What the ordering changed is the shape of a probe DURING that work, and it moved
# in the operator's favour. The entrypoint no longer installs anything: it hardens
# /config, optionally installs APT_PACKAGES, prunes superseded kiro-cli agent
# runtimes, writes the theme and execs the server, so the listener binds within
# seconds on a boot with no APT_PACKAGES. The install then runs in the background,
# and a probe against it answers 503 with a reason (kiro-cli installing / install
# retrying / unavailable) instead of being refused outright for want of a listener.
# Health still only reports 200 once a version is active, so neither this budget
# nor the smoke timeout got looser.
#
# FOREGROUND allowance-sum before the listener binds, explicit timeouts only:
# APT_PACKAGES (apt-get update 300, +30 kill-after; apt-cache pkgnames 60, +10
# kill-after; apt-get install 600, +30 kill-after) = 1030s with APT_PACKAGES, and
# effectively zero without — every remaining step is untimed local work (directory
# walks, stat/chmod, the agent-runtime prune, a small file write). That is a
# ~4800s reduction against the pre-move sum, and it is why the container is now
# observable during a first-boot download rather than connection-refused.
#
# BACKGROUND allowance-sum for one install attempt, all AFTER the bind: the
# archive fetch (bounded by a 60s no-progress stall guard and a 20s handshake
# deadline rather than a wall-clock cap, so a slow-but-progressing link is not cut
# off), local unzip and streaming SHA-256 (untimed, ~528MB), install.sh (120s),
# one --version probe on the staged binary plus one per selection candidate (10s
# each), and the settings calls (10s each: one required before publication, then
# five against the active binary). The manager then retries a failed attempt up to
# 4 times with 30s/60s/120s backoff, so a persistently failing install keeps the
# server up for the container's lifetime and reports the reason on /api/health.
#
# THE BUDGET IS DELIBERATELY BELOW THE WORST CASE (decided 2026-07, unchanged by
# the move). The two budgets protect different things and only one has teeth:
#   - At RUNTIME `unhealthy` is cosmetic. The restart policy acts on process exit,
#     not health status, so a very slow first boot shows unhealthy, keeps
#     downloading, and converges once a version is active. /api/health is
#     reachable throughout and names the phase, so the state is diagnosable while
#     it lasts. Tool installs converge in the BACKGROUND alongside it (only
#     session creation waits on them) and report through the informational "tools"
#     field.
#   - In CI the download runs on a GitHub-hosted runner over a fast link and takes
#     minutes. A smoke boot that exceeds this start-period means something is
#     genuinely wrong, so tests/image-smoke.sh failing there is CORRECT SIGNAL, not
#     a false negative on a healthy image.
# Raising both budgets to cover the retry envelope was considered and
# rejected: it would make a genuinely hung CI job burn ~3 hours of Actions time
# before failing, which is a real recurring cost against a theoretical worst case
# (CI cost matters on the free plan; validation is meant to stay minutes, not
# hours). Bounding or dropping the retries was also rejected: the stall guard
# already aborts a link that stops making progress, so the retries exist for the
# case worth keeping, a connection DROPPED mid-528MB.
# What this accepts, stated plainly: a download slow enough to outlast the
# start-period fails the smoke job, and an operator on a genuinely slow link sees
# an unhealthy interval on first boot before it converges. Both are the intended
# outcomes, not a gap awaiting a decision.
# Keep this comment and tests/image-smoke.conf's header in lockstep whenever a
# timeout on either side of the exec changes.
# Under `restart: unless-stopped`, health failures are reported
# but do not restart the container (restart policies react to process exit,
# not health status); under a liveness-acting orchestrator, wire /api/health
# to a readinessProbe.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=20m \
    CMD curl -sfS --max-time 4 "http://127.0.0.1:${KWEB_ADDR##*:}/api/health" || exit 1

ENTRYPOINT ["/opt/web-terminal-kiro/entrypoint.sh"]
