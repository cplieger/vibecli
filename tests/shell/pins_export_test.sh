#!/usr/bin/env bash
# The shell/Go boundary: entrypoint.sh declares the kiro-cli pins and the Go
# server installs from them, so the two halves agree only by name. Nothing else
# checks that agreement, and every way of breaking it is SILENT:
#
#   - drop an `export` and the server sees no pins, falls back to resolving
#     kiro-cli by bare name, and turns its readiness gate OFF -- a container that
#     reports healthy while installing nothing;
#   - rename a literal and Renovate's custom datasource stops matching, so the
#     pin quietly stops being bumped;
#   - rename an env var on either side and the same fallback applies.
#
# So each assertion reads BOTH sides at run time: the shipped entrypoint and the
# Go file that consumes it.
#
# Lint directives, each against a stated guarantee:
#   SC2015 - the assertion form `[ cond ] && ok "..." || no "..."` cannot mis-fire,
#     because lib.sh's ok/no return 0 unconditionally by design (see their comment).
#   SC2016 - the grep patterns below must stay single-quoted: they match LITERAL
#     text in the shipped files, not an expansion.
# shellcheck disable=SC2015,SC2016
set -u

# shellcheck source-path=SCRIPTDIR
. "$(dirname -- "$0")/lib.sh"
new_workdir >/dev/null

REPO=$(cd -- "$(dirname -- "$0")/../.." && pwd)
MAIN="$REPO/main.go"
# Overridable for the same reason lib.sh makes $ENTRYPOINT overridable: the
# red-check a maintainer runs when adding a case here mutates a /tmp COPY of the
# file and confirms the new assertion actually fails against it. Half of these
# assertions read the Go side or the README, so without these seams that half
# could not be red-checked at all -- and an assertion nobody has seen fail is not
# evidence.
GO_SOURCE_ROOT="${KWEB_GO_SOURCE_ROOT:-$REPO}"
README="${KWEB_README:-$REPO/README.md}"
# A precondition, not decoration: an unreadable main.go makes every cross-file
# assertion below fail for the same reason a genuine drift would, so it has to be
# fatal for the section rather than reported as a drift.
if [ ! -r "$MAIN" ]; then
  printf 'harness error: main.go is not readable at %s\n' "$MAIN" >&2
  exit 1
fi
if [ ! -r "$README" ] || [ ! -d "$GO_SOURCE_ROOT" ]; then
  printf 'harness error: README (%s) or Go source root (%s) is unreadable\n' "$README" "$GO_SOURCE_ROOT" >&2
  exit 1
fi

# --- the Renovate literals still look the way the datasource expects ----------
# cplieger/.github's customDatasources match on these exact comment anchors; the
# version + amd64 sha are rewritten as a pair, and the arm64 sha's
# `# kiro-cli <version>` trailer is its own version anchor.
grep -q '^# renovate: datasource=custom.kiro-cli depName=kiro-cli$' "$ENTRYPOINT" \
  && ok "the amd64 Renovate anchor comment is intact" \
  || no "amd64 Renovate anchor" "the '# renovate: datasource=custom.kiro-cli depName=kiro-cli' line is gone; the version + sha pair will stop being bumped"

grep -q '^# renovate: datasource=custom.kiro-cli-arm64 depName=kiro-cli-arm64$' "$ENTRYPOINT" \
  && ok "the arm64 Renovate anchor comment is intact" \
  || no "arm64 Renovate anchor" "the '# renovate: datasource=custom.kiro-cli-arm64 depName=kiro-cli-arm64' line is gone"

PIN_VERSION=$(sed -n 's/^KIRO_CLI_VERSION="\([^"]*\)"$/\1/p' "$ENTRYPOINT")
[ -n "$PIN_VERSION" ] \
  && ok "KIRO_CLI_VERSION is a bare double-quoted literal ($PIN_VERSION)" \
  || no "KIRO_CLI_VERSION literal" "no 'KIRO_CLI_VERSION=\"...\"' line; the datasource's rewrite target is gone"

grep -qE '^KIRO_CLI_SHA256="[0-9a-f]{64}"$' "$ENTRYPOINT" \
  && ok "KIRO_CLI_SHA256 is a bare 64-hex literal" \
  || no "KIRO_CLI_SHA256 literal" "not a bare 64-hex double-quoted literal"

# The trailer is the arm64 digest's version anchor, so it must name the SAME
# version the pin declares -- a stale trailer sends the datasource looking up the
# wrong release's digest.
grep -qE "^KIRO_CLI_SHA256_ARM64=\"[0-9a-f]{64}\" # kiro-cli ${PIN_VERSION}\$" "$ENTRYPOINT" \
  && ok "KIRO_CLI_SHA256_ARM64 carries a 64-hex literal and a trailer naming the pinned version" \
  || no "KIRO_CLI_SHA256_ARM64 literal" "missing the 64-hex value or the '# kiro-cli $PIN_VERSION' trailer"

# --- every pin the server needs is exported, and read under the same name -----
# Sourcing the file is not an option (it hardens /config and execs the server), so
# the export is read from the text -- but paired with the Go read, so a rename on
# either side fails here.
for var in KIRO_CLI_VERSION KIRO_CLI_SHA256 KIRO_CLI_SHA256_ARM64 KIRO_CLI_TOOLS_DIR KIRO_CLI_TOOLS_TAINTED; do
  if grep -qE "^export ([A-Z0-9_]+ )*${var}( |$)" "$ENTRYPOINT"; then
    ok "$var is exported to the server"
  else
    no "$var export" "entrypoint.sh never exports it, so the server falls back to bare-name kiro-cli with its readiness gate off"
  fi
  if grep -q "\"$var\"" "$MAIN"; then
    ok "$var is read by main.go under that exact name"
  else
    no "$var read" "main.go does not mention \"$var\"; the exported pin reaches nothing"
  fi
done

# --- KIRO_CLI_PATH is GONE, on both surfaces --------------------------------
# It was an operator env var whose whole effect was to stand the install manager
# down: the server ran that binary verbatim and /api/health stopped reporting
# kiro-cli readiness. Deleting the variable deleted that mode, so the manager is
# now the only source of the binary path. Re-adding the read is the way the mode
# comes back, and it comes back SILENTLY (the server still resolves *a* kiro-cli),
# so its absence is asserted on both surfaces an operator or a developer would
# reach for: the Go sources that could read it, and the README table that would
# advertise it.
#
# Dot-directories are excluded because they are not source: .git, .github, and any
# scratch tree a tool left behind (a stale COPY of main.go there would fail this
# assertion while the shipped code is clean).
if grep -rq --include='*.go' --exclude-dir='.*' 'KIRO_CLI_PATH' "$GO_SOURCE_ROOT"; then
  no "KIRO_CLI_PATH in Go sources" "a Go source still mentions KIRO_CLI_PATH; reading it stands the install manager down and takes kiro-cli readiness off /api/health"
else
  ok "no Go source mentions KIRO_CLI_PATH: the install manager is the only source of the binary path"
fi

grep -q 'KIRO_CLI_PATH' "$README" \
  && no "KIRO_CLI_PATH in the README" "the README still documents KIRO_CLI_PATH; an operator setting a variable the server ignores gets no error and no managed install either" \
  || ok "the README config table does not offer KIRO_CLI_PATH"

# --- the tools dir the server writes to is the one this script hardened -------
# The manager creates version directories under $KIRO_CLI_TOOLS_DIR/kiro-cli-versions,
# and the symlink + mode guards only cover it because the same path is walked
# here. Exporting a different path would move the install outside everything this
# script proved about it.
grep -q '^KIRO_CLI_TOOLS_DIR="\$TOOLS"$' "$ENTRYPOINT" \
  && ok "the exported tools dir is \$TOOLS itself" \
  || no "exported tools dir" "KIRO_CLI_TOOLS_DIR is not \$TOOLS, so the server may write outside the hardened tree"

# The install root is a SIBLING of the toolbelt engine's opt/ tree, not a child of
# it. The engine's per-tool prune removes every version directory under
# opt/<tool> that is not the one it just installed, and it accepts any tool name
# from a hand-editable manifest -- so an entry named `kiro-cli` under opt/ would
# delete the active kiro-cli and its retained predecessor. Both dirs are still
# created and hardened; only the kiro-cli root moved out from under opt/.
for dir in '"$TOOLS/opt"' '"$TOOLS/kiro-cli-versions"' \
  '"$TOOLS/npm"' '"$TOOLS/npm/bin"' '"$TOOLS/python"' '"$TOOLS/python/bin"'; do
  grep -qF "make_config_dir $dir" "$ENTRYPOINT" \
    && ok "make_config_dir walks $dir before the server writes into it" \
    || no "make_config_dir $dir" "the install root is not created component-by-component, so a symlink planted there is followed"
  grep -qF "secure_tools_dir $dir" "$ENTRYPOINT" \
    && ok "secure_tools_dir hardens $dir" \
    || no "secure_tools_dir $dir" "the install root's mode is never enforced"
done

# The install root must not be reachable as a child of a toolbelt tree, whatever
# it is named. A nested root is what the collision was.
#
# Name-INDEPENDENT by design: keying the pattern on `kiro-cli` would let a nested
# root under any other name pass green, which is the opposite of what the rule above
# says. The two exceptions are the toolbelt engine's OWN package-manager bin dirs,
# which the hardening sweep now legitimately pre-creates because $TOOLS/bin symlinks
# into them -- they are not a nested install root, so they are subtracted BY NAME
# rather than the rule being widened to admit anything.
grep -oE 'make_config_dir "\$TOOLS/(opt|npm|python|bin)/[^"]*"' "$ENTRYPOINT" \
  | grep -vE '"\$TOOLS/(npm|python)/bin"$' \
  | grep -q . \
  && no "install root under a toolbelt tree" "a directory that is not one of the engine's own bin dirs is created INSIDE one of the toolbelt engine's own trees (opt/npm/python/bin); the engine's per-tool prune and bin republish own everything under those" \
  || ok "no directory other than the engine's own npm/python bin dirs is created inside a toolbelt-engine tree, so the engine's prune cannot reach the kiro-cli install"

# --- the taint flag carries the observation, not a constant ------------------
# The flag is the only thing that stops a forged `.complete` sentinel on a
# once-writable volume from being activated, and hardcoding it to 0 would be
# invisible: every boot would look exactly like a clean one.
grep -q '^KIRO_CLI_TOOLS_TAINTED="\$tools_tree_was_writable"$' "$ENTRYPOINT" \
  && ok "the exported taint flag is secure_tools_dir's own observation" \
  || no "taint flag value" "KIRO_CLI_TOOLS_TAINTED is not \$tools_tree_was_writable, so a foreign-writable tree is reported as clean"

report
