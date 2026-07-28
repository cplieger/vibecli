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
# A precondition, not decoration: an unreadable main.go makes every cross-file
# assertion below fail for the same reason a genuine drift would, so it has to be
# fatal for the section rather than reported as a drift.
if [ ! -r "$MAIN" ]; then
  printf 'harness error: main.go is not readable at %s\n' "$MAIN" >&2
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

# --- the tools dir the server writes to is the one this script hardened -------
# The manager creates version directories under $KIRO_CLI_TOOLS_DIR/opt/kiro-cli,
# and the symlink + mode guards only cover it because the same path is walked
# here. Exporting a different path would move the install outside everything this
# script proved about it.
grep -q '^KIRO_CLI_TOOLS_DIR="\$TOOLS"$' "$ENTRYPOINT" \
  && ok "the exported tools dir is \$TOOLS itself" \
  || no "exported tools dir" "KIRO_CLI_TOOLS_DIR is not \$TOOLS, so the server may write outside the hardened tree"

for dir in '"$TOOLS/opt"' '"$TOOLS/opt/kiro-cli"'; do
  grep -qF "make_config_dir $dir" "$ENTRYPOINT" \
    && ok "make_config_dir walks $dir before the server writes into it" \
    || no "make_config_dir $dir" "the install root is not created component-by-component, so a symlink planted there is followed"
  grep -qF "secure_tools_dir $dir" "$ENTRYPOINT" \
    && ok "secure_tools_dir hardens $dir" \
    || no "secure_tools_dir $dir" "the install root's mode is never enforced"
done

# --- the taint flag carries the observation, not a constant ------------------
# The flag is the only thing that stops a forged `.complete` sentinel on a
# once-writable volume from being activated, and hardcoding it to 0 would be
# invisible: every boot would look exactly like a clean one.
grep -q '^KIRO_CLI_TOOLS_TAINTED="\$tools_tree_was_writable"$' "$ENTRYPOINT" \
  && ok "the exported taint flag is secure_tools_dir's own observation" \
  || no "taint flag value" "KIRO_CLI_TOOLS_TAINTED is not \$tools_tree_was_writable, so a foreign-writable tree is reported as clean"

report
