#!/usr/bin/env bash
# The shell/Go boundary: entrypoint.sh declares the kiro-cli pins and the Go
# server installs from them, so the two halves agree only by name, and every
# way of breaking that agreement is SILENT (a dropped export turns off
# readiness with no error; a renamed literal stops Renovate matching; a renamed
# env var on either side falls back the same way). So each assertion reads BOTH
# sides at run time: the shipped entrypoint and the Go file that consumes it.
#
# Lint directives, each against a stated guarantee:
#   SC2015 - `[ cond ] && ok || no` cannot mis-fire: lib.sh's ok/no return 0
#     unconditionally by design.
#   SC2016 - the grep patterns match LITERAL text in the shipped files, not an
#     expansion, so they must stay single-quoted.
# shellcheck disable=SC2015,SC2016
set -u

# shellcheck source-path=SCRIPTDIR
. "$(dirname -- "$0")/lib.sh"
new_workdir >/dev/null

REPO=$(cd -- "$(dirname -- "$0")/../.." && pwd)
MAIN="$REPO/main.go"
# Overridable so a red-check can mutate a /tmp copy and confirm an assertion
# actually fails against it.
GO_SOURCE_ROOT="${WT_GO_SOURCE_ROOT:-$REPO}"
README="${WT_README:-$REPO/README.md}"
if [ ! -r "$MAIN" ]; then
  printf 'harness error: main.go is not readable at %s\n' "$MAIN" >&2
  exit 1
fi
if [ ! -r "$README" ] || [ ! -d "$GO_SOURCE_ROOT" ]; then
  printf 'harness error: README (%s) or Go source root (%s) is unreadable\n' "$README" "$GO_SOURCE_ROOT" >&2
  exit 1
fi

# --- the Renovate literals still look the way the datasource expects ----------
# cplieger/.github's customDatasources match on these exact comment anchors.
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

# The trailer is the arm64 digest's version anchor and must name the SAME
# version the pin declares, or the datasource looks up the wrong release.
grep -qE "^KIRO_CLI_SHA256_ARM64=\"[0-9a-f]{64}\" # kiro-cli ${PIN_VERSION}\$" "$ENTRYPOINT" \
  && ok "KIRO_CLI_SHA256_ARM64 carries a 64-hex literal and a trailer naming the pinned version" \
  || no "KIRO_CLI_SHA256_ARM64 literal" "missing the 64-hex value or the '# kiro-cli $PIN_VERSION' trailer"

# --- every pin the server needs is exported, and read under the same name -----
# Sourcing the file is not an option (it hardens /config and execs the server),
# so the export is read from the text -- paired with the Go read, so a rename on
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
# It was an operator env var that stood the install manager down and dropped
# kiro-cli readiness from /api/health; re-adding a READ brings that mode back
# silently, so its absence is asserted on both surfaces a developer or operator
# would touch: the Go sources, and the README table.
if grep -rq --include='*.go' --exclude-dir='.*' 'KIRO_CLI_PATH' "$GO_SOURCE_ROOT"; then
  no "KIRO_CLI_PATH in Go sources" "a Go source still mentions KIRO_CLI_PATH; reading it stands the install manager down and takes kiro-cli readiness off /api/health"
else
  ok "no Go source mentions KIRO_CLI_PATH: the install manager is the only source of the binary path"
fi

grep -q 'KIRO_CLI_PATH' "$README" \
  && no "KIRO_CLI_PATH in the README" "the README still documents KIRO_CLI_PATH; an operator setting a variable the server ignores gets no error and no managed install either" \
  || ok "the README config table does not offer KIRO_CLI_PATH"

# --- KWEB_CONFIG_DIR is GONE, on all three surfaces --------------------------
# Same class of deletion as KIRO_CLI_PATH, asserted the same way: the knob's
# only reachable effect was splitting the tool subsystem's manifest from the
# tree it describes, and any of the three surfaces below can silently bring
# that split back.
if grep -rq --include='*.go' --exclude-dir='.*' 'KWEB_CONFIG_DIR' "$GO_SOURCE_ROOT"; then
  no "KWEB_CONFIG_DIR in Go sources" "a Go source still mentions KWEB_CONFIG_DIR; reading it re-splits the tool subsystem, putting the manifest and state in a different tree from the artifacts they describe"
else
  ok "no Go source mentions KWEB_CONFIG_DIR: the tool subsystem has one root"
fi

grep -q 'KWEB_CONFIG_DIR' "$README" \
  && no "KWEB_CONFIG_DIR in the README" "the README still documents KWEB_CONFIG_DIR; an operator setting a variable the server ignores gets no error and no relocated state either" \
  || ok "the README config table does not offer KWEB_CONFIG_DIR"

grep -q 'KWEB_CONFIG_DIR' "$ENTRYPOINT" \
  && no "KWEB_CONFIG_DIR in entrypoint.sh" "entrypoint.sh still mentions KWEB_CONFIG_DIR; deriving \$TOOLS from it would move the hardened tree out from under the export the server reads" \
  || ok "entrypoint.sh derives nothing from KWEB_CONFIG_DIR"

# --- the tools dir the server writes to is the one this script hardened -------
grep -q '^KIRO_CLI_TOOLS_DIR="\$TOOLS"$' "$ENTRYPOINT" \
  && ok "the exported tools dir is \$TOOLS itself" \
  || no "exported tools dir" "KIRO_CLI_TOOLS_DIR is not \$TOOLS, so the server may write outside the hardened tree"

# The install root is a SIBLING of the toolbelt engine's opt/ tree, not a
# child: the engine accepts any tool name from a hand-editable manifest and its
# per-tool prune would delete a `kiro-cli` entry under opt/ along with its
# retained predecessor.
for dir in '"$TOOLS/opt"' '"$TOOLS/kiro-cli-versions"' \
  '"$TOOLS/npm"' '"$TOOLS/npm/bin"' '"$TOOLS/python"' '"$TOOLS/python/bin"'; do
  grep -qF "make_config_dir $dir" "$ENTRYPOINT" \
    && ok "make_config_dir walks $dir before the server writes into it" \
    || no "make_config_dir $dir" "the install root is not created component-by-component, so a symlink planted there is followed"
  grep -qF "secure_tools_dir $dir" "$ENTRYPOINT" \
    && ok "secure_tools_dir hardens $dir" \
    || no "secure_tools_dir $dir" "the install root's mode is never enforced"
done

# The install root must not be reachable as a child of a toolbelt tree, under
# any name -- keying the check on `kiro-cli` would miss a nested root under any
# other name. The toolbelt engine's own npm/python bin dirs are subtracted BY
# NAME since the hardening sweep now legitimately pre-creates them.
grep -oE 'make_config_dir "\$TOOLS/(opt|npm|python|bin)/[^"]*"' "$ENTRYPOINT" \
  | grep -vE '"\$TOOLS/(npm|python)/bin"$' \
  | grep -q . \
  && no "install root under a toolbelt tree" "a directory that is not one of the engine's own bin dirs is created INSIDE one of the toolbelt engine's own trees (opt/npm/python/bin); the engine's per-tool prune and bin republish own everything under those" \
  || ok "no directory other than the engine's own npm/python bin dirs is created inside a toolbelt-engine tree, so the engine's prune cannot reach the kiro-cli install"

# --- the taint flag carries the observation, not a constant ------------------
# It is the only thing stopping a forged .complete sentinel on a once-writable
# volume from being activated; hardcoding it to 0 would be invisible.
grep -q '^KIRO_CLI_TOOLS_TAINTED="\$tools_tree_was_writable"$' "$ENTRYPOINT" \
  && ok "the exported taint flag is secure_tools_dir's own observation" \
  || no "taint flag value" "KIRO_CLI_TOOLS_TAINTED is not \$tools_tree_was_writable, so a foreign-writable tree is reported as clean"

# --- ...and the producer only ever emits 0 or 1 -------------------------------
# main.go's parseToolsTainted decodes exactly "1" and "0" and treats any other
# spelling as NO observation (identically to unset, plus a warning), so this
# pins the SET of values the script can assign -- a third spelling here would
# report a foreign-writable tree as clean, silently. Read as text rather than
# by running secure_tools_dir, since a set cannot be exhibited by one execution.
# The pattern admits a local/declare/export/readonly prefix so an assignment
# hidden behind one cannot evade the check.
taint_writes=$(grep -nE '^[[:space:]]*(local|declare|export|readonly)?[[:space:]]*tools_tree_was_writable=' "$ENTRYPOINT")
if [ -z "$taint_writes" ]; then
  no "taint flag producer" "nothing assigns tools_tree_was_writable, so the exported flag is empty on every boot and main.go's decoder reads an empty value as no observation: a foreign-writable tree would be reported as clean"
else
  foreign_taint_writes=$(printf '%s\n' "$taint_writes" | grep -vE '=[01][[:space:]]*(#.*)?$')
  [ -z "$foreign_taint_writes" ] \
    && ok "every assignment to tools_tree_was_writable is the literal 0 or 1" \
    || no "taint flag vocabulary" "an assignment is not the literal 0 or 1 [$(printf '%s' "$foreign_taint_writes" | tr '\n' ';')]; main.go's parseToolsTainted accepts only those two spellings and reads anything else as NO observation, so such a value reports a foreign-writable tree as clean"

  # Both literals must actually occur, or the vocabulary check above passes
  # vacuously (a deleted 0 exports empty; a deleted 1 can never arm the taint).
  printf '%s\n' "$taint_writes" | grep -qE '=0[[:space:]]*(#.*)?$' \
    && ok "the taint flag is initialised to the literal 0 (the clean default)" \
    || no "taint flag default" "no assignment sets tools_tree_was_writable to 0, so the exported flag has no defined clean value"

  printf '%s\n' "$taint_writes" | grep -qE '=1[[:space:]]*(#.*)?$' \
    && ok "at least one site arms the taint flag with the literal 1" \
    || no "taint flag arming" "no assignment sets tools_tree_was_writable to 1, so no observation can ever arm the quarantine and every boot looks clean"
fi

# One assignment, so a later KIRO_CLI_TOOLS_TAINTED=<anything> cannot win at
# exec time while the exact-shape check above still matched the earlier line.
taint_export_writes=$(grep -cE '^[[:space:]]*(local|declare|export|readonly)?[[:space:]]*KIRO_CLI_TOOLS_TAINTED=' "$ENTRYPOINT")
[ "$taint_export_writes" -eq 1 ] \
  && ok "KIRO_CLI_TOOLS_TAINTED is assigned exactly once" \
  || no "taint flag assignment count" "KIRO_CLI_TOOLS_TAINTED is assigned $taint_export_writes times; the last one wins at exec, so the observation this script proved can be overwritten by a value nothing checked"

report
