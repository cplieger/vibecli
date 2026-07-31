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

# --- KWEB_CONFIG_DIR is GONE, on all three surfaces --------------------------
# Same class of deletion as KIRO_CLI_PATH above, and asserted the same way. The
# knob claimed to relocate persistent state but reached only toolbelt's three
# metadata files (tools.json, tools-state.json, tool-catalog.cached.json): the
# artifacts they describe followed the entrypoint's exported KIRO_CLI_TOOLS_DIR,
# $HOME is fixed at /config/home by the Dockerfile (and refused outside /config
# here), and the kiro-cli install root sits under the exported tree -- so its only
# reachable effect was splitting ONE subsystem across two volumes: a hand-edited
# manifest and machine state describing a tree that was somewhere else, on no
# session's PATH, while /api/health still reported tools=ok.
#
# Three surfaces, because the knob can come back through any of them and every
# route is silent: a Go source re-reading the env (the split returns), the README
# table re-advertising it (an operator sets a variable nothing reads), or this
# script re-deriving $TOOLS from it (the split returns from the other end).
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

# --- ...and the producer only ever emits 0 or 1 -------------------------------
# The assertion above pins WHERE the exported value comes from; this one pins what
# that value can BE, which is the other half of a contract main.go now depends on.
# parseToolsTainted decodes exactly "1" and "0" and treats every other spelling as
# NO observation (i.e. identically to unset, plus a warning), deliberately refusing
# envx.Bool's wider true/yes/on-any-case-trimmed vocabulary, because a wider reader
# widens what can arm a trust boundary. A narrow reader is only SAFE while the
# writer cannot emit a third spelling: `tools_tree_was_writable=true` here would be
# read as no observation at all, so a foreign-writable tree would be reported clean
# -- silently, and that is the exact failure this flag exists to prevent.
#
# Read as TEXT rather than by running secure_tools_dir, for the reason
# tools_dir_hardening_test.sh parses its call sites: the property is the SET of
# values the script can assign, and no single execution can exhibit a set.
#
# The pattern admits a `local`/`declare`/`export`/`readonly` prefix on purpose --
# an assignment hidden behind one of those would otherwise evade the check and pass
# green, which is the one way this assertion could lie.
taint_writes=$(grep -nE '^[[:space:]]*(local|declare|export|readonly)?[[:space:]]*tools_tree_was_writable=' "$ENTRYPOINT")
if [ -z "$taint_writes" ]; then
  no "taint flag producer" "nothing assigns tools_tree_was_writable, so the exported flag is empty on every boot and main.go's decoder reads an empty value as no observation: a foreign-writable tree would be reported as clean"
else
  foreign_taint_writes=$(printf '%s\n' "$taint_writes" | grep -vE '=[01][[:space:]]*(#.*)?$')
  [ -z "$foreign_taint_writes" ] \
    && ok "every assignment to tools_tree_was_writable is the literal 0 or 1" \
    || no "taint flag vocabulary" "an assignment is not the literal 0 or 1 [$(printf '%s' "$foreign_taint_writes" | tr '\n' ';')]; main.go's parseToolsTainted accepts only those two spellings and reads anything else as NO observation, so such a value reports a foreign-writable tree as clean"

  # Both literals must actually occur, or the vocabulary assertion above passes
  # vacuously: a producer whose 0 was deleted exports an empty flag, and one whose
  # 1 was deleted can never arm the taint at all -- the invisible every-boot-looks-
  # clean failure the "not a constant" assertion above guards from the other end.
  printf '%s\n' "$taint_writes" | grep -qE '=0[[:space:]]*(#.*)?$' \
    && ok "the taint flag is initialised to the literal 0 (the clean default)" \
    || no "taint flag default" "no assignment sets tools_tree_was_writable to 0, so the exported flag has no defined clean value"

  printf '%s\n' "$taint_writes" | grep -qE '=1[[:space:]]*(#.*)?$' \
    && ok "at least one site arms the taint flag with the literal 1" \
    || no "taint flag arming" "no assignment sets tools_tree_was_writable to 1, so no observation can ever arm the quarantine and every boot looks clean"
fi

# One assignment, so the exact-shape assertion above cannot be undone further down
# the file: a later KIRO_CLI_TOOLS_TAINTED=<anything> would win at exec time while
# that grep still matched the earlier line and reported green.
taint_export_writes=$(grep -cE '^[[:space:]]*(local|declare|export|readonly)?[[:space:]]*KIRO_CLI_TOOLS_TAINTED=' "$ENTRYPOINT")
[ "$taint_export_writes" -eq 1 ] \
  && ok "KIRO_CLI_TOOLS_TAINTED is assigned exactly once" \
  || no "taint flag assignment count" "KIRO_CLI_TOOLS_TAINTED is assigned $taint_export_writes times; the last one wins at exec, so the observation this script proved can be overwritten by a value nothing checked"

report
