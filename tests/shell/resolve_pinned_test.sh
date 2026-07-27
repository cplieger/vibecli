#!/usr/bin/env bash
# resolves_to_pinned_kiro_cli(): does anything other than the pinned binary win
# bare-name `kiro-cli` resolution, and does asking that question cost a --version
# probe?
#
# The distinction the two modes draw is not cosmetic. identity mode is what the
# every-boot advisory site uses, and it must stay SILENT on the routine boot after
# a Renovate bump, where $BIN legitimately still holds the old version: a full
# check there warned twice about a suspected "unremovable stale binary" on the
# ordinary upgrade path, for a state the drift check corrects seconds later. full
# mode is what the post-install sites use, where the sweep has already run and a
# surviving unpinned $BIN really is dangerous.
# Lint directives for this whole file, each against a stated guarantee rather than
# an assumption:
#   SC2015 - the assertion form `[ cond ] && ok "..." || no "..."` cannot mis-fire,
#     because lib.sh's ok/no return 0 unconditionally by design (see their comment).
#   SC2034 - the variables set below are the INPUTS to entrypoint.sh code that is
#     extracted and sourced at RUNTIME, so shellcheck cannot see the reads.
# shellcheck disable=SC2015,SC2034
set -u

# shellcheck source-path=SCRIPTDIR
. "$(dirname -- "$0")/lib.sh"
new_workdir >/dev/null

load_function resolves_to_pinned_kiro_cli

KIRO_CLI_VERSION="2.14.1"
PROBES=0
# Stub: counts probes so "identity mode costs no --version call" is observable, and
# returns whatever the scenario planted.
kiro_cli_version() {
  PROBES=$((PROBES + 1))
  printf '%s\n' "$STUB_VERSION"
}

setup() {
  ROOT=$(mktemp -d "$WORK/t.XXXXXX")
  TOOLS="$ROOT/tools"
  HOME_DIR="$ROOT/home"
  mkdir -p "$TOOLS/bin" "$HOME_DIR/.local/bin"
  BIN="$TOOLS/bin/kiro-cli"
  SESSION_PATH="$TOOLS/bin:$HOME_DIR/.local/bin:/usr/bin"
  PROBES=0
  STUB_VERSION="$KIRO_CLI_VERSION"
}
# run <mode> -> RC, WARNS (count of level=warn lines on stderr)
run() {
  local out
  out=$(resolves_to_pinned_kiro_cli ${1:+"$1"} 2>&1 >/dev/null)
  RC=$?
  WARNS=$(printf '%s' "$out" | grep -c 'level=warn' || true)
}

# --- THE REGRESSION: a Renovate-bump boot, $BIN present at the OLD version --------
setup
: >"$BIN" && chmod +x "$BIN"
STUB_VERSION="2.13.0"
run identity
if [ "$RC" -eq 0 ] && [ "$WARNS" -eq 0 ]; then
  ok "bump boot, identity mode: silent and rc0 (no warn on the routine upgrade path)"
else
  no "bump boot identity" "rc=$RC warns=$WARNS -- the routine upgrade path warns again"
fi
[ "$PROBES" -eq 0 ] && ok "identity mode costs no --version probe" \
  || no "identity probe" "probed $PROBES times; the boot allowance sum assumes zero here"

# ...while FULL mode still reports it, which is what the post-install sites rely on.
setup
: >"$BIN" && chmod +x "$BIN"
STUB_VERSION="2.13.0"
run
[ "$RC" -eq 2 ] && [ "$WARNS" -eq 1 ] \
  && ok "same state, full mode: rc2 + one warn (post-install sites keep their signal)" \
  || no "full mode drift" "rc=$RC warns=$WARNS, want rc2 + 1 warn"

# --- the shadowing case must still fire in BOTH modes -----------------------------
for mode in identity full; do
  setup
  : >"$HOME_DIR/.local/bin/kiro-cli" && chmod +x "$HOME_DIR/.local/bin/kiro-cli"
  SESSION_PATH="$HOME_DIR/.local/bin:$TOOLS/bin:/usr/bin"
  run "$([ "$mode" = identity ] && printf identity)"
  [ "$RC" -eq 1 ] && [ "$WARNS" -eq 1 ] \
    && ok "unpinned binary at another path: rc1 + warn in $mode mode" \
    || no "shadowing in $mode mode" "rc=$RC warns=$WARNS, want rc1 + 1 warn"
done

# --- benign states stay quiet in both modes ---------------------------------------
for mode in identity full; do
  setup
  : >"$BIN" && chmod +x "$BIN" # at the pin
  run "$([ "$mode" = identity ] && printf identity)"
  [ "$RC" -eq 0 ] && [ "$WARNS" -eq 0 ] && ok "at the pin: rc0, silent in $mode mode" \
    || no "at-pin $mode" "rc=$RC warns=$WARNS"

  setup # nothing reachable at all
  run "$([ "$mode" = identity ] && printf identity)"
  [ "$RC" -eq 0 ] && [ "$WARNS" -eq 0 ] && ok "nothing reachable: rc0, silent in $mode mode" \
    || no "absent $mode" "rc=$RC warns=$WARNS"
done

report
