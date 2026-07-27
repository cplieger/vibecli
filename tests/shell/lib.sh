#!/usr/bin/env bash
# Shared harness for the entrypoint.sh unit tests.
#
# WHY THESE TESTS EXIST, and why they are not the image smoke test: entrypoint.sh
# is ~1200 lines and it IS the product's boot path. Its most consequential
# branches are the ones that fail CLOSED — an unremovable stale binary, a
# non-private /config, a failed kiro-cli download, a package index that cannot be
# read — and a smoke test can never reach them, because a healthy image never
# takes them. tests/image-smoke.sh builds an image and asserts it boots; these
# assert what happens when it should NOT.
#
# HOW: each test extracts one function verbatim from the shipped entrypoint.sh
# and runs it against temp directories, with the few external commands it touches
# stubbed. Nothing is reimplemented here — an assertion that passed against a
# paraphrase would prove nothing about what ships. The functions under test are
# already parameterised (they take the directory or mode as an argument), which is
# what makes this possible without a container or a writable /config.
#
# Sourced by every tests/shell/*_test.sh via the runner; not executable itself.

# The repo root, derived from this file's own location so a test behaves the same
# whether the runner, CI, or a developer in another directory invokes it.
TESTS_SHELL_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$TESTS_SHELL_DIR/../.." && pwd)
# Overridable so a test can be pointed at an older revision of the file (the
# red-check a maintainer runs when adding a case: extract the previous
# entrypoint.sh to /tmp and confirm the new assertion actually fails against it).
#
# Deliberately NOT readonly, and reassignable mid-file: a repo whose shipped shell
# spans several files (an entrypoint plus sourced helpers) points ENTRYPOINT at each
# one in turn before extracting from it. Every extract validates the current value,
# so a stale or mistyped path names itself instead of surfacing as an empty
# extraction.
ENTRYPOINT="${ENTRYPOINT:-$REPO_ROOT/entrypoint.sh}"

_pass=0
_fail=0
_skip=0

# ok/no are the whole assertion vocabulary: a test states what it verified in the
# same words the failure would use, so a CI log reads as a list of guarantees.
# Both RETURN 0 unconditionally, and that is load-bearing rather than tidy: the
# tests read `[ cond ] && ok "..." || no "..."`, which shellcheck flags (SC2015)
# because in general the `||` branch also runs when the middle command fails.
# Pinning the status here makes that impossible, so each test file disables SC2015
# against this guarantee instead of against an assumption.
ok() {
  _pass=$((_pass + 1))
  printf 'ok   %s\n' "$1"
  return 0
}

no() {
  _fail=$((_fail + 1))
  printf 'FAIL %s -- %s\n' "$1" "$2"
  return 0
}

# skip <what> <why>
#
# For an assertion whose PREMISE does not hold in this environment rather than one
# that failed. The case exists here because some guards are unreachable for some
# callers: root reads a chmod-000 file, so a `[ -r "$f" ]` refusal cannot be
# provoked as root, and asserting it anyway fails for a maintainer running as root
# while passing on the non-root CI runner -- a per-user false failure, which is
# worse than an honest gap. Counted separately and never as a pass, so a suite that
# quietly skips everything cannot read as green. Returns 0 for the same reason
# ok/no do (see their comment above).
skip() {
  _skip=$((_skip + 1))
  printf 'skip %s -- %s\n' "$1" "$2"
  return 0
}

# Every extract reads $ENTRYPOINT, which a test may have just reassigned; a
# mistyped or stale path must name itself here rather than reaching sed and
# surfacing as an indistinguishable empty extraction.
_require_entrypoint() {
  [ -f "$ENTRYPOINT" ] && [ -r "$ENTRYPOINT" ] && return 0
  printf 'harness error: ENTRYPOINT is not a readable file: %s\n' "$ENTRYPOINT" >&2
  exit 1
}

# extract_function <name> [dest]
#
# Copies one function's source out of $ENTRYPOINT so it can be sourced in
# isolation, and prints the path it wrote.
#
# The body's end is found by scanning for a line that is exactly `}` or `)` in
# column 0, which shfmt -i 2 -ci -bn guarantees and the repo's own format gate
# enforces -- so a reformat that broke this would fail CI on the shipped file, not
# silently here. Both closers matter: a SUBSHELL-bodied function (`fn() (`, which
# entrypoint.sh uses for install_kiro_cli so its cd and traps cannot leak) closes
# with `)`, and a `}`-only scan runs straight past it into whatever follows. That
# over-capture is silent, because the result still parses and still defines the
# function asked for -- it just also redefines the next one or two, which is how a
# test starts asserting against something it never named.
#
# A one-line definition (`fn() { cmd; }`) is closed by its own opening line, so it
# is emitted alone rather than swept forward to the next function's closing brace.
#
# A miss is fatal rather than an empty source: a test that sources nothing would
# report every assertion as passing against a function that never ran. Reach that
# fatal through load_function, or by checking the status -- see its comment.
extract_function() {
  local name=$1 dest=${2:-$WORK/$1.sh}
  _require_entrypoint
  awk -v fn="$name" '
    !inside && index($0, fn "()") == 1 {
      print
      # The opening line closes the body itself only for a one-liner; `fn() {` and
      # `fn() (` end with the OPENER, so they must not match here.
      if ($0 ~ /[)}][[:space:]]*$/) exit
      inside = 1
      next
    }
    inside {
      print
      if ($0 ~ /^[)}][[:space:]]*$/) exit
    }
  ' "$ENTRYPOINT" >"$dest"
  if [ ! -s "$dest" ]; then
    printf 'harness error: could not extract %s() from %s\n' "$name" "$ENTRYPOINT" >&2
    exit 1
  fi
  printf '%s\n' "$dest"
}

# load_function <name> [dest]
#
# extract_function plus the source, and the ONLY safe way to spell that pair.
#
# `. "$(extract_function x)"` reads naturally and is broken: the fatal `exit 1`
# runs inside the command substitution, so it kills that subshell and nothing
# else. The substitution yields the empty string, `.` fails on it, and with no
# `set -e` the test file CARRIES ON with the function undefined -- every assertion
# that expects a guard NOT to fire then passes, because nothing ran at all.
# Measured on this suite: 5 of 10 assertions reported ok against a function that
# did not exist. Here the status of the assignment is the subshell's, so the
# refusal reaches the test process.
load_function() {
  local src
  src=$(extract_function "$@") || exit 1
  # The path is generated above, so there is nothing on disk for shellcheck to
  # follow at lint time.
  # shellcheck disable=SC1090
  . "$src"
}

# extract_range <start-regex> <end-regex> [dest]
#
# The block form, for logic that lives inline in the boot path rather than in a
# function (the APT_PACKAGES block). Same fatal-on-miss rule, and the same
# reachability caveat: capture it as `x=$(extract_range ...) || exit 1`, never as a
# bare `. "$(extract_range ...)"`.
extract_range() {
  local start=$1 end=$2 dest=${3:-$WORK/range.sh}
  _require_entrypoint
  sed -n "/$start/,/$end/p" "$ENTRYPOINT" >"$dest"
  if [ ! -s "$dest" ]; then
    printf 'harness error: could not extract range %s..%s from %s\n' \
      "$start" "$end" "$ENTRYPOINT" >&2
    exit 1
  fi
  printf '%s\n' "$dest"
}

# A private scratch directory per test process, removed on exit including on a
# failed assertion, so a run leaves nothing behind in /tmp.
new_workdir() {
  WORK=$(mktemp -d)
  # Deliberate early expansion: the trap must capture THIS directory, not whatever
  # $WORK holds when the shell exits.
  # shellcheck disable=SC2064
  trap "rm -rf '$WORK'" EXIT
  printf '%s\n' "$WORK"
}

# Prints the tally and sets the process exit status. Every test file ends with
# this, and the runner reads the status rather than parsing output. Skips are
# reported separately and never fold into the pass count: a suite whose premises
# all went unmet must not read as a suite that verified them.
report() {
  if [ "$_skip" -ne 0 ]; then
    printf '\n%s: %d passed, %d failed, %d skipped\n' "$(basename "$0")" "$_pass" "$_fail" "$_skip"
  else
    printf '\n%s: %d passed, %d failed\n' "$(basename "$0")" "$_pass" "$_fail"
  fi
  [ "$_fail" -eq 0 ]
}
