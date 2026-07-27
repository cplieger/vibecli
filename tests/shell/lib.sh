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
ENTRYPOINT="${ENTRYPOINT:-$REPO_ROOT/entrypoint.sh}"

_pass=0
_fail=0

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

# extract_function <name> [dest]
#
# Copies one function's source out of $ENTRYPOINT so it can be sourced in
# isolation. The `/^name()/,/^}$/` range relies on entrypoint.sh's formatting
# (shfmt -i 2 -ci -bn puts a function's closing brace in column 0 and nothing
# else), which the repo's own format gate enforces — so a reformat that broke
# this would fail CI on the file itself, not silently here. A miss is fatal
# rather than an empty source: a test that sources nothing would report every
# assertion as passing against a function that never ran.
extract_function() {
  local name=$1 dest=${2:-$WORK/$1.sh}
  sed -n "/^${name}()/,/^}\$/p" "$ENTRYPOINT" >"$dest"
  if [ ! -s "$dest" ]; then
    printf 'harness error: could not extract %s() from %s\n' "$name" "$ENTRYPOINT" >&2
    exit 1
  fi
  printf '%s\n' "$dest"
}

# extract_range <start-regex> <end-regex> [dest]
#
# The block form, for logic that lives inline in the boot path rather than in a
# function (the APT_PACKAGES block). Same fatal-on-miss rule.
extract_range() {
  local start=$1 end=$2 dest=${3:-$WORK/range.sh}
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
# this, and the runner reads the status rather than parsing output.
report() {
  printf '\n%s: %d passed, %d failed\n' "$(basename "$0")" "$_pass" "$_fail"
  [ "$_fail" -eq 0 ]
}
