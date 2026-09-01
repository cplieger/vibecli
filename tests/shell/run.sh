#!/usr/bin/env bash
# Runs every entrypoint.sh unit test in this directory.
#
# This filename is cplieger/ci's shell-ci.yaml trigger: it runs tests/shell/run.sh
# when present and skips otherwise, so committing this file is the opt-in.
#
# This file is repo-owned; lib.sh and harness_test.sh beside it are synced from
# cplieger/ci and must not be hand-edited here.
#
# Covers what tests/image-smoke.sh cannot reach: entrypoint.sh's fail-CLOSED
# branches (a non-private /config, an unowned PATH segment that resists
# hardening, an unreadable package index) that a healthy boot never takes. The
# kiro-cli INSTALL itself is out of scope — the cplieger/pinstall library owns
# it and carries its own Go tests.
#
# Each *_test.sh runs as a separate process so one test's stubs/traps/shell
# options cannot leak into another's; all run even after an early failure.
set -u

cd -- "$(dirname -- "$0")" || exit 1

failed=0
ran=0
for t in ./*_test.sh; do
  # A glob that matches nothing expands to itself; treat that as a harness fault
  # rather than a green run, since an empty suite passing silently is how a
  # test directory quietly stops testing anything.
  if [ ! -f "$t" ]; then
    printf 'harness error: no *_test.sh found in %s\n' "$PWD" >&2
    exit 1
  fi
  printf '=== %s\n' "$(basename "$t")"
  ran=$((ran + 1))
  bash "$t" || failed=$((failed + 1))
  printf '\n'
done

if [ "$failed" -ne 0 ]; then
  printf 'FAILED: %d of %d entrypoint test files failed\n' "$failed" "$ran" >&2
  exit 1
fi
printf 'all %d entrypoint test files passed\n' "$ran"
