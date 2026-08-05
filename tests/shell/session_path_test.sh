#!/usr/bin/env bash
# The session PATH boundary: entrypoint.sh narrows its OWN PATH so its directory
# checks cannot be answered by a planted binary on the /config bind mount, then
# hands the image's PATH back to the server it execs. Between those two points it
# RE-EXECS itself through setpriv to drop CAP_SYS_ADMIN, and PATH is an exported
# variable, so the narrowed value crosses that exec.
#
# That combination broke the restore in production (borgcube, 2026-08): the second
# invocation captured the NARROWED list as the value to restore, so the server and
# every PTY session under it ran without /config/tools/bin, /config/tools/go/bin or
# /config/home/.local/bin. Nothing failed loudly. Every binary the toolbelt engine
# installs became unreachable by bare name -- for the operator's terminal and for
# any agent running in one -- and the engine could not even find its own npm and uv
# to finish installing two of its entries, which surfaced only as
# /api/health reporting tools "degraded".
#
# A smoke test cannot see this: the container boots, serves, and reports ok. So the
# assertions below drive the shipped PATH statements through a simulated re-exec and
# check the value the server would actually get, then pin the two orderings that
# make the narrowing meaningful in the first place.
#
# Lint directives, each against a stated guarantee:
#   SC2015 - the assertion form `[ cond ] && ok "..." || no "..."` cannot mis-fire,
#     because lib.sh's ok/no return 0 unconditionally by design (see their comment).
#   SC2016 - the grep patterns below must stay single-quoted: they match LITERAL
#     text in the shipped file, not an expansion.
# shellcheck disable=SC2015,SC2016
set -u

# shellcheck source-path=SCRIPTDIR
. "$(dirname -- "$0")/lib.sh"
new_workdir >/dev/null

# The PATH an image-built container really starts with (Dockerfile ENV PATH). The
# three /config-resident dirs are the whole point: they are what the restore must
# preserve and what the regression dropped.
IMAGE_PATH="/config/tools/bin:/config/tools/go/bin:/config/home/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --- the shipped statements, located by ROLE and extracted rather than retyped --
# Every anchor below is structural: the capture is the first top-level
# SESSION_PATH= assignment, and the narrowing is the first top-level PATH=
# assignment at or after it. Anchoring the narrowing on its CONTENT instead (its
# leading /usr/local/sbin) is a trap this test fell into once: a mutant that
# rewrote the list to start with /config/tools/bin then matched no anchor, the
# extraction came back empty, and the assertion that the narrowing excludes
# /config passed against a narrowing that did not. A structural anchor cannot go
# blind that way -- if the statement is there, it is found, whatever it says.
capture_line=$(grep -n '^SESSION_PATH=' "$ENTRYPOINT" | head -1 | cut -d: -f1)
restore_line=$(grep -n '^PATH="\$SESSION_PATH"$' "$ENTRYPOINT" | head -1 | cut -d: -f1)
narrow_line=$(awk -v start="${capture_line:-0}" 'start > 0 && NR >= start && /^PATH=/ { print NR; exit }' "$ENTRYPOINT")
# The real re-exec line, located the same comment-immune way containment_test.sh
# locates it (a prose mention of the statement is not the statement).
containment_line=$(grep -nE '^[^#]*exec setpriv' "$ENTRYPOINT" | head -1 | cut -d: -f1)

if [ -z "$capture_line" ] || [ -z "$narrow_line" ] || [ -z "$restore_line" ]; then
  printf 'harness error: could not locate the PATH capture, narrowing or restore statement in %s\n' "$ENTRYPOINT" >&2
  exit 1
fi
# If the first PATH= after the capture IS the restore, the prologue and the restore
# have been reordered into each other and every extraction below is meaningless --
# a harness fault rather than a drift, so say which.
if [ "$narrow_line" -eq "$restore_line" ]; then
  printf 'harness error: the first PATH= after the capture is the restore itself (line %s); the narrowing statement is missing\n' "$restore_line" >&2
  exit 1
fi

# The prologue is the contiguous block from the capture through the narrowing, so
# ANY shape of it is carried into the stand-in below. That matters for the
# red-check: reverting the fix to a bare SESSION_PATH="$PATH" does not make the
# extraction fail, it makes the stand-in reproduce the bug, which is the assertion
# firing rather than the harness erroring.
PROLOGUE="$WORK/prologue.sh"
sed -n "${capture_line},${narrow_line}p" "$ENTRYPOINT" >"$PROLOGUE"

RESTORE="$WORK/restore.sh"
sed -n "${restore_line}p" "$ENTRYPOINT" >"$RESTORE"

if [ ! -s "$PROLOGUE" ] || [ ! -s "$RESTORE" ]; then
  printf 'harness error: extracted an empty prologue or restore from %s\n' "$ENTRYPOINT" >&2
  exit 1
fi

# --- behaviour: what PATH would the server be exec'd with? --------------------
# These need the prologue to be what it claims: a short, contiguous run of
# statements. A reordering mutation (the narrowing moved below the containment
# block) makes the extracted span swallow that entire block, and a stand-in built
# from it produces garbage -- several failures whose messages name a PATH loss
# rather than the reordering that caused it. The ordering assertions further down
# diagnose that case precisely, so when the span is implausible these are SKIPPED
# instead. lib.sh's skip exists for exactly this: a premise that does not hold, as
# distinct from an assertion that failed.
PROLOGUE_MAX_SPAN=6

check_behaviour() {
  # The stand-in is the shipped prologue, a re-exec of the SAME shape the containment
  # block uses (exported marker, then `exec "$0"`), and the shipped restore. Nothing
  # here is a copy of the logic under test; the two extracted files are.
  STANDIN="$WORK/standin.sh"
  {
    printf '#!/bin/bash\nset -u\n'
    cat "$PROLOGUE"
    printf 'if [ "${SIM_REEXEC:-}" != "1" ]; then\n'
    printf '  export SIM_REEXEC=1\n'
    printf '  exec "$0" "$@"\n'
    printf 'fi\n'
    cat "$RESTORE"
    printf 'printf "%%s\\n" "$PATH"\n'
  } >"$STANDIN"
  chmod +x "$STANDIN"

  # The re-exec path. This is the one every container actually takes: root holds
  # CAP_SETPCAP, so the setpriv pre-flight succeeds and the script always re-execs.
  reexec_path=$(env -i PATH="$IMAGE_PATH" HOME=/config/home bash "$STANDIN" 2>/dev/null)
  case ":$reexec_path:" in
    *:/config/tools/bin:*)
      ok "the server's PATH keeps /config/tools/bin across the setpriv re-exec"
      ;;
    *)
      no "session PATH survives the re-exec" \
        "the server would start with PATH=$reexec_path -- the engine-managed tool dir is gone, so nothing toolbelt installs resolves by bare name in any session"
      ;;
  esac

  case ":$reexec_path:" in
    *:/config/tools/go/bin:*)
      ok "the server's PATH keeps GOPATH/bin across the setpriv re-exec"
      ;;
    *)
      no "GOPATH/bin survives the re-exec" "PATH=$reexec_path"
      ;;
  esac

  case ":$reexec_path:" in
    *:/config/home/.local/bin:*)
      ok "the server's PATH keeps /config/home/.local/bin across the setpriv re-exec"
      ;;
    *)
      no ".local/bin survives the re-exec" "PATH=$reexec_path"
      ;;
  esac

  # The no-re-exec path, which a container reaches when the setpriv pre-flight fails
  # (a capability-reduced or non-root run). It worked before the fix and must keep
  # working after it -- a fix that only repairs the re-exec case would trade one
  # silent PATH loss for another.
  direct_path=$(env -i PATH="$IMAGE_PATH" HOME=/config/home SIM_REEXEC=1 bash "$STANDIN" 2>/dev/null)
  [ "$direct_path" = "$IMAGE_PATH" ] \
    && ok "without a re-exec the image PATH is restored byte for byte" \
    || no "single-invocation restore" "expected the image PATH, got PATH=$direct_path"

  # Idempotence: the capture must survive more than one re-exec. Nothing chains two
  # today, but the failure it guards against is precisely a value that degrades once
  # per exec, which is invisible until something adds the second one.
  twice_path=$(env -i PATH="$IMAGE_PATH" HOME=/config/home bash -c '
  script=$1
  # First hop leaves the marker set, so run the stand-in through one extra exec of
  # itself before letting it restore.
  KWEB_SESSION_PATH=${KWEB_SESSION_PATH:-$PATH} exec bash "$script"' _ "$STANDIN" 2>/dev/null)
  case ":$twice_path:" in
    *:/config/tools/bin:*)
      ok "the carried PATH is idempotent across repeated re-execs"
      ;;
    *)
      no "carry is idempotent" "a second hop degraded it to PATH=$twice_path"
      ;;
  esac
}

if [ $((narrow_line - capture_line)) -le "$PROLOGUE_MAX_SPAN" ]; then
  check_behaviour
else
  skip "the PATH the server would be exec'd with" \
    "the capture (line $capture_line) and the narrowing (line $narrow_line) are $((narrow_line - capture_line)) lines apart, so the extracted block is not the statement run this test models; the ordering assertions below name the real defect"
fi

# --- the real transport: setpriv must not sanitize the carry -------------------
# Everything above models the re-exec with a plain `exec "$0"`. That is the shape,
# not the mechanism: the boot path goes through setpriv, and setpriv can clear the
# whole environment (--reset-env). A carry variable is exactly the thing such a
# flag would drop, so a test that only ever simulates the hop would stay green
# while the server lost its PATH again. Run the REAL invocation, read out of the
# shipped file rather than retyped, so adding --reset-env to it fails here.
setpriv_invocation=""
if [ -n "$containment_line" ]; then
  setpriv_invocation=$(sed -n "${containment_line}p" "$ENTRYPOINT" \
    | sed -e 's/^[[:space:]]*exec //' -e 's/[[:space:]]*-- "\$0" "\$@"[[:space:]]*$//')
fi
if [ -z "$setpriv_invocation" ]; then
  skip "the real setpriv invocation preserves the carry" \
    "could not read the re-exec line out of $ENTRYPOINT"
elif ! eval "$setpriv_invocation -- true" 2>/dev/null; then
  # Dropping from the bounding set needs CAP_SETPCAP, which a non-root or
  # capability-reduced runner lacks -- the same pre-flight the entrypoint itself
  # performs before committing to the exec. A premise that does not hold here,
  # not a failure.
  skip "the real setpriv invocation preserves the carry" \
    "this environment cannot run '$setpriv_invocation' (needs CAP_SETPCAP)"
else
  carried=$(eval "KWEB_SESSION_PATH='$IMAGE_PATH' $setpriv_invocation -- sh -c 'printf %s \"\$KWEB_SESSION_PATH\"'" 2>/dev/null)
  [ "$carried" = "$IMAGE_PATH" ] \
    && ok "the real setpriv invocation passes the carry variable through untouched" \
    || no "setpriv preserves the carry" \
      "the shipped invocation sanitized it (got '${carried:-<empty>}'); the restore would narrow the server's PATH again"
fi

# --- the carry variable is internal, not a knob -------------------------------
# It is exported only so the re-exec'd invocation can read it, and dropped before
# the server is exec'd. Left in place it would show up in the environment of every
# terminal session as a second copy of PATH that looks configurable.
grep -q '^export KWEB_SESSION_PATH="\$SESSION_PATH"$' "$ENTRYPOINT" \
  && ok "the carry variable is exported so the re-exec'd invocation can read it" \
  || no "carry is exported" "without the export the re-exec'd invocation cannot see it and the restore silently narrows again"

grep -q '^unset KWEB_SESSION_PATH$' "$ENTRYPOINT" \
  && ok "the carry variable is dropped before the server is exec'd" \
  || no "carry is dropped" "KWEB_SESSION_PATH would leak into the server and every PTY session as a second copy of PATH"

# --- the narrowing is real ----------------------------------------------------
# A narrowed list that still contained a /config component would defeat the whole
# reason the prologue exists, and every directory check below it would again be
# answerable by a planted binary on the bind mount.
narrow=$(sed -n "${narrow_line}p" "$ENTRYPOINT")
case "$narrow" in
  *"/config"*)
    no "the narrowed PATH excludes /config" "the entrypoint's own commands could resolve through the bind mount: $narrow"
    ;;
  *)
    ok "the entrypoint narrows its own PATH to image directories only"
    ;;
esac

# --- ordering: the two rearrangements that look like simplifications ----------
# Narrowing must precede the containment block, because that block runs `mount`,
# `setpriv` and `awk` by bare name. Moving the save/narrow pair below it -- an
# obvious-looking way to dodge the re-exec entirely -- would resolve all three
# through /config/tools/bin. ($containment_line is located once, in the extraction
# block above, on an anchor that survives both a comment mention and a new flag;
# do not recompute it here.)
last_harden_line=$(grep -n '^secure_tools_dir\|^  secure_tools_dir' "$ENTRYPOINT" | tail -1 | cut -d: -f1)

if [ -n "$containment_line" ] && [ "$narrow_line" -lt "$containment_line" ]; then
  ok "PATH is narrowed before the containment block resolves mount/setpriv/awk"
else
  no "narrow precedes containment" "narrow=$narrow_line containment=$containment_line -- the re-exec's own tools would resolve through /config/tools/bin"
fi

# The restore must be the LAST thing before the exec, after every hardening call,
# or the checks that prove /config is private would themselves run with the bind
# mount back on PATH.
if [ -n "$last_harden_line" ] && [ "$restore_line" -gt "$last_harden_line" ]; then
  ok "PATH is restored only after the /config hardening pass has finished"
else
  no "restore follows hardening" "restore=$restore_line last secure_tools_dir=$last_harden_line"
fi

report
