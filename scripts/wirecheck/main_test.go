package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

// gatePackage is the gate's package path as the Dockerfile spells it, in the
// `go build` step and nowhere else (see TestDockerfileBuildsTheGateInsteadOfGoRun).
const gatePackage = "./scripts/wirecheck"

// subprocessEnv re-enters the test binary AS the gate, so the process-level exit
// codes can be observed without shelling out to `go build`. See
// TestGateProcessPropagatesExitCodes.
const subprocessEnv = "WIRECHECK_RUN_AS_GATE"

func TestMain(m *testing.M) {
	if os.Getenv(subprocessEnv) == "1" {
		main() // flag.Parse reads the -client-* flags the parent passed
		return
	}
	os.Exit(m.Run())
}

// dockerfileUnderTest returns the Dockerfile text the parity tests scan.
// WIRECHECK_DOCKERFILE overrides the path so these assertions can be red-checked
// against a MUTATED /tmp copy -- the repo's established red-check discipline
// (tests/shell's `ENTRYPOINT=/tmp/mut.sh`), and the only safe one here: editing
// the real Dockerfile in place races a live code-review pipeline that may be
// writing to it.
func dockerfileUnderTest(t *testing.T) string {
	t.Helper()
	path := os.Getenv("WIRECHECK_DOCKERFILE")
	if path == "" {
		path = filepath.Join("..", "..", "Dockerfile")
	}
	b, err := os.ReadFile(path) // #nosec G304 -- test-only red-check seam
	if err != nil {
		t.Fatalf("read Dockerfile %s: %v", path, err)
	}
	return string(b)
}

// TestDockerfileInvokesTheGate pins the gate's only execution site. run()'s verdict
// is worthless if nothing runs it: a stage restructure that drops OR COMMENTS OUT
// the RUN leaves this package compiling and every test green while an incompatible
// Go/TS pair ships and refuses every session at first connect (close 4002) behind a
// green /api/health.
func TestDockerfileInvokesTheGate(t *testing.T) {
	// One LIVE line must build the gate and then invoke the BUILT binary with
	// both flags. A whole-file substring sweep would pass on a commented-out RUN
	// (`#    /tmp/…/wirecheck …`) — the other half of the silent case this test
	// exists for, and the likelier one during a stage restructure, since it is
	// the reversible edit a person makes while debugging a build — and the prose
	// block above the RUN already mentions scripts/wirecheck. Requiring the whole
	// build-then-invoke shape on ONE uncommented logical line also proves both
	// flags are still attached to the gate invocation rather than surviving
	// somewhere else in the file.
	if !slices.ContainsFunc(dockerfileLogicalLines(dockerfileUnderTest(t)), lineInvokesTheGate) {
		t.Error("Dockerfile has no un-commented `go build -o <path> ./scripts/wirecheck " +
			"&& <path> -manifest ...` (or `-client-rev ... -client-min-server ...`) line; the " +
			"wire-floor gate is not invoked (deleted OR commented out), so an incompatible " +
			"Go/TS pair would build clean and refuse every session with close 4002 at runtime")
	}
}

// TestDockerfileBuildsTheGateInsteadOfGoRun pins the exit-status half of the
// gate's contract at its only execution site. `go run` reports its OWN status 1
// for ANY non-zero program exit (it writes "exit status 2" to stderr but does not
// propagate the 2), so under `go run` the gate's two failure modes -- exit 2 "the
// Dockerfile's extraction is broken, fix the gate, do NOT bump a pin" and exit 1
// "genuine wire incompatibility, move a pin" -- collapse into one code and only
// the stderr text tells them apart. Reverting the step to `go run` is a one-word
// edit that keeps every other assertion in this file green (the pair is still
// gated, the build still fails on an incompatible pair), which is exactly why the
// regression needs its own assertion rather than riding on the recognizer.
func TestDockerfileBuildsTheGateInsteadOfGoRun(t *testing.T) {
	lines := dockerfileLogicalLines(dockerfileUnderTest(t))
	if i := slices.IndexFunc(lines, lineRunsTheGateUnbuilt); i >= 0 {
		t.Errorf("Dockerfile runs the wire-floor gate via `go run %s`: %q\n"+
			"`go run` collapses the gate's exit 2 (gate broken, fix the extraction) and exit 1 "+
			"(genuine wire incompatibility, move a pin) into its own status 1, so the "+
			"machine-readable distinction is lost. Build the gate and invoke the binary instead.",
			gatePackage, lines[i])
	}
}

// shellSegment strips a logical line's leading `RUN` and the instruction FLAGS
// that belong to it (`--mount=…`, `--network=…`, `--security=…`), so the shell
// command that follows can still be anchored at the START of its `&&` segment.
// The gate is the FIRST command in its RUN — nothing precedes it to create an
// `&&` boundary — so without this the three cache/tmpfs mounts and the `go build`
// share one segment and a field-exact match on the raw segment cannot see the
// build at all. Only `--`-prefixed words immediately following `RUN` are dropped,
// so no shell word is ever skipped and inert data (`echo go build …`) keeps its
// echo at the anchor position.
func shellSegment(seg string) string {
	trimmed := strings.TrimSpace(seg)
	fields := strings.Fields(trimmed)
	if len(fields) == 0 || fields[0] != "RUN" {
		return trimmed
	}
	fields = fields[1:]
	for len(fields) > 0 && strings.HasPrefix(fields[0], "--") {
		fields = fields[1:]
	}
	return strings.Join(fields, " ")
}

// lineRunsTheGateUnbuilt reports whether one LOGICAL Dockerfile line executes the
// gate through `go run` rather than as a built binary. Anchored at an `&&` segment
// start (past any RUN instruction flags, see shellSegment) for the same reason as
// lineInvokesTheGate: the prose above the RUN mentions the package, and an
// `echo go run …` is not an execution.
func lineRunsTheGateUnbuilt(line string) bool {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "#") {
		return false
	}
	for seg := range strings.SplitSeq(trimmed, "&&") {
		if strings.HasPrefix(shellSegment(seg), "go run "+gatePackage) {
			return true
		}
	}
	return false
}

// gateBuildOutput finds the `go build -o <path> ./scripts/wirecheck` segment of a
// split logical line and returns the output path plus that segment's index (index
// -1 and an empty path when the line does not build the gate). The shape is
// matched on FIELDS anchored at the segment start (past any RUN instruction
// flags, see shellSegment), not as a substring, so inert shell data
// (`echo go build -o … ./scripts/wirecheck`) is not mistaken for a
// build. Exactly the five-field form is accepted: extra flags on the step would
// fail this test loudly and get the assertion consciously updated, which is the
// right direction of error for a gate whose false pass ships an incompatible pair.
func gateBuildOutput(segments []string) (string, int) {
	for i, seg := range segments {
		fields := strings.Fields(shellSegment(seg))
		if len(fields) != 5 {
			continue
		}
		if fields[0] != "go" || fields[1] != "build" || fields[2] != "-o" || fields[4] != gatePackage {
			continue
		}
		return fields[3], i
	}
	return "", -1
}

// gateFlagsPresent reports whether an invocation segment carries a client-side
// declaration for the gate to check. Either shape counts: `-manifest <path>`
// (the engine artifact's own wire-compatibility.json, which the gate parses
// itself) or the explicit `-client-rev`/`-client-min-server` pair. Both halves
// of the pair are required together, because either one alone leaves the gate
// with an unusable pairing and exits 2 — a step that never reports a floor
// violation. An invocation carrying NEITHER is not a gate: the program would
// exit 2 on every build for the same reason.
//
// Every flag is matched as an exact FIELD with a value after it, not as a
// substring. A bare trailing `-manifest`, or an unrelated `-manifest-backup path`,
// each contain the text while leaving the gate with no parsable declaration, so it
// exits 2 and checks no floor — the same never-reports-a-violation state the
// half-pair cases above are rejected for. A substring test called both of those a
// valid declaration, which is a weaker oracle than this test's own error message
// claims. The SAME rule applies to the pair, for the reason the manifest arm needs
// it: `-client-rev-backup a` contains the text and declares nothing.
func gateFlagsPresent(seg string) bool {
	fields := strings.Fields(seg)
	hasValued := func(flag string) bool {
		for i, field := range fields {
			if field == flag && i+1 < len(fields) {
				return true
			}
		}
		return false
	}
	if hasValued("-manifest") {
		return true
	}
	return hasValued("-client-rev") && hasValued("-client-min-server")
}

// lineInvokesTheGate reports whether one LOGICAL Dockerfile line (see
// dockerfileLogicalLines) BUILDS the wire-floor gate and then RUNS the built
// binary with a client-side declaration attached (see gateFlagsPresent). Both
// halves are required and in that order:
// the built path is read out of the `go build -o` segment rather than hardcoded
// here, so moving the binary (a tmpfs mount elsewhere) does not fail the test,
// while dropping either half does. The executable is anchored at the start of an
// `&&` SEGMENT rather than merely contained in the line: a substring test counts
// inert shell data as an invocation, so `echo /tmp/…/wirecheck …` (the reversible
// edit a person makes while debugging a build) would print the command, exit 0,
// and leave this file's parity test green while the gate no longer runs. Segment
// anchoring is what lets the live chain shape (`RUN … && go build … && /tmp/… `)
// match without weakening that: a shell construct WRAPPING the command still
// fails the parity test until the assertion is consciously updated -- the
// intended trade, since the alternative silently ships an incompatible Go/TS
// pair. A logical line carrying `||` is rejected for the same reason in the other
// direction: it still runs the gate but discards the verdict, so the build
// survives an incompatible pair. That refusal is judged over the WHOLE logical
// line, so a `||` on any segment of the chain is refused too -- a false failure
// is loud and gets fixed, a false pass ships an incompatible pair in silence.
func lineInvokesTheGate(line string) bool {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "#") {
		return false // a commented-out invocation is not an invocation
	}
	if strings.Contains(trimmed, "||") {
		// A swallowed verdict is not a gate: `<gate> ... || true` runs the
		// check and then exits 0 on an incompatible pair.
		return false
	}
	segments := strings.Split(trimmed, "&&")
	bin, built := gateBuildOutput(segments)
	if bin == "" {
		return false // nothing built the gate on this line
	}
	for i := built + 1; i < len(segments); i++ {
		seg := strings.TrimSpace(segments[i])
		if !strings.HasPrefix(seg, bin+" ") || !gateFlagsPresent(seg) {
			continue
		}
		// `;` discards the verdict the same way `||` does (`<gate> ... ; true`
		// exits 0 on an incompatible pair, and the RUN is a `&&` chain so a
		// trailing `;` command supplies the whole step's exit status), but it is
		// refused from the BUILD segment onward rather than over the whole
		// logical line: a `;` in an EARLIER segment cannot touch the gate's exit
		// status, and an earlier segment may legitimately carry one (a quoted
		// shell script preparing the step). Starting at the build segment is
		// strictly the stronger window: a discarded `go build` status would leave
		// the next segment invoking a stale or absent binary. A `|` discards the verdict
		// too (a pipeline's status is the LAST command's), and a `&` backgrounds
		// the gate so the step never waits for it -- both are refused on the same
		// build-onward terms. Backgrounding is judged as the presence of the `&`
		// CONTROL OPERATOR, not as a trailing character: `<gate> … & wait`
		// discards the verdict just as thoroughly (in POSIX `sh`, `false & wait`
		// exits 0), so a shape test on the last character would accept it.
		// Splitting on `&&` has already removed the legitimate chain separators
		// from that text, and neither the build nor the gate arguments contain an
		// ampersand, so any `&` left anywhere in those segments is a background
		// operator. The check is therefore over the build-onward segments joined
		// WITHOUT the `&&` separator, which refuses an `&` in ANY position of ANY
		// later segment: `&` applies to the whole AND-list, so both
		// `<gate> … && true &` and `<gate> … && true & echo done` background the
		// gate without putting an ampersand in its own segment.
		rest := segments[built:]
		if strings.ContainsAny(strings.Join(rest, "&&"), ";|") ||
			strings.Contains(strings.Join(rest, ""), "&") {
			return false
		}
		return true
	}
	return false
}

// dockerfileLogicalLines folds each backslash-continued line into the single
// LOGICAL line a shell executes. Scanning PHYSICAL lines is what let the
// recognizer's `||` refusal be bypassed, and this Dockerfile is the shape that
// makes it reachable: the gate is the last link of a seven-line `RUN … \` chain,
// so appending `|| true` on one further continuation line leaves the gate's own
// physical line untouched, matches it, and swallows the verdict with this file's
// only parity test still green.
func dockerfileLogicalLines(dockerfile string) []string {
	var (
		logical []string
		b       strings.Builder
	)
	for line := range strings.SplitSeq(dockerfile, "\n") {
		trimmed := strings.TrimSpace(line)
		if head, continued := strings.CutSuffix(trimmed, `\`); continued {
			b.WriteString(strings.TrimSpace(head))
			b.WriteByte(' ')
			continue
		}
		b.WriteString(trimmed)
		logical = append(logical, b.String())
		b.Reset()
	}
	if b.Len() > 0 {
		logical = append(logical, b.String())
	}
	return logical
}

// TestLineInvokesTheGate_rejectsInertForms pins the recognizer itself, which is
// what makes TestDockerfileInvokesTheGate's verdict mean "the gate runs" rather
// than "the gate's name appears somewhere". Each negative is a shape that leaves
// the text intact while the build stops executing it.
func TestLineInvokesTheGate_rejectsInertForms(t *testing.T) {
	const (
		flags    = `-client-rev "$CLIENT_REV" -client-min-server "$CLIENT_MIN_SERVER"`
		manifest = `-manifest static-src/node_modules/@cplieger/web-terminal-engine/wire-compatibility.json`
		bin      = "/tmp/wirecheck-bin/wirecheck"
		build    = "go build -o " + bin + " " + gatePackage
	)
	live := "    " + build + " && " + bin + " " + manifest
	cases := map[string]struct {
		line string
		want bool
	}{
		"the live Dockerfile form": {live, true},
		// The explicit client-side pair stays a legitimate invocation (dev-build
		// and any consumer without a manifest use it), so the recognizer must
		// accept it too — dropping it would fail a build that still gates.
		"the explicit client-flag pair":                  {"    " + build + " && " + bin + " " + flags, true},
		"echoed, so never executed":                      {"    " + build + " && echo " + bin + " " + manifest, false},
		"quoted into a no-op builtin":                    {"    " + build + " && : '" + bin + " " + manifest + "'", false},
		"commented out":                                  {"#    " + build + " && " + bin + " " + manifest, false},
		"missing the client-rev flag":                    {"    " + build + ` && ` + bin + ` -client-min-server "$CLIENT_MIN_SERVER"`, false},
		"missing the min-server flag":                    {"    " + build + ` && ` + bin + ` -client-rev "$CLIENT_REV"`, false},
		"invoked with no client-side declaration at all": {"    " + build + " && " + bin, false},
		// A bare `-manifest` with no path, and an unrelated flag that merely
		// CONTAINS the text: both leave the gate with nothing to parse, so it exits
		// 2 and checks no floor. A substring test accepted both as a declaration.
		"a bare -manifest with no path":   {"    " + build + " && " + bin + " -manifest", false},
		"an unrelated -manifest-ish flag": {"    " + build + ` && ` + bin + " -manifest-backup /tmp/x.json", false},
		// The same two shapes on the explicit pair: both flags present as bare
		// trailing words, and two unrelated flags that merely CONTAIN the names.
		"the pair with no values":       {"    " + build + " && " + bin + " -client-rev -client-min-server", false},
		"an unrelated -client-rev flag": {"    " + build + ` && ` + bin + ` -client-rev-backup a -client-min-server-backup b`, false},
		"prose mentioning the gate":     {"# public Go API inside scripts/wirecheck (no source scraping)", false},
		// The gate must be BUILT and then RUN. `go run` still gates the pair but
		// reports its own status 1 for the gate's exit 2, so the "fix the gate, do
		// not bump a pin" signal is lost; TestDockerfileBuildsTheGateInsteadOfGoRun
		// is the assertion that names that regression, and the recognizer must not
		// accept it either.
		"go run instead of build-then-invoke": {"    go run " + gatePackage + " " + flags, false},
		// Built but never invoked: `go build` alone exits 0 for any wire pairing.
		"built but not invoked": {"    " + build, false},
		// Invoked but never built: the path is stale at best, absent at worst, so
		// the step's verdict is not this repo's gate.
		"invoked but not built":        {"    " + bin + " " + flags, false},
		"a different package is built": {"    go build -o " + bin + " ./scripts/other && " + bin + " " + flags, false},
		// The binary that runs must be the one just built; a stale path in the
		// invocation would gate against whatever happens to sit there.
		"a different binary is invoked": {"    " + build + " && /usr/local/bin/wirecheck " + flags, false},
		"verdict swallowed by || true":  {live + " || true", false},
		"verdict discarded by ; true":   {live + " ; true", false},
		// A pipeline's exit status is the LAST command's, and a backgrounded gate
		// is never waited for: both leave the invocation textually intact while
		// the build stops acting on its verdict.
		"verdict piped away": {live + " | tee /dev/null", false},
		"gate backgrounded":  {live + " &", false},
		// `& wait` is the shape a trailing-character test accepts: the gate is
		// backgrounded and the step then waits, but `wait` reports 0 here, so an
		// incompatible pair builds clean with this file's parity test still green.
		"gate backgrounded then masked by wait": {live + " & wait", false},
		// `&` applies to the whole AND-list, so a `&` ending a LATER segment
		// backgrounds the gate as well, without appearing in the gate's segment.
		"a chain backgrounded by a trailing & on a later segment": {live + " && true &", false},
		// ...and an `&` INTERIOR to a later segment backgrounds the AND-list just
		// the same: `A && B & C` parses as `(A && B) & C`, so the gate's verdict is
		// never waited for even though the ampersand is neither in the gate's
		// segment nor at the end of the line.
		"a chain backgrounded by an interior & on a later segment": {live + " && true & echo done", false},
		// The build's own status must not be discarded either: a failed build
		// followed by an invocation of an absent path is a different failure than
		// the one this step exists to report.
		"the build's status discarded by a trailing ;": {
			"    " + build + " ; " + bin + " " + flags, false,
		},
		"the live chained form": {
			`RUN --mount=type=cache,target=/root/go/pkg/mod WIRE_TS=x && CLIENT_REV=$(sed -n 's|^export const X = \([0-9]\{1,\}\);.*|\1|p' "$WIRE_TS") && ` + build + " && " + bin + " " + flags, true,
		},
		"a chain whose verdict is swallowed": {
			`RUN --mount=type=cache,target=/root/go/pkg/mod WIRE_TS=x && ` + build + " && " + bin + " " + flags + ` || true`, false,
		},
		"a chain whose verdict is discarded by a trailing ;": {
			`RUN WIRE_TS=x && ` + build + " && " + bin + " " + flags + ` ; true`, false,
		},
		// The live shape: the gate is the FIRST command in its RUN, so the build
		// shares a segment with the RUN's cache/tmpfs mounts and is only visible
		// once those instruction flags are stripped (shellSegment).
		"the live RUN-with-mounts shape": {
			`RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build --mount=type=tmpfs,target=/tmp/wirecheck-bin ` +
				build + " && " + bin + " " + manifest, true,
		},
		// ...and stripping them must not make an echoed build look live: the
		// anchor moves past the RUN flags only, never past a shell word.
		"a RUN-with-mounts shape whose build is echoed": {
			`RUN --mount=type=tmpfs,target=/tmp/wirecheck-bin echo ` + build + " && " + bin + " " + manifest, false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := lineInvokesTheGate(tc.line); got != tc.want {
				t.Errorf("lineInvokesTheGate(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}

// TestLineRunsTheGateUnbuilt pins the `go run` detector, so
// TestDockerfileBuildsTheGateInsteadOfGoRun means "the step executes the gate
// through go run" rather than "the words appear somewhere".
func TestLineRunsTheGateUnbuilt(t *testing.T) {
	const flags = `-client-rev "$CLIENT_REV" -client-min-server "$CLIENT_MIN_SERVER"`
	cases := map[string]struct {
		line string
		want bool
	}{
		"go run with flags":            {"    go run " + gatePackage + " " + flags, true},
		"go run at the end of a chain": {"RUN WIRE_TS=x && go run " + gatePackage + " " + flags, true},
		// Reverting the live step is now a one-word edit INSIDE the RUN's own
		// segment (the gate is its first command), so the detector has to see past
		// the instruction flags or the regression it exists to name goes unreported.
		"go run as the RUN's first command, behind its mounts": {
			"RUN --mount=type=cache,target=/root/.cache/go-build go run " + gatePackage +
				" -manifest static-src/node_modules/@cplieger/web-terminal-engine/wire-compatibility.json", true,
		},
		"the live build-then-invoke form": {
			"    go build -o /tmp/wirecheck-bin/wirecheck " + gatePackage +
				" && /tmp/wirecheck-bin/wirecheck " + flags, false,
		},
		"commented out":                     {"#    go run " + gatePackage + " " + flags, false},
		"prose mentioning it":               {"# never `go run ./scripts/wirecheck`: the exit code collapses", false},
		"go run of an unrelated package":    {`    go run "github.com/cplieger/toolbelt/v2/cmd/toolcatalog@v2.2.8" verify`, false},
		"echoed rather than executed":       {"    echo go run " + gatePackage, false},
		"go build of the gate is not a run": {"    go build -o /tmp/x " + gatePackage, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := lineRunsTheGateUnbuilt(tc.line); got != tc.want {
				t.Errorf("lineRunsTheGateUnbuilt(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}

// TestRun_delegatesToTheEngineRule pins that the gate's verdict IS the
// engine's verdict, in both directions and at the exclusive boundary. The
// local reason-string comparator this replaced could drift from the engine's
// rule silently (nothing asserted they agreed); after delegation the only
// thing worth pinning here is that run() routes the engine's answer without
// inverting or swallowing it. The engine owns the rule's own table plus a
// runtime-floor agreement test.
func TestRun_delegatesToTheEngineRule(t *testing.T) {
	cases := map[string]struct {
		clientRev, clientMinServer int
		wantCompatible             bool
	}{
		"current pairing":                    {terminal.WireProtocolVersion, terminal.MinSupportedClientWireVersion, true},
		"client exactly at the server floor": {terminal.MinSupportedClientWireVersion, terminal.MinSupportedClientWireVersion, true},
		"client below the server floor":      {terminal.MinSupportedClientWireVersion - 1, terminal.MinSupportedClientWireVersion, false},
		"client demands a newer server":      {terminal.WireProtocolVersion, terminal.WireProtocolVersion + 1, false},
		"client demands exactly this server": {terminal.WireProtocolVersion, terminal.WireProtocolVersion, true},
		"future client revision is accepted": {terminal.WireProtocolVersion + 3, terminal.MinSupportedClientWireVersion, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.clientRev, tc.clientMinServer, &stdout, &stderr)
			engineSaysCompatible := terminal.WirePairIncompatibility(
				terminal.WireProtocolVersion, terminal.MinSupportedClientWireVersion,
				tc.clientRev, tc.clientMinServer,
			) == ""
			if engineSaysCompatible != tc.wantCompatible {
				t.Fatalf("engine verdict for (%d,%d) = compatible:%v, test expected %v; the engine's rule changed and this table is stale",
					tc.clientRev, tc.clientMinServer, engineSaysCompatible, tc.wantCompatible)
			}
			if gateCompatible := code == 0; gateCompatible != engineSaysCompatible {
				t.Errorf("run(%d,%d) exit %d (compatible:%v) but the engine says compatible:%v; the gate does not follow the engine's rule",
					tc.clientRev, tc.clientMinServer, code, gateCompatible, engineSaysCompatible)
			}
			// An incompatible pairing must be refused as a FLOOR violation (exit
			// 1), never as the usage error (exit 2). The below-the-floor row
			// derives its client revision as MinSupportedClientWireVersion-1,
			// which reaches 0 if the engine ever lowers that floor to 1 -- the row
			// would then exercise run's flag guard instead of the engine's rule
			// and still pass, silently retiring the only negative-direction case.
			if !tc.wantCompatible && code != 1 {
				t.Errorf("run(%d,%d) = %d, want exit 1; an incompatible pairing must fail on the engine's floor rule, not on the usage guard (this case no longer tests the rule)",
					tc.clientRev, tc.clientMinServer, code)
			}
		})
	}
}

// TestRun_failureNamesBothPins keeps the remediation useful: the engine's
// reason says WHICH half is behind, and this repo must add which pin to move
// (build-layout knowledge the engine deliberately does not carry).
func TestRun_failureNamesBothPins(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(terminal.WireProtocolVersion, terminal.WireProtocolVersion+1, &stdout, &stderr); code != 1 {
		t.Fatalf("run() = %d, want exit 1 for a violated floor", code)
	}
	out := stderr.String()
	for _, want := range []string{"go.mod", "Dockerfile ARG", "static-src/package.json"} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr = %q, want it to name the %q pin", out, want)
		}
	}
}

// TestRun_exitCodeContract pins the exit codes and output streams that are this
// program's own contract (0 compatible, 1 floor violated, 2 usage error). Since
// the Dockerfile builds the gate and invokes the BINARY (see
// TestDockerfileBuildsTheGateInsteadOfGoRun), these codes are what the build step
// actually observes, not merely a direct-invocation nicety: 2 means the step's
// own extraction is broken and no pin should move, 1 means the pair is genuinely
// incompatible. TestRun_delegatesToTheEngineRule alone cannot pin them: it checks
// only the compatible-vs-not verdict, so a wiring regression in main/run (an
// inverted reason check, a swapped exit code, output on the wrong stream) would
// pass it and silently neuter or misreport the image build gate.
// Client-side values are derived from the engine's exported constants, never
// hardcoded, so the cases track a future floor raise automatically.
func TestRun_exitCodeContract(t *testing.T) {
	cases := []struct {
		name            string
		clientRev       int
		clientMinServer int
		wantCode        int
		wantStdout      string // "" = stdout must stay empty
		wantStderr      string // "" = stderr must stay empty
	}{
		{
			name:            "compatible pairing exits 0 and reports ok on stdout",
			clientRev:       terminal.WireProtocolVersion,
			clientMinServer: terminal.WireProtocolVersion,
			wantCode:        0,
			wantStdout:      "wirecheck ok:",
		},
		{
			name:            "violated floor exits 1 with the mismatch on stderr",
			clientRev:       terminal.WireProtocolVersion,
			clientMinServer: terminal.WireProtocolVersion + 1, // client demands a newer server than go.mod pins
			wantCode:        1,
			wantStderr:      "ERROR wire-floor-mismatch:",
		},
		{
			name:            "zero client-rev is a usage error (exit 2)",
			clientRev:       0,
			clientMinServer: terminal.WireProtocolVersion,
			wantCode:        2,
			wantStderr:      "required positive integers",
		},
		{
			name:            "negative client-min-server is a usage error (exit 2)",
			clientRev:       terminal.WireProtocolVersion,
			clientMinServer: -1,
			wantCode:        2,
			wantStderr:      "required positive integers",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run(tc.clientRev, tc.clientMinServer, &stdout, &stderr)
			if got != tc.wantCode {
				t.Errorf("run(%d, %d) = %d, want exit code %d (the build gate fails on any non-zero; the distinct codes are this program's own contract)",
					tc.clientRev, tc.clientMinServer, got, tc.wantCode)
			}
			if tc.wantStdout == "" {
				if stdout.Len() != 0 {
					t.Errorf("stdout = %q, want empty on a non-zero exit", stdout.String())
				}
			} else if !strings.Contains(stdout.String(), tc.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tc.wantStdout)
			}
			if tc.wantStderr == "" {
				if stderr.Len() != 0 {
					t.Errorf("stderr = %q, want empty on success", stderr.String())
				}
			} else if !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantStderr)
			}
		})
	}
}

// TestGateProcessPropagatesExitCodes pins the last link that makes the
// Dockerfile's build-then-invoke shape worth anything: the PROCESS must exit with
// run()'s code. run() returning 2 is invisible to the build step if main()
// collapses it (an `os.Exit(0)`, a `!= 0 -> 1` normalisation, a swallowed error),
// which is the same loss the `go run` invocation caused and is not observable in
// any in-process test. The gate is re-entered as a subprocess of this test binary
// (TestMain honours WIRECHECK_RUN_AS_GATE) rather than shelling out to `go build`,
// so the assertion costs a fork instead of a compile.
func TestGateProcessPropagatesExitCodes(t *testing.T) {
	cases := map[string]struct {
		clientRev, clientMinServer int
		wantCode                   int
	}{
		"compatible pairing":       {terminal.WireProtocolVersion, terminal.WireProtocolVersion, 0},
		"genuine wire mismatch":    {terminal.WireProtocolVersion, terminal.WireProtocolVersion + 1, 1},
		"unusable extracted input": {0, 0, 2},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// #nosec G204 -- os.Args[0] is this test binary; no external input.
			cmd := exec.Command(os.Args[0],
				fmt.Sprintf("-client-rev=%d", tc.clientRev),
				fmt.Sprintf("-client-min-server=%d", tc.clientMinServer))
			cmd.Env = append(os.Environ(), subprocessEnv+"=1")
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if err != nil && !errors.As(err, &exitErr) {
				t.Fatalf("run gate subprocess: %v (output %q)", err, out)
			}
			if got := cmd.ProcessState.ExitCode(); got != tc.wantCode {
				t.Errorf("gate process exit = %d, want %d (output %q); the Dockerfile's wire-floor "+
					"gate reads this code -- 2 must stay distinguishable from 1, or a broken "+
					"extraction reads as a genuine incompatibility and someone bumps a pin",
					got, tc.wantCode, out)
			}
		})
	}
}

// TestDockerfileLogicalLines_foldsAContinuedChain pins the joiner the parity scan
// depends on. The gate is the last link of a multi-line `RUN … \` chain, so a
// `|| true` appended on one FURTHER continuation line must be seen as part of the
// same logical command; scanning physical lines reported exactly that fragment as
// a live invocation, because the gate's own line carried no `||`.
func TestDockerfileLogicalLines_foldsAContinuedChain(t *testing.T) {
	const flags = `-client-rev "$CLIENT_REV" -client-min-server "$CLIENT_MIN_SERVER"`
	live := "RUN --mount=type=cache,target=/root/go/pkg/mod \\\n" +
		"    CLIENT_REV=$(sed -n 's|a|b|p' \"$WIRE_TS\") && \\\n" +
		"    go build -o /tmp/wirecheck-bin/wirecheck " + gatePackage + " && \\\n" +
		"    /tmp/wirecheck-bin/wirecheck " + flags + "\n"
	swallowed := strings.TrimSuffix(live, "\n") + " \\\n    || true\n"

	invoked := func(dockerfile string) bool {
		return slices.ContainsFunc(dockerfileLogicalLines(dockerfile), lineInvokesTheGate)
	}
	if !invoked(live) {
		t.Errorf("the live continued-chain shape is not recognized as an invocation; logical lines = %q", dockerfileLogicalLines(live))
	}
	if invoked(swallowed) {
		t.Errorf("a verdict swallowed by a continuation-line `|| true` was recognized as a live gate; logical lines = %q", dockerfileLogicalLines(swallowed))
	}
}

// TestReadManifest is the payoff of moving the client-side parse out of the
// Dockerfile: every failure shape below was previously a shell `sed` capture
// whose only guard was `${VAR:?}`, in a RUN no test could reach. Each case
// asserts the parse's OWN contract — a usable pairing, or a refusal that says
// the gate cannot read the client's declaration (which the caller turns into
// exit 2, "fix the gate, do not bump a pin", never a floor verdict).
func TestReadManifest(t *testing.T) {
	const good = `{"schemaVersion":1,"generatedBy":"web/src/wire-manifest.ts",` +
		`"wireCompatibility":{"protocolVersion":4,"minimumServerProtocolVersion":3,"incompatibleCloseCode":4002}}`
	cases := map[string]struct {
		content         string // "" = do not create the file at all
		wantOK          bool
		wantRev         int
		wantMinServer   int
		wantStderrNames string // a fragment naming WHY the manifest is unusable
	}{
		"the engine's published shape": {
			content: good, wantOK: true, wantRev: 4, wantMinServer: 3,
		},
		// Unknown-schema is the case the engine's own manifest declares
		// schemaVersion FOR: the format moved ahead of this gate, so the gate is
		// behind and no pin should move.
		"a newer schema is refused rather than guessed at": {
			content:         `{"schemaVersion":2,"wireCompatibility":{"protocolVersion":9,"minimumServerProtocolVersion":9}}`,
			wantStderrNames: "schemaVersion 2",
		},
		"a schemaVersion-less document is refused": {
			content:         `{"wireCompatibility":{"protocolVersion":4,"minimumServerProtocolVersion":3}}`,
			wantStderrNames: "schemaVersion 0",
		},
		// The silent-empty-capture failure the `${VAR:?}` guards existed for: a
		// renamed or absent field must not read as revision 0 and reach the
		// engine's comparator.
		"a manifest with no usable revisions is refused": {
			content:         `{"schemaVersion":1,"wireCompatibility":{}}`,
			wantStderrNames: "no usable wireCompatibility revisions",
		},
		"a non-JSON document is refused": {
			content:         "export const WIRE_PROTOCOL_VERSION = 4;\n",
			wantStderrNames: "cannot parse",
		},
		"an absent manifest is refused": {
			wantStderrNames: "cannot read",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wire-compatibility.json")
			if tc.content != "" {
				if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
					t.Fatalf("write manifest fixture: %v", err)
				}
			}
			var stderr bytes.Buffer
			rev, minServer, ok := readManifest(path, &stderr)
			if ok != tc.wantOK {
				t.Fatalf("readManifest ok = %v, want %v (stderr %q)", ok, tc.wantOK, stderr.String())
			}
			if !tc.wantOK {
				if !strings.Contains(stderr.String(), tc.wantStderrNames) {
					t.Errorf("stderr = %q, want it to name %q; \"fix the gate\" is only actionable when it says what could not be read",
						stderr.String(), tc.wantStderrNames)
				}
				if !strings.Contains(stderr.String(), usageErrMsg) {
					t.Errorf("stderr = %q, want it to carry the usage line so the reader is told not to bump a pin", stderr.String())
				}
				return
			}
			if rev != tc.wantRev || minServer != tc.wantMinServer {
				t.Errorf("readManifest = (%d, %d), want (%d, %d)", rev, minServer, tc.wantRev, tc.wantMinServer)
			}
		})
	}
}

// TestReadManifest_readsTheVendoredEngineArtifact closes the loop the Dockerfile
// step depends on: the manifest the image build actually points the gate at must
// parse, and the pairing it declares must be the one the engine's Go constants
// agree with. A shape change in the published artifact (a renamed field, a bumped
// schemaVersion) would otherwise surface only as an exit-2 image build.
func TestReadManifest_readsTheVendoredEngineArtifact(t *testing.T) {
	const vendored = "../../static-src/node_modules/@cplieger/web-terminal-engine/wire-compatibility.json"
	if _, err := os.Stat(vendored); err != nil {
		t.Skip("vendored engine artifact absent (no npm install here); the image build reads it")
	}
	var stderr bytes.Buffer
	rev, minServer, ok := readManifest(vendored, &stderr)
	if !ok {
		t.Fatalf("readManifest(%s) refused the vendored artifact: %s", vendored, stderr.String())
	}
	if code := run(rev, minServer, &bytes.Buffer{}, &stderr); code != 0 {
		t.Errorf("the vendored engine artifact's declared pairing (client rev %d, min server %d) fails the gate: exit %d, %s",
			rev, minServer, code, stderr.String())
	}
}
