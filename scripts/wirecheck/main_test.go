package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

// TestDockerfileInvokesTheGate pins the gate's only execution site. run()'s verdict
// is worthless if nothing runs it: a stage restructure that drops OR COMMENTS OUT
// the RUN leaves this package compiling and every test green while an incompatible
// Go/TS pair ships and refuses every session at first connect (close 4002) behind a
// green /api/health.
func TestDockerfileInvokesTheGate(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	// One LIVE line must carry the invocation and both flags. A whole-file
	// substring sweep would pass on a commented-out RUN (`#    go run
	// ./scripts/wirecheck …`) — the other half of the silent case this test
	// exists for, and the likelier one during a stage restructure, since it is
	// the reversible edit a person makes while debugging a build — and the prose
	// block above the RUN already mentions scripts/wirecheck. Requiring all three
	// needles on ONE uncommented line also proves both flags are still attached
	// to the gate invocation rather than surviving somewhere else in the file.
	invoked := false
	for line := range strings.SplitSeq(string(b), "\n") {
		if lineInvokesTheGate(line) {
			invoked = true
			break
		}
	}
	if !invoked {
		t.Error("Dockerfile has no un-commented `go run ./scripts/wirecheck " +
			"-client-rev ... -client-min-server ...` line; the wire-floor gate is " +
			"not invoked (deleted OR commented out), so an incompatible Go/TS pair " +
			"would build clean and refuse every session with close 4002 at runtime")
	}
}

// lineInvokesTheGate reports whether one Dockerfile line RUNS the wire-floor gate
// with both flags attached. The executable is anchored at the START of the trimmed
// line rather than merely contained in it: a substring test counts inert shell data
// as an invocation, so `echo go run ./scripts/wirecheck …` (the reversible edit a
// person makes while debugging a build) would print the command, exit 0, and leave
// this file's parity test green while the gate no longer runs. A future Dockerfile
// restructure that legitimately puts another shell construct before the command
// fails the parity test until this assertion is consciously updated -- the intended
// trade, since the alternative silently ships an incompatible Go/TS pair. A line
// carrying `||` is rejected for the same reason in the other direction: it still
// runs the gate but discards the verdict, so the build survives an incompatible
// pair.
func lineInvokesTheGate(line string) bool {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "#") {
		return false // a commented-out invocation is not an invocation
	}
	if strings.Contains(trimmed, "||") {
		// A swallowed verdict is not a gate: `go run ... || true` runs the
		// check and then exits 0 on an incompatible pair.
		return false
	}
	return strings.HasPrefix(trimmed, "go run ./scripts/wirecheck ") &&
		strings.Contains(trimmed, "-client-rev") &&
		strings.Contains(trimmed, "-client-min-server")
}

// TestLineInvokesTheGate_rejectsInertForms pins the recognizer itself, which is
// what makes TestDockerfileInvokesTheGate's verdict mean "the gate runs" rather
// than "the gate's name appears somewhere". Each negative is a shape that leaves
// the text intact while the build stops executing it.
func TestLineInvokesTheGate_rejectsInertForms(t *testing.T) {
	const flags = `-client-rev "$CLIENT_REV" -client-min-server "$CLIENT_MIN_SERVER"`
	cases := map[string]struct {
		line string
		want bool
	}{
		"the live Dockerfile form":      {"    go run ./scripts/wirecheck " + flags, true},
		"echoed, so never executed":     {"    echo go run ./scripts/wirecheck " + flags, false},
		"quoted into a no-op builtin":   {"    : 'go run ./scripts/wirecheck " + flags + "'", false},
		"commented out":                 {"#    go run ./scripts/wirecheck " + flags, false},
		"missing the client-rev flag":   {`    go run ./scripts/wirecheck -client-min-server "$CLIENT_MIN_SERVER"`, false},
		"missing the min-server flag":   {`    go run ./scripts/wirecheck -client-rev "$CLIENT_REV"`, false},
		"prose mentioning the gate":     {"# public Go API inside scripts/wirecheck (no source scraping)", false},
		"another command of the binary": {"    go build ./scripts/wirecheck " + flags, false},
		"verdict swallowed by || true":  {"    go run ./scripts/wirecheck " + flags + " || true", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := lineInvokesTheGate(tc.line); got != tc.want {
				t.Errorf("lineInvokesTheGate(%q) = %v, want %v", tc.line, got, tc.want)
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

// TestRun_exitCodeContract pins the process exit codes and output streams that
// are this program's own contract (0 compatible, 1 floor violated, 2 usage
// error). The Dockerfile's gate observes only zero vs non-zero (see run's doc
// comment), so these codes are the contract for direct invocation and for this
// test. TestRun_delegatesToTheEngineRule alone cannot pin them: it checks only
// the compatible-vs-not verdict, so a wiring regression in main/run (an
// inverted reason check, a swapped exit code, output on the wrong stream)
// would pass it and silently neuter or break the image build gate.
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
