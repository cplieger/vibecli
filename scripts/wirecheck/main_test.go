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
// is worthless if nothing runs it: a stage restructure that drops the RUN leaves
// this package compiling and every test green while an incompatible Go/TS pair
// ships and refuses every session at first connect (close 4002) behind a green
// /api/health.
func TestDockerfileInvokesTheGate(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	for _, want := range []string{
		"go run ./scripts/wirecheck",
		"-client-rev",
		"-client-min-server",
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("Dockerfile no longer contains %q; the wire-floor gate is "+
				"not invoked, so an incompatible Go/TS pair would build clean and "+
				"refuse every session with close 4002 at runtime", want)
		}
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
