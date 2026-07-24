package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

// TestIncompatibility pins the two directional floor checks and the named
// remediation in each failure message: the server must meet the client's
// minimum server revision, and the client must meet the server's minimum
// client revision. Values are exercised around the current 4/3 floors so a
// future floor raise re-runs meaningful boundaries.
func TestIncompatibility(t *testing.T) {
	cases := []struct {
		name                                                   string
		serverRev, serverMinClient, clientRev, clientMinServer int
		wantSubstr                                             string // "" = compatible
	}{
		{name: "current pairing compatible", serverRev: 4, serverMinClient: 3, clientRev: 4, clientMinServer: 3},
		{name: "skew within floors compatible", serverRev: 5, serverMinClient: 3, clientRev: 4, clientMinServer: 4},
		{
			name: "server below client floor", serverRev: 3, serverMinClient: 3, clientRev: 5, clientMinServer: 4,
			wantSubstr: "bump go.mod",
		},
		{
			name: "client below server floor", serverRev: 5, serverMinClient: 5, clientRev: 4, clientMinServer: 3,
			wantSubstr: "bump the Dockerfile ARG",
		},
		{name: "equal at both floors compatible", serverRev: 3, serverMinClient: 3, clientRev: 3, clientMinServer: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := incompatibility(tc.serverRev, tc.serverMinClient, tc.clientRev, tc.clientMinServer)
			if tc.wantSubstr == "" {
				if got != "" {
					t.Errorf("incompatibility(%d,%d,%d,%d) = %q, want compatible",
						tc.serverRev, tc.serverMinClient, tc.clientRev, tc.clientMinServer, got)
				}
				return
			}
			if got == "" || !strings.Contains(got, tc.wantSubstr) {
				t.Errorf("incompatibility(%d,%d,%d,%d) = %q, want reason containing %q",
					tc.serverRev, tc.serverMinClient, tc.clientRev, tc.clientMinServer, got, tc.wantSubstr)
			}
		})
	}
}

// TestRun_exitCodeContract pins the process exit codes and output streams the
// Dockerfile wire-floor gate consumes — the package comment's documented
// contract (0 compatible, 1 floor violated, 2 usage error). incompatibility()
// alone cannot pin this: a wiring regression in main/run (an inverted
// reason check, a swapped exit code, output on the wrong stream) would pass
// TestIncompatibility and silently neuter or break the image build gate.
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
				t.Errorf("run(%d, %d) = %d, want exit code %d (the Dockerfile gate branches on it)",
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
