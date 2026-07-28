package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestKeepUnfocusedWiredIntoSessionFactory pins the OTHER half of the OSC 9
// notification chain the tab activity dots depend on: registerRoutes' session
// factory passes terminal.WithKeepUnfocused(), which makes the engine write a
// DEC 1004 focus-out (ESC [ O) to the PTY whenever the child enables focus
// reporting, so kiro-cli — which emits its turn/permission notifications only
// while it believes it is unfocused — keeps emitting them. Nothing asserted
// this option: TestStatusClassifierWiredIntoManager injects the OSC 9 sequence
// with printf, so it stays green with the option deleted, and the dots would
// silently stop latching against the real kiro-cli.
//
// The child switches the PTY out of canonical mode (a canonical read would
// block on the newline-less escape sequence), enables focus reporting, records
// the first three bytes the server writes back, then stays alive under cat so
// the session is not torn down mid-write.
func TestKeepUnfocusedWiredIntoSessionFactory(t *testing.T) {
	if _, err := exec.LookPath("stty"); err != nil {
		// A skip is right on a stripped dev machine, but under CI it would turn
		// the ONLY check on terminal.WithKeepUnfocused() off with a green run.
		if os.Getenv("CI") != "" {
			t.Fatalf("stty unavailable under CI: this is the only assertion on terminal.WithKeepUnfocused(), so it must not be skipped in the gate")
		}
		t.Skip("stty unavailable: the child cannot leave canonical mode, so it cannot read the focus-out bytes")
	}
	marker := filepath.Join(t.TempDir(), "focus-bytes")
	deps := newTestDeps(true)
	deps.cmd = staticCmd(
		"/bin/sh", "-c",
		`stty raw -echo 2>/dev/null; printf '\033[?1004h'; dd bs=1 count=3 of='`+marker+`' 2>/dev/null; exec cat`,
	)
	mustStartSession(t, deps)

	if got := string(readMarkerWithin(t, marker, 3, "receive a DEC 1004 focus-out after enabling focus reporting; registerRoutes must pass terminal.WithKeepUnfocused() or kiro-cli stops emitting the OSC 9 notifications that latch the tab status dots")); got != "\x1b[O" {
		t.Errorf("child received %q, want the DEC 1004 focus-out %q", got, "\x1b[O")
	}
}
