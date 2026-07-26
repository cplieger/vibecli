package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSessionWorkDirWiredIntoSessionFactory pins terminal.WithWorkDir in
// registerRoutes' session factory: every kiro-cli chat must start in
// KWEB_WORK_DIR (/workspace in the container), never in the server process's
// own working directory. Nothing asserted this option -- every other session
// test leaves workDir "" and checks only status, logs, or titles -- so
// deleting it keeps the whole suite green while each tab opens on the wrong
// tree and kiro-cli sees the container root instead of the user's repo
// checkouts.
//
// The child records its PHYSICAL cwd (pwd -P; /tmp itself may be a symlink)
// and then stays alive under cat so the session is not torn down mid-write.
// The assertion polls for the marker under a deadline rather than sleeping a
// guessed interval.
func TestSessionWorkDirWiredIntoSessionFactory(t *testing.T) {
	workDir, resolveErr := filepath.EvalSymlinks(t.TempDir())
	if resolveErr != nil {
		t.Fatalf("EvalSymlinks: %v", resolveErr)
	}
	marker := filepath.Join(t.TempDir(), "cwd")
	deps := newTestDeps(true)
	deps.workDir = workDir
	deps.cmd = []string{"/bin/sh", "-c", `pwd -P > '` + marker + `'; exec cat`}
	_, mgr, _ := mustRegisterRoutes(t, deps)
	if _, err := mgr.Create(); err != nil {
		t.Fatalf("Create: %v", err)
	}
	quietTeardown(t, deps)

	deadline := time.Now().Add(10 * time.Second)
	for {
		b, readErr := os.ReadFile(marker) // #nosec G304 -- test-owned temp path
		if readErr == nil && len(b) > 0 {
			if got := strings.TrimSpace(string(b)); got != workDir {
				t.Errorf("session working directory = %q, want %q -- terminal.WithWorkDir(deps.workDir) is missing from the session factory, so every session starts in the server's cwd instead of KWEB_WORK_DIR", got, workDir)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("child never reported its working directory; the session command must run pwd -P into the marker")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
