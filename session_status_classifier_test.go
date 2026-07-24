package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

// TestStatusClassifierWiredIntoManager pins the WIRING of the app's only
// kiro-cli-specific coupling: registerRoutes hands classifyStatus to the
// engine via terminal.WithStatusClassifier, and that option is what turns a
// kiro-cli OSC 9 notification into the latched per-tab status the UI paints.
// TestClassifyStatus covers the mapping FUNCTION in isolation, so dropping the
// WithStatusClassifier option leaves every session at "idle" forever — the tab
// activity dots die silently and the whole suite stays green (verified by
// deleting the option: only this test fails). This drives a real session whose
// process emits the OSC 9 "Response complete" sequence and asserts the status
// the engine reports on GET /api/sessions latches to done.
//
// Synchronization: the notification travels the PTY -> VT parser -> classifier
// path asynchronously, so the assertion polls the engine's own list endpoint
// (the same observable the UI reads) under a deadline rather than sleeping a
// guessed interval.
func TestStatusClassifierWiredIntoManager(t *testing.T) {
	deps := newTestDeps(true)
	// printf emits the OSC 9 notification kiro-cli sends at turn end
	// (ESC ] 9 ; text BEL); `exec cat` then keeps the process alive so the
	// session stays listed while the status latches.
	deps.cmd = []string{"/bin/sh", "-c", `printf '\033]9;Response complete\a'; exec cat`}
	mux, mgr, _ := mustRegisterRoutes(t, deps)
	if _, err := mgr.Create(); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Clear readiness before the deferred mgr.Shutdown kills the child: the
	// factory's fast-death hook keys on it, so this keeps a teardown kill from
	// emitting a stray broken-install Warn into a later test's log capture.
	t.Cleanup(func() { deps.ready.Set(false) })

	deadline := time.Now().Add(10 * time.Second)
	for {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, terminal.SessionsPath, http.NoBody))
		if strings.Contains(rec.Body.String(), `"status":"`+terminal.StatusDone+`"`) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("session status never latched to %q after the OSC 9 notification; body %s (registerRoutes must pass terminal.WithStatusClassifier(classifyStatus))",
				terminal.StatusDone, rec.Body.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
