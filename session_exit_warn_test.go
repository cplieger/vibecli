package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

// TestSessionFastDeathWarn pins the operator-facing fast-death signal wired in
// registerRoutes' session factory (WithOnProcessExit): a session whose process
// dies within seconds of spawn while the server is SERVING (ready=true) is the
// kiro-cli-missing/broken signature and must be promoted to exactly one Warn;
// an app-initiated teardown (readiness already cleared by the SIGTERM pre-drain
// or the Serve-error path) must stay quiet, or every deploy would emit a false
// broken-install alert. Neither branch was asserted anywhere: the hook's
// statements were executed only incidentally when unrelated tests' cleanups
// killed their live sessions, so deleting the Warn or inverting the ready gate
// would have passed the suite.
//
// Synchronization: the manager's session status derives from Handler.Exited(),
// whose procExitCh closes only AFTER the engine's process monitor has invoked
// the OnProcessExit callback (terminal.go: the callback runs in the monitor
// body, the channel close in its defer). Polling GET /api/sessions for
// "exited" is therefore a deterministic happens-after barrier for the Warn
// decision on BOTH branches — no bare sleep guessing.
//
// Serial: capture.Default mutates the process-global default logger, and the
// factory binds its session logger from slog.Default() at Create time (no
// t.Parallel).
func TestSessionFastDeathWarn(t *testing.T) {
	runFastDeathSession := func(t *testing.T, ready bool) *capture.Recorder {
		t.Helper()
		records := capture.Default(t) // before registerRoutes: the factory derives its logger from slog.Default()
		deps := newTestDeps(ready)
		deps.cmd = []string{"/bin/false"} // exits 1 instantly: the broken-install signature (non-nil Wait error, well under 10s)
		mux, mgr, _ := mustRegisterRoutes(t, deps)
		if _, err := mgr.Create(); err != nil {
			t.Fatalf("Create: %v", err)
		}

		deadline := time.Now().Add(10 * time.Second)
		for {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, terminal.SessionsPath, http.NoBody))
			if strings.Contains(rec.Body.String(), `"status":"`+terminal.StatusExited+`"`) {
				return records
			}
			if time.Now().After(deadline) {
				t.Fatalf("session never reported exited; body %s", rec.Body.String())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	const warnMsg = "exited almost immediately"

	t.Run("spontaneous fast death while serving warns once", func(t *testing.T) {
		records := runFastDeathSession(t, true)
		if got := records.CountLevel(slog.LevelWarn, warnMsg); got != 1 {
			t.Errorf("log = %q, want exactly one fast-death Warn (got %d); a broken kiro-cli install must be operator-visible outside the PTY", records.Messages(), got)
		}
	})

	t.Run("app-initiated shutdown stays quiet", func(t *testing.T) {
		records := runFastDeathSession(t, false)
		if got := records.CountLevel(slog.LevelWarn, warnMsg); got != 0 {
			t.Errorf("log = %q, want no fast-death Warn when readiness is cleared (got %d); a deploy teardown must not raise false broken-install alerts", records.Messages(), got)
		}
	})
}
