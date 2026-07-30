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
	runFastDeathSession := func(t *testing.T, ready bool, kiroReady func() (bool, string)) *capture.Recorder {
		t.Helper()
		records := capture.Default(t) // before registerRoutes: the factory derives its logger from slog.Default()
		deps := newTestDeps(ready)
		deps.kiroReady = kiroReady         // the composition root's permissive default is the no-install shape
		deps.cmd = staticCmd("/bin/false") // exits 1 instantly: the broken-install signature (non-nil Wait error, well under 10s)
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

	const warnMsg = sessionFastDeathMsg

	// The permissive readiness policy main.go's unmanagedKiroRuntime supplies:
	// no install to gate on, so the hook's kiro-cli conjunct is satisfied.
	noInstall := func() (bool, string) { return true, "" }

	t.Run("spontaneous fast death while serving warns once", func(t *testing.T) {
		records := runFastDeathSession(t, true, noInstall)
		if got := records.CountLevel(slog.LevelWarn, warnMsg); got != 1 {
			t.Errorf("log = %q, want exactly one fast-death Warn (got %d); a broken kiro-cli install must be operator-visible outside the PTY", records.Messages(), got)
		}
	})

	t.Run("app-initiated shutdown stays quiet", func(t *testing.T) {
		records := runFastDeathSession(t, false, noInstall)
		if got := records.CountLevel(slog.LevelWarn, warnMsg); got != 0 {
			t.Errorf("log = %q, want no fast-death Warn when readiness is cleared (got %d); a deploy teardown must not raise false broken-install alerts", records.Messages(), got)
		}
	})

	// The kiro-cli half of the hook's guard, which the two rows above cannot
	// see: both use the permissive no-install policy, so the readiness read
	// returns true and the conjunct is never exercised. The install manager's
	// verdict changes while the server runs in both directions (a first-boot
	// download completing, a rescan, an exhausted retry budget), so a session can
	// die fast at a moment kiro-cli is NOT usable -- and that state already has
	// its own 503 and its own log line, so promoting it to a broken-install Warn
	// is a false alert on exactly the boot where the log is busiest. Deleting the
	// `&& kiroReady` conjunct from the factory's WithOnProcessExit hook, or
	// inverting it, leaves every other test in the package green.
	t.Run("fast death while kiro-cli is unready stays quiet", func(t *testing.T) {
		records := runFastDeathSession(t, true, func() (bool, string) { return false, reasonInstalling })
		if got := records.CountLevel(slog.LevelWarn, warnMsg); got != 0 {
			t.Errorf("log = %q, want no fast-death Warn while the kiro-cli install is unready (got %d); that state reports itself through /api/health's reason, and a broken-install alert per tab during a first-boot download is the false signal the guard exists to suppress", records.Messages(), got)
		}
	})
}
