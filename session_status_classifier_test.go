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

// TestStatusClassifierWiredIntoManager pins the WIRING of the app's only
// kiro-cli-specific coupling: registerRoutes hands newStatusClassifier()'s
// mapping to the
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
			t.Fatalf("session status never latched to %q after the OSC 9 notification; body %s (registerRoutes must pass terminal.WithStatusClassifier(newStatusClassifier()))",
				terminal.StatusDone, rec.Body.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestClassifyStatus_unrecognizedNotificationLogsBoundedWarning pins the two
// observable LOGGING behaviors of the unrecognized-notification path, which
// TestClassifyStatus (return values only) leaves entirely unguarded: exactly the
// FIRST unknown notification per classifier is promoted to Warn so a kiro-cli
// wording drift is visible at the default info level, and EVERY occurrence stays
// recorded at Debug for KWEB_LOG_LEVEL=debug. Without this test, deleting the
// Warn block, moving it outside the sync.Once (log flooding on every
// notification), or deleting the Debug trace all leave the suite green.
//
// The warn-once latch is owned by the classifier instance, so the test builds
// its own and depends on no package state. capture.Default swaps the global
// default logger, so this test must never call t.Parallel.
func TestClassifyStatus_unrecognizedNotificationLogsBoundedWarning(t *testing.T) {
	records := capture.Default(t)
	const message = "unrecognized kiro-cli OSC 9 notification"
	classify := newStatusClassifier()

	got, latch := classify("New response wording")
	if got != "" || latch {
		t.Errorf("classify(first unknown) = (%q, %v), want (empty, false)", got, latch)
	}
	got, latch = classify("Another response wording")
	if got != "" || latch {
		t.Errorf("classify(second unknown) = (%q, %v), want (empty, false)", got, latch)
	}
	if got := records.CountLevel(slog.LevelWarn, message); got != 1 {
		t.Errorf("unrecognized notification Warn count = %d, want 1 (bounded to the first occurrence per classifier)", got)
	}
	if got := records.CountLevel(slog.LevelDebug, message); got != 2 {
		t.Errorf("unrecognized notification Debug count = %d, want 2 (every occurrence is traced)", got)
	}
}

// TestClassifyStatus_logsSanitizedNotificationText pins the LOG-SAFETY half of
// the OSC 9 coupling. classifyStatus logs the notification text raw, and its
// comment justifies that by the engine's capture-time sanitization (runesafe
// drops C0/DEL, C1, Bidi controls and U+2028/29 and rune-caps the text). That
// justification is an assumption about a Renovate-bumped dependency and
// nothing here checks it: the notification text originates in arbitrary child
// output, so if a bump moved or dropped sanitizeNotification, any program run
// in the terminal could inject Bidi overrides or forged fields into the
// aggregated log stream (CWE-117) and every existing test would still pass.
//
// A real session emits an OSC 9 whose text carries U+202E (RIGHT-TO-LEFT
// OVERRIDE, an unsafe rune under the engine's policy). The assertion proves
// the app's log record carries the notification text but not the unsafe rune,
// so it fails on the Renovate PR that would break the guarantee.
//
// registerRoutes constructs a fresh classifier (with its own warn-once latch)
// per call, so the record is produced regardless of what earlier tests logged.
// capture.Default swaps the global default logger, so this test must never call
// t.Parallel.
func TestClassifyStatus_logsSanitizedNotificationText(t *testing.T) {
	records := capture.Default(t)

	deps := newTestDeps(true)
	// An unrecognized OSC 9 notification (so it reaches the logging branch)
	// whose text embeds U+202E; `exec cat` keeps the child alive so the session
	// is not torn down before the notification is classified.
	deps.cmd = []string{"/bin/sh", "-c", `printf '\033]9;evil\342\200\256wording\a'; exec cat`}
	_, mgr, _ := mustRegisterRoutes(t, deps)
	if _, err := mgr.Create(); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Clear readiness before the deferred mgr.Shutdown kills the child so a
	// teardown kill cannot emit a stray fast-death Warn into this capture.
	t.Cleanup(func() { deps.ready.Set(false) })

	const (
		unsafeRune = "\u202e"
		wantSubstr = "evil"
	)
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, r := range records.Records() {
			if !strings.Contains(r.Message, "unrecognized kiro-cli OSC 9 notification") {
				continue
			}
			var logged string
			r.Attrs(func(a slog.Attr) bool {
				if a.Key == "message" {
					logged = a.Value.String()
					return false
				}
				return true
			})
			if !strings.Contains(logged, wantSubstr) {
				t.Fatalf("logged notification = %q, want it to carry the notification text %q", logged, wantSubstr)
			}
			if strings.Contains(logged, unsafeRune) {
				t.Errorf("logged notification = %q carries U+202E; the engine must sanitize notification text before the classifier logs it, or arbitrary child output can inject into the log stream", logged)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no unrecognized-notification record reached the log; log = %q", records.Messages())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
