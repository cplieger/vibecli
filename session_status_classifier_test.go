package main

import (
	"fmt"
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
	quietTeardown(t, deps)

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

// TestClassifyStatus_unrecognizedNotificationLogsBoundedWarning pins the three
// observable LOGGING behaviors of the unrecognized-notification path, which
// TestClassifyStatus (return values only) leaves entirely unguarded: the first
// occurrence of each DISTINCT unknown notification is promoted to Warn so a
// kiro-cli wording drift is visible at the default info level, a REPEAT of a
// message already warned about is not, and EVERY occurrence stays recorded at
// Debug for KWEB_LOG_LEVEL=debug. Without this test, deleting the Warn block,
// warning on every occurrence (log flooding), or deleting the Debug trace all
// leave the suite green.
//
// The per-distinct keying is the point, and it is what this test used to get
// wrong: it fed two DIFFERENT unknown messages and asserted exactly one Warn,
// which pinned the defect rather than the intent. A single latch was spent by the
// first unknown message of any kind, so one benign extra notification silenced
// the warning for a later rewording of the two strings the dots depend on -- the
// exact drift the Warn exists to surface. The bound that remains is on VOLUME
// (unrecognizedNotifyCap distinct strings), asserted separately below.
//
// The latch is owned by the classifier instance, so the test builds its own and
// depends on no package state. capture.Default swaps the global default logger,
// so this test must never call t.Parallel.
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
	// A DISTINCT second message warns: this is the regression guard. With the old
	// single latch this count was 1, and a reworded "Response complete" arriving
	// after any other notification produced no Warn at all.
	if got := records.CountLevel(slog.LevelWarn, message); got != 2 {
		t.Errorf("unrecognized notification Warn count = %d, want 2 (one per distinct message)", got)
	}
	// A REPEAT does not warn again, which is what keeps a chatty build from
	// flooding the shipped stream.
	classify("New response wording")
	if got := records.CountLevel(slog.LevelWarn, message); got != 2 {
		t.Errorf("Warn count after repeating a known-unknown = %d, want 2 (repeats stay Debug-only)", got)
	}
	if got := records.CountLevel(slog.LevelDebug, message); got != 3 {
		t.Errorf("unrecognized notification Debug count = %d, want 3 (every occurrence is traced)", got)
	}
}

// TestClassifyStatus_unrecognizedNotificationCapsDistinctWarnings pins the volume
// bound that replaced the single latch. Without it, per-distinct warning would be
// an unbounded log-volume AND unbounded-memory vector: the map key is child
// process output, so a session emitting a fresh notification per turn would grow
// the seen-set for the container's lifetime.
func TestClassifyStatus_unrecognizedNotificationCapsDistinctWarnings(t *testing.T) {
	records := capture.Default(t)
	const message = "unrecognized kiro-cli OSC 9 notification"
	classify := newStatusClassifier()

	// One more distinct message than the budget allows.
	for i := range unrecognizedNotifyCap + 1 {
		classify(fmt.Sprintf("wording variant %d", i))
	}
	if got := records.CountLevel(slog.LevelWarn, message); got != unrecognizedNotifyCap {
		t.Errorf("per-distinct Warn count = %d, want %d (the cap)", got, unrecognizedNotifyCap)
	}
	// The message the cap turned away announces exhaustion exactly once, so a
	// silent stop is never mistaken for "nothing new appeared". This wording must
	// not be a substring of the drift wording (or vice versa) or the counts above
	// would double-count it -- the same confusion a log search would hit.
	const capped = "kiro-cli OSC 9 notification warn budget exhausted"
	if got := records.CountLevel(slog.LevelWarn, capped); got != 1 {
		t.Errorf("budget-exhausted Warn count = %d, want 1", got)
	}
	classify("yet another distinct wording")
	if got := records.CountLevel(slog.LevelWarn, capped); got != 1 {
		t.Errorf("budget-exhausted Warn count after a further distinct message = %d, want 1 (announced once)", got)
	}
	// Every occurrence still reaches Debug, so the full set stays diagnosable.
	if got := records.CountLevel(slog.LevelDebug, message); got != unrecognizedNotifyCap+2 {
		t.Errorf("Debug count = %d, want %d (every occurrence traced)", got, unrecognizedNotifyCap+2)
	}
}

// TestClassifyStatus_logsSanitizedNotificationText pins the LOG-SAFETY half of
// the OSC 9 coupling, which has two independent halves.
//
// INTEGRITY: newStatusClassifier logs notification text whose only forging
// defence is the engine's capture-time sanitization (runesafe drops C0/DEL, C1,
// Bidi controls and U+2028/29 and rune-caps the text). That
// justification is an assumption about a Renovate-bumped dependency and
// nothing here checks it: the notification text originates in arbitrary child
// output, so if a bump moved or dropped sanitizeNotification, any program run
// in the terminal could inject Bidi overrides or forged fields into the
// aggregated log stream (CWE-117) and every existing test would still pass.
//
// CONFIDENTIALITY: sanitization redacts nothing, so the same arbitrary child
// output could carry a token or a device code. The Warn therefore carries only a
// bounded `message_excerpt` while the full text stays at Debug, and this test
// pins that split — a long notification must be truncated in the default stream
// and complete under KWEB_LOG_LEVEL=debug. Asserting only the Warn (as this test
// originally did, on a `message` attribute that no longer exists there) would let
// a change that logs the full text at Warn pass unnoticed.
//
// A real session emits an OSC 9 whose text carries U+202E (RIGHT-TO-LEFT
// OVERRIDE, an unsafe rune under the engine's policy) followed by enough
// characters to exceed the excerpt bound. The assertions prove the app's records
// carry the notification text, never the unsafe rune, and truncate at Warn — so
// they fail on the Renovate PR that would break the sanitization guarantee AND on
// a regression that widens the default stream.
//
// registerRoutes constructs a fresh classifier (with its own warn latch)
// per call, so the records are produced regardless of what earlier tests logged.
// capture.Default records every level and swaps the global default logger, so this
// test must never call t.Parallel.
func TestClassifyStatus_logsSanitizedNotificationText(t *testing.T) {
	records := capture.Default(t)

	deps := newTestDeps(true)
	// An unrecognized OSC 9 notification (so it reaches the logging branch) whose
	// text embeds U+202E and is LONGER than the excerpt bound, so the same record
	// exercises sanitization and truncation; `exec cat` keeps the child alive so
	// the session is not torn down before the notification is classified.
	longTail := strings.Repeat("x", unrecognizedNotifyExcerptRunes)
	deps.cmd = []string{"/bin/sh", "-c", `printf '\033]9;evil\342\200\256wording` + longTail + `\a'; exec cat`}
	_, mgr, _ := mustRegisterRoutes(t, deps)
	if _, err := mgr.Create(); err != nil {
		t.Fatalf("Create: %v", err)
	}
	quietTeardown(t, deps)

	const unsafeRune = "\u202e"
	// The EXACT text each record must carry. The engine's sanitizeNotification
	// DROPS an unsafe rune (it does not substitute a placeholder) and caps at 256
	// runes, so the sanitized notification is the emitted text minus U+202E; the
	// excerpt is then notifyExcerpt's bounded prefix of exactly that. Spelled out
	// rather than probed with a substring + length bound, because a loose oracle
	// admitted the regressions this test exists to catch: a Debug attribute
	// truncated to anything from 65 to 74 runes still contained "evil" and still
	// exceeded the bound, and any short excerpt ending in an ellipsis satisfied the
	// Warn side without proving the full 64-rune prefix survived.
	wantFull := "evilwording" + longTail
	wantExcerpt := string([]rune(wantFull)[:unrecognizedNotifyExcerptRunes]) + "…"
	// attrOf returns the named attribute of the first record at level that carries
	// the unrecognized-notification message.
	attrOf := func(level slog.Level, key string) (string, bool) {
		for _, r := range records.Records() {
			if r.Level != level || !strings.Contains(r.Message, "unrecognized kiro-cli OSC 9 notification") {
				continue
			}
			var got string
			found := false
			r.Attrs(func(a slog.Attr) bool {
				if a.Key == key {
					got, found = a.Value.String(), true
					return false
				}
				return true
			})
			if found {
				return got, true
			}
		}
		return "", false
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		excerpt, haveWarn := attrOf(slog.LevelWarn, "message_excerpt")
		full, haveDebug := attrOf(slog.LevelDebug, "message")
		if haveWarn && haveDebug {
			// Both records carry the text and neither carries the unsafe rune: the
			// engine sanitized before the classifier ever saw it. Kept as an
			// independent guard -- it fails on a sanitization regression even if the
			// exact comparisons below are ever relaxed.
			for _, tc := range []struct{ what, got string }{
				{"Warn excerpt", excerpt},
				{"Debug full text", full},
			} {
				if strings.Contains(tc.got, unsafeRune) {
					t.Errorf("%s = %q carries U+202E; the engine must sanitize notification text before the classifier logs it, or arbitrary child output can inject into the log stream", tc.what, tc.got)
				}
			}
			// The default stream is BOUNDED and says so; the Debug record is not.
			if full != wantFull {
				t.Errorf("Debug full text = %q, want the COMPLETE sanitized notification %q (Debug must not be truncated -- it is what an operator raises the level for)", full, wantFull)
			}
			if excerpt != wantExcerpt {
				t.Errorf("Warn excerpt = %q, want exactly the %d-rune prefix plus the truncation marker: %q (a token in child output must not reach the always-on stream in full, and a clipped wording must stay distinguishable from a short one)", excerpt, unrecognizedNotifyExcerptRunes, wantExcerpt)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no unrecognized-notification record pair reached the log (warn=%v debug=%v); log = %q", haveWarn, haveDebug, records.Messages())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
