package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	deps.cmd = staticCmd("/bin/sh", "-c", `printf '\033]9;Response complete\a'; exec cat`)
	mux, _, _, _ := mustStartSession(t, deps)

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
// Debug for WT_LOG_LEVEL=debug. Without this test, deleting the Warn block,
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
	const message = unrecognizedNotifyMsg
	classify := newStatusClassifier(false)

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

// TestClassifyStatus_recognizedNotificationTracesTheMapping pins the POSITIVE
// half of the classifier trace. The unrecognized arm's Warn/Debug pair answers
// "a wording this app does not recognize appeared"; nothing answered "a wording
// it DOES recognize appeared", so an operator running the documented
// WT_LOG_LEVEL=debug step after the tab status dots stop latching saw an empty
// classifier trace with two incompatible meanings: kiro-cli emitted no OSC 9
// notification at all (its notifier's focus gate, the engine's DEC 1004
// unfocused pin, or kiro-cli dropping the TERM_PROGRAM identity from its OSC
// allowlist) or every notification mapped fine and the dot is lost downstream
// (the engine's latch, the status SSE, the client's render). Different owners, so
// the investigation started by guessing which repo to open. The residual is
// sharper once unrecognizedNotifyCap is spent, since a later reword then produces
// no new record at all -- this trace is what still answers the question there.
//
// Deleting either Debug call must fail this test. capture.Default swaps the
// global default logger, so this test must never call t.Parallel.
func TestClassifyStatus_recognizedNotificationTracesTheMapping(t *testing.T) {
	records := capture.Default(t)
	classify := newStatusClassifier(false)

	type mapping struct{ notification, status string }
	want := []mapping{
		{"Response complete", terminal.StatusDone},
		{"Permission required", terminal.StatusInput},
		{"Input required", terminal.StatusInput},
	}
	for _, tc := range want {
		got, latch := classify(tc.notification)
		if got != tc.status || !latch {
			t.Errorf("classify(%q) = (%q, %v), want (%q, true)", tc.notification, got, latch, tc.status)
		}
	}

	// One record per recognized notification, each naming WHICH wording matched
	// and WHICH status it produced: the wording alone would not distinguish a
	// mis-mapped switch arm from a correct one.
	var got []mapping
	for _, r := range records.Records() {
		if !strings.Contains(r.Message, recognizedNotifyMsg) {
			continue
		}
		if r.Level != slog.LevelDebug {
			t.Errorf("recognized-notification trace logged at %s, want Debug; it fires at every turn boundary and must stay out of the shipped stream", r.Level)
		}
		var m mapping
		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "notification":
				m.notification = a.Value.String()
			case "status":
				m.status = a.Value.String()
			}
			return true
		})
		got = append(got, m)
	}
	if !slices.Equal(got, want) {
		t.Errorf("recognized-notification trace = %v, want %v (one Debug record per recognized notification, naming the matched wording and the status it mapped to)", got, want)
	}

	// The two classifier messages must stay searchable apart: every
	// confidentiality sweep in this file filters on unrecognizedNotifyMsg as a
	// substring, so a positive-trace wording that contained it would be swept as
	// an unrecognized record (and vice versa for a log search after a bump).
	if strings.Contains(recognizedNotifyMsg, unrecognizedNotifyMsg) || strings.Contains(unrecognizedNotifyMsg, recognizedNotifyMsg) {
		t.Errorf("recognizedNotifyMsg %q and unrecognizedNotifyMsg %q share a substring; a log search or a test matching one would match the other", recognizedNotifyMsg, unrecognizedNotifyMsg)
	}
	// A recognized notification is not a drift signal: nothing here may consume
	// the warn budget or reach the default stream.
	if n := records.CountLevel(slog.LevelWarn, unrecognizedNotifyMsg); n != 0 {
		t.Errorf("recognized notifications produced %d unrecognized-notification Warn records, want 0", n)
	}
}

// TestClassifyStatus_unrecognizedNotificationCapsDistinctWarnings pins the volume
// bound that replaced the single latch. Without it, per-distinct warning would be
// an unbounded log-volume AND unbounded-memory vector: the map key is child
// process output, so a session emitting a fresh notification per turn would grow
// the seen-set for the container's lifetime.
func TestClassifyStatus_unrecognizedNotificationCapsDistinctWarnings(t *testing.T) {
	records := capture.Default(t)
	const message = unrecognizedNotifyMsg
	classify := newStatusClassifier(false)

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
	const capped = unrecognizedNotifyCapMsg
	if got := records.CountLevel(slog.LevelWarn, capped); got != 1 {
		t.Errorf("budget-exhausted Warn count = %d, want 1", got)
	}
	classify("yet another distinct wording")
	if got := records.CountLevel(slog.LevelWarn, capped); got != 1 {
		t.Errorf("budget-exhausted Warn count after a further distinct message = %d, want 1 (announced once)", got)
	}
	// The cap record's EXACT attr set. It is the one always-on record the
	// package's confidentiality sweeps structurally cannot see:
	// TestClassifyStatus_notificationTextLogging filters on
	// unrecognizedNotifyMsg, and this wording deliberately shares no substring
	// with it, so an attr carrying the notification text here would reach the
	// shipped stream with nothing failing. The cap arm has the message in scope,
	// which is what makes that a one-line edit rather than a hypothetical.
	//
	// The fingerprint pair is required, not optional: since the announcement
	// RE-ARMS, it is the only default-level signal of a wording drift that begins
	// after the budget filled, and without the fingerprint two firings are
	// indistinguishable from the same rejected wording arriving twice. It is the
	// same content-free, keyed attribute the per-distinct arm carries — so this
	// assertion pins both the correlation key and its confidentiality shape.
	assertAttrSchema(t, records, slog.LevelWarn, capped, map[string]attrCheck{
		"message_fingerprint": isNotifyFingerprint,
		"message_runes":       wantInt(len([]rune(fmt.Sprintf("wording variant %d", unrecognizedNotifyCap)))),
		"distinct_limit":      wantInt(unrecognizedNotifyCap),
		"hint":                wantString(unrecognizedNotifyHint),
	})
	// Every occurrence still reaches Debug, so the full set stays diagnosable.
	if got := records.CountLevel(slog.LevelDebug, message); got != unrecognizedNotifyCap+2 {
		t.Errorf("Debug count = %d, want %d (every occurrence traced)", got, unrecognizedNotifyCap+2)
	}
}

// TestClassifyStatus_notificationTextLogging pins the LOG-SAFETY half of the
// OSC 9 coupling, which has two independent halves and one operator-facing
// switch between them.
//
// CONFIDENTIALITY (the default): notification text is arbitrary child output —
// any program in the terminal can emit `ESC ] 9 ; <text>` — and the engine's
// sanitization redacts nothing, so that text can carry a token or a device
// code. A bounded excerpt used to stand in for redaction and did not redact (a
// short secret fits inside any excerpt), so with WT_LOG_OSC_TEXT off NEITHER
// record may carry the text: the Warn and the Debug both get a content-free
// fingerprint plus a rune count. Without this test, restoring an excerpt — or
// putting the text back on the Debug record that WT_LOG_LEVEL=debug is
// routinely recommended for — leaves the suite green while re-creating a durable
// credential copy in the log store.
//
// INTEGRITY (the opt-in path): with WT_LOG_OSC_TEXT on, the Debug record does
// carry the full text, and its only forging defence is the engine's capture-time
// sanitization (runesafe drops C0/DEL, C1, Bidi controls and U+2028/29, and
// rune-caps the text). That justification is an assumption about a
// Renovate-bumped dependency, so this half emits a notification embedding U+202E
// and asserts the logged text is the sanitized one — it fails on the bump that
// moved or dropped sanitizeNotification, which would otherwise let child output
// inject forged fields into the aggregated stream (CWE-117).
//
// Both halves drive a REAL session (the notification travels PTY -> VT ->
// classifier asynchronously, hence the polling deadline). capture.Default swaps
// the global default logger, so this test must never call t.Parallel.
func TestClassifyStatus_notificationTextLogging(t *testing.T) {
	// A notification long enough that any excerpt-style regression is visibly a
	// prefix rather than the whole text, embedding U+202E (unsafe under the
	// engine's policy) so the same record exercises sanitization.
	longTail := strings.Repeat("x", 72)
	emitted := `evil\342\200\256wording` + longTail
	const unsafeRune = "\u202e"
	// The engine's sanitizeNotification DROPS an unsafe rune (no placeholder),
	// so the text the classifier sees is the emitted text minus U+202E.
	wantFull := "evilwording" + longTail

	// attrOf returns the named attribute of the first record at level carrying
	// the unrecognized-notification message, and whether any such record exists.
	attrOf := func(records *capture.Recorder, level slog.Level, key string) (value string, haveAttr, haveRecord bool) {
		for _, r := range records.Records() {
			if r.Level != level || !strings.Contains(r.Message, unrecognizedNotifyMsg) {
				continue
			}
			haveRecord = true
			r.Attrs(func(a slog.Attr) bool {
				if a.Key == key {
					value, haveAttr = a.Value.String(), true
					return false
				}
				return true
			})
			if haveAttr {
				return value, true, true
			}
		}
		return "", false, haveRecord
	}

	// The attr SCHEMA that pins which attrs may describe a notification at a given
	// level AND what each of their values must be is the package-shared
	// assertAttrSchema (trusted_proxies_test.go), used with unrecognizedNotifyMsg
	// as the message filter below.

	t.Run("default logs no notification text at any level", func(t *testing.T) {
		records := capture.Default(t)
		deps := newTestDeps(true) // logOSCText defaults false, like an unset env
		deps.cmd = staticCmd("/bin/sh", "-c", `printf '\033]9;`+emitted+`\a'; exec cat`)
		mustStartSession(t, deps)

		// The production key is drawn inside newStatusClassifier and never
		// logged, so the expected fingerprint is not computable here — by
		// design (an unkeyed digest of low-entropy child output would be
		// recoverable by offline enumeration). What the live session must show
		// is that ONE classifier instance stamps BOTH records with the SAME
		// well-formed identifier, which is the correlation property the
		// fingerprint replaced the text to preserve.
		deadline := time.Now().Add(10 * time.Second)
		for {
			warnFP, haveWarnFP, haveWarn := attrOf(records, slog.LevelWarn, "message_fingerprint")
			debugFP, haveDebugFP, haveDebug := attrOf(records, slog.LevelDebug, "message_fingerprint")
			if haveWarn && haveDebug {
				// Both records identify the notification, and by the SAME
				// fingerprint: that pairing is what an operator correlates on now
				// that neither record carries the text.
				for _, tc := range []struct {
					level    string
					fp       string
					haveAttr bool
				}{
					{"Warn", warnFP, haveWarnFP},
					{"Debug", debugFP, haveDebugFP},
				} {
					if !tc.haveAttr {
						t.Errorf("%s record carries no message_fingerprint; an unrecognized wording would be unidentifiable, which is what the fingerprint replaced the text to preserve", tc.level)
						continue
					}
					if len(tc.fp) != notifyFingerprintHexDigits || strings.Trim(tc.fp, "0123456789abcdef") != "" {
						t.Errorf("%s message_fingerprint = %q, want exactly %d lowercase hex digits; any other shape means child output shaped the record", tc.level, tc.fp, notifyFingerprintHexDigits)
					}
				}
				if haveWarnFP && haveDebugFP && warnFP != debugFP {
					t.Errorf("Warn message_fingerprint = %q but Debug = %q; one classifier instance must stamp both records identically or an operator cannot pair them", warnFP, debugFP)
				}
				// The confidentiality assertion proper: no record at any level
				// carries the text, an excerpt of it, or the unsafe rune.
				for _, r := range records.Records() {
					if !strings.Contains(r.Message, unrecognizedNotifyMsg) {
						continue
					}
					r.Attrs(func(a slog.Attr) bool {
						got := a.Value.String()
						switch {
						case strings.Contains(got, "evilwording"):
							t.Errorf("%s record attr %q = %q carries the notification text with WT_LOG_OSC_TEXT off; arbitrary child output may be a token or a device code, and the log store outlives and out-queries the PTY scrollback", r.Level, a.Key, got)
						case strings.Contains(got, unsafeRune):
							t.Errorf("%s record attr %q = %q carries U+202E; the engine must sanitize notification text before the classifier sees it", r.Level, a.Key, got)
						}
						return true
					})
				}
				// Any excerpt of the notification, however short, and wherever it
				// lands: the 11-rune "evilwording" needle above misses a short
				// prefix, and a device code fits in 9 characters.
				if logContains(records, "evil") {
					t.Errorf("log = %q carries a prefix of the notification text with WT_LOG_OSC_TEXT off; "+
						"arbitrary child output may be a token or a device code", records.Messages())
				}
				assertAttrSchema(t, records, slog.LevelWarn, unrecognizedNotifyMsg, map[string]attrCheck{
					"message_fingerprint": isNotifyFingerprint,
					"message_runes":       wantInt(len([]rune(wantFull))),
					"hint":                wantString(unrecognizedNotifyHint),
				})
				assertAttrSchema(t, records, slog.LevelDebug, unrecognizedNotifyMsg, map[string]attrCheck{
					"message_fingerprint": isNotifyFingerprint,
					"message_runes":       wantInt(len([]rune(wantFull))),
				})
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("no unrecognized-notification record pair reached the log (warn=%v debug=%v); log = %q", haveWarn, haveDebug, records.Messages())
			}
			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Run("opt-in logs the sanitized full text at debug only", func(t *testing.T) {
		records := capture.Default(t)
		deps := newTestDeps(true)
		deps.logOSCText = true // WT_LOG_OSC_TEXT=true
		deps.cmd = staticCmd("/bin/sh", "-c", `printf '\033]9;`+emitted+`\a'; exec cat`)
		mustStartSession(t, deps)

		deadline := time.Now().Add(10 * time.Second)
		for {
			full, haveText, haveDebug := attrOf(records, slog.LevelDebug, "message")
			_, _, haveWarn := attrOf(records, slog.LevelWarn, "message_fingerprint")
			if haveDebug && haveWarn {
				if !haveText {
					t.Fatalf("Debug record carries no message attr with WT_LOG_OSC_TEXT on; the opt-in exists to make the text recoverable after a kiro-cli wording bump; log = %q", records.Messages())
				}
				// The opt-in ADDS the text; it does not trade the correlation key
				// away for it. The Warn is what sends an operator here, and with a
				// warn budget of unrecognizedNotifyCap distinct wordings several
				// Warn/Debug pairs can be in flight at once, so without a shared
				// fingerprint the logged text cannot be attributed to the wording
				// that warned and the wrong classifier string gets updated.
				warnFP, haveWarnFP, _ := attrOf(records, slog.LevelWarn, "message_fingerprint")
				debugFP, haveDebugFP, _ := attrOf(records, slog.LevelDebug, "message_fingerprint")
				if !haveDebugFP {
					t.Errorf("Debug record carries no message_fingerprint with WT_LOG_OSC_TEXT on; the opt-in must ADD the text to the default record, not replace the key that pairs it with its Warn")
				} else if haveWarnFP && warnFP != debugFP {
					t.Errorf("Warn message_fingerprint = %q but Debug = %q; one classifier instance must stamp both records identically or an operator cannot pair them", warnFP, debugFP)
				}
				// COMPLETE, not truncated: recovering the whole wording is the only
				// reason to accept the exposure.
				if full != wantFull {
					t.Errorf("Debug message = %q, want the COMPLETE sanitized notification %q", full, wantFull)
				}
				if strings.Contains(full, unsafeRune) {
					t.Errorf("Debug message = %q carries U+202E; the engine must sanitize notification text before the classifier logs it, or arbitrary child output can inject into the log stream", full)
				}
				// The opt-in widens Debug ONLY. The always-on stream stays
				// content-free whatever the switch says.
				if warnText, haveWarnText, _ := attrOf(records, slog.LevelWarn, "message"); haveWarnText {
					t.Errorf("Warn record carries a message attr (%q) with WT_LOG_OSC_TEXT on; notification content must never reach the default stream, which is what makes the opt-in bounded", warnText)
				}
				for _, r := range records.Records() {
					if r.Level != slog.LevelWarn || !strings.Contains(r.Message, unrecognizedNotifyMsg) {
						continue
					}
					r.Attrs(func(a slog.Attr) bool {
						if strings.Contains(a.Value.String(), "evilwording") {
							t.Errorf("Warn record attr %q = %q carries the notification text; the opt-in must widen Debug only", a.Key, a.Value.String())
						}
						return true
					})
				}
				assertAttrSchema(t, records, slog.LevelWarn, unrecognizedNotifyMsg, map[string]attrCheck{
					"message_fingerprint": isNotifyFingerprint,
					"message_runes":       wantInt(len([]rune(wantFull))),
					"hint":                wantString(unrecognizedNotifyHint),
				})
				// The opt-in adds exactly one attr, and it must be the COMPLETE
				// sanitized text: pinning message to wantFull here is what stops a
				// truncated or re-encoded excerpt from passing as "the text".
				assertAttrSchema(t, records, slog.LevelDebug, unrecognizedNotifyMsg, map[string]attrCheck{
					"message_fingerprint": isNotifyFingerprint,
					"message_runes":       wantInt(len([]rune(wantFull))),
					"message":             wantString(wantFull),
				})
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("no unrecognized-notification records reached the log (warn=%v debug=%v); log = %q", haveWarn, haveDebug, records.Messages())
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

// TestNotifyWarningState_concurrentObserveHonoursTheBudget pins the
// SYNCHRONIZATION of the warn budget, which every other classifier test
// exercises single-threaded. registerRoutes wires ONE classifier into
// terminal.NewSessionManager, and the engine calls it from every session's own
// event goroutine, so observe's seen-set is shared mutable state across tabs.
// Nothing asserted that: removing the mutex keeps the whole suite green while a
// container with a few busy tabs takes a "concurrent map writes" fatal error --
// unrecoverable, so every session dies at once -- and the budget itself stops
// holding (more than unrecognizedNotifyCap first-occurrence Warn decisions, or a
// second budget-exhausted announcement).
//
// Counting observe's DECISIONS rather than the emitted records keeps this on the
// method's own contract, so it needs no logger capture and no serial execution.
// The rounds loop is the confidence knob, not decoration: one round of
// unsynchronized writes escapes detection often enough to be useless as a gate
// (measured: 2 of 6 runs failed at one round), while 50 rounds failed 6 of 6 and
// still costs ~10ms. Red-green verified against a mutated copy of routes.go with
// the lock removed.
func TestNotifyWarningState_concurrentObserveHonoursTheBudget(t *testing.T) {
	const (
		distinct   = unrecognizedNotifyCap * 4 // more distinct wordings than the budget
		perMessage = 8                         // several tabs report the same wording at once
		rounds     = 50                        // see the doc comment: the confidence knob
	)
	for range rounds {
		state := notifyWarningState{warned: make(map[string]struct{}, unrecognizedNotifyCap)}
		var warnFirsts, warnCappeds atomic.Int64
		var release, finished sync.WaitGroup
		release.Add(1)
		for i := range distinct {
			for range perMessage {
				finished.Add(1)
				go func(i int) {
					defer finished.Done()
					release.Wait() // start every caller at once, so the writes really overlap
					warnFirst, warnCapped := state.observe(fmt.Sprintf("wording variant %d", i))
					if warnFirst {
						warnFirsts.Add(1)
					}
					if warnCapped {
						warnCappeds.Add(1)
					}
				}(i)
			}
		}
		release.Done()
		finished.Wait()

		if got := warnFirsts.Load(); got != unrecognizedNotifyCap {
			t.Fatalf("first-occurrence Warn decisions = %d, want exactly %d (the cap); a duplicate means one wording warns twice, a shortfall means a wording never warns", got, unrecognizedNotifyCap)
		}
		if got := warnCappeds.Load(); got != 1 {
			t.Fatalf("budget-exhausted Warn decisions = %d, want exactly 1 (announced once, whatever the concurrency)", got)
		}
		if got := len(state.warned); got != unrecognizedNotifyCap {
			t.Fatalf("seen-set size = %d, want %d; the set is keyed by child output, so exceeding the cap is an unbounded-memory path", got, unrecognizedNotifyCap)
		}
	}
}

// TestNotifyWarningState_capRearms pins the re-arm window on the budget-exhausted
// announcement: suppressed inside unrecognizedNotifyCapRearm, fired again once the
// window has elapsed. Reverting lastCapWarn to the old once-per-process bool keeps
// every other test in this file green (the cap-count assertion holds under BOTH
// semantics), so this is the only pin on the behavior the re-arm exists for -- a
// kiro-cli rewording that begins AFTER exhaustion still reaching the default log
// stream. observe() is directly constructible in-package with a backdatable
// lastCapWarn, so no production seam is needed and no clock is faked.
func TestNotifyWarningState_capRearms(t *testing.T) {
	s := &notifyWarningState{warned: make(map[string]struct{})}
	for i := range unrecognizedNotifyCap {
		if first, capped := s.observe(fmt.Sprintf("wording %d", i)); !first || capped {
			t.Fatalf("observe(wording %d) = (%t, %t), want (true, false) while budget remains", i, first, capped)
		}
	}
	if first, capped := s.observe("overflow a"); first || !capped {
		t.Fatalf("first turned-away message = (%t, %t), want (false, true): exhaustion is announced", first, capped)
	}
	if first, capped := s.observe("overflow b"); first || capped {
		t.Fatalf("second turned-away message inside the window = (%t, %t), want (false, false): announcement suppressed", first, capped)
	}
	s.mu.Lock()
	s.lastCapWarn = time.Now().Add(-unrecognizedNotifyCapRearm - time.Minute)
	s.mu.Unlock()
	if first, capped := s.observe("overflow c"); first || !capped {
		t.Fatalf("turned-away message after the window = (%t, %t), want (false, true): the announcement re-arms", first, capped)
	}
}
