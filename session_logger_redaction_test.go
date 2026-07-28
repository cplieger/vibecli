package main

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/cplieger/slogx/capture"
	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

// TestSessionLoggerRedactsCommand pins the credential boundary around the
// per-session logger wired in registerRoutes' factory: web-terminal-engine
// logs the session's argv as the "command" attr when the child process
// starts (Handler.ensureStarted), and deps.cmd carries the operator's
// KIRO_CLI_CHAT_ARGS values — a value-bearing flag there could hold a
// credential from a compose interpolation mistake (CWE-532). The factory
// therefore passes terminal.WithCommandLogValue("[redacted]"); this test runs
// a real session with a secret-looking chat arg and proves neither the secret
// nor the argv reaches the captured log stream, while the "command" key
// survives as the redaction placeholder. It is the end-to-end leak gate for
// the engine coupling: an engine bump that renames the attr, moves the
// emission site, or drops the option's effect fails here on the Renovate PR.
//
// Synchronization: Create starts the child eagerly (StartEager →
// ensureStarted), which emits the process-start record synchronously, so the
// capture already holds it when Create returns — no polling needed.
// Serial: capture.Default mutates the process-global default logger, and the
// factory binds its session logger from slog.Default() at Create time (no
// t.Parallel).
func TestSessionLoggerRedactsCommand(t *testing.T) {
	const secret = "chat-arg-hunter2-sekret"
	records := capture.Default(t)
	deps := newTestDeps(true)
	// The trailing args model KIRO_CLI_CHAT_ARGS values riding sessionCommand's
	// positional params; /bin/sh -c ignores extra positional params it never
	// expands, and `exec cat` keeps the process alive until manager shutdown so
	// the fast-death Warn path stays out of the assertions below. The teardown
	// KILL does trip that hook (readiness is still set), so quietTeardown clears
	// readiness first -- the contract every test leaving a live session owes the
	// next test's log capture.
	deps.cmd = []string{"/bin/sh", "-c", "exec cat", "sh", "--token=" + secret}
	_, mgr, _ := mustRegisterRoutes(t, deps)
	if _, err := mgr.Create(); err != nil {
		t.Fatalf("Create: %v", err)
	}
	quietTeardown(t, deps)

	// EVERY command attr must be the placeholder, not merely the last one
	// seen: a record carrying the real argv anywhere in the stream is the leak.
	sawCommandAttr := false
	for _, r := range records.Records() {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key != "command" {
				return true
			}
			sawCommandAttr = true
			if got := a.Value.String(); got != "[redacted]" {
				t.Errorf("command attr = %q, want %q (the key survives as a launch marker; the argv value must be withheld)", got, "[redacted]")
			}
			return true
		})
	}
	if !sawCommandAttr {
		t.Fatalf("no captured record carries a command attr; log = %q (want the engine's process-start record)", records.Messages())
	}
	if logContains(records, secret) {
		t.Error("captured log carries the secret-looking chat arg; KIRO_CLI_CHAT_ARGS values must never reach the log stream")
	}
	if logContains(records, "/bin/sh") {
		t.Error("captured log carries the session argv; the full command slice must stay out of the log stream")
	}
}

// TestSessionLoggerTruncatesSessionID pins the OTHER half of the session
// logger's credential boundary: the session id doubles as the /ws attach and
// resume capability token, so the factory binds only terminal.LogID's
// truncated form. Without this test the truncation could be widened or
// dropped and nothing would fail — the exact silent-drift class a fleet audit
// found live in the sibling app, which logged whole tokens.
//
// Serial for the same reason as the test above (process-global default logger).
func TestSessionLoggerTruncatesSessionID(t *testing.T) {
	records := capture.Default(t)
	deps := newTestDeps(true)
	deps.cmd = []string{"/bin/sh", "-c", "exec cat"}
	_, mgr, _ := mustRegisterRoutes(t, deps)
	id, err := mgr.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	quietTeardown(t, deps)
	if len(id) <= 8 {
		t.Fatalf("session id %q is too short to exercise truncation", id)
	}

	if logContains(records, id) {
		t.Errorf("captured log carries the FULL session id %q; it is the /ws resume capability token and must never be logged whole (CWE-532)", id)
	}

	// An app-side ceiling on how much of the token may be logged, independent of
	// LogID: the equality assertion below is derived from LogID itself, so it
	// accepts a WIDENED truncation. The id is 128-bit crypto-random hex; logging
	// 24 of its 32 digits would leave 32 bits to brute-force against /ws?session=.
	// 12 leaves headroom above LogID's 8 so this is not a restatement of the
	// current engine constant.
	const maxLoggedIDChars = 12
	if logContains(records, id[:maxLoggedIDChars]) {
		t.Errorf("captured log carries the first %d characters of session id %q; at most "+
			"terminal.LogID's 8-digit prefix may be logged, or the /ws resume token loses "+
			"brute-force entropy (CWE-532)", maxLoggedIDChars, id)
	}

	want := terminal.LogID(id)
	var sawSession bool
	for _, r := range records.Records() {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key != "session" {
				return true
			}
			sawSession = true
			if got := a.Value.String(); got != want {
				t.Errorf("session attr = %q, want the engine's LogID form %q (every record's session attr must be truncated, not just the first)", got, want)
			}
			return true
		})
	}
	if !sawSession {
		t.Fatalf("no captured record carries a session attr; log = %q", records.Messages())
	}
	if !strings.HasPrefix(id, strings.TrimSuffix(want, "\u2026")) {
		t.Errorf("LogID(%q) = %q, which is not a prefix of the id (correlation would break)", id, want)
	}
}
