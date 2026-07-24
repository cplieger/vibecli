package main

import (
	"log/slog"
	"testing"

	"github.com/cplieger/slogx/capture"
)

// TestSessionLoggerRedactsCommand pins the credential boundary around the
// per-session logger wired in registerRoutes' factory: web-terminal-engine
// logs the session's argv as the "command" attr when the child process
// starts (Handler.ensureStarted), and deps.cmd carries the operator's
// KIRO_CLI_CHAT_ARGS values — a value-bearing flag there could hold a
// credential from a compose interpolation mistake (CWE-532). The factory
// therefore passes terminal.WithCommandLogValue("[redacted]"); this test
// runs a real session with a secret-looking chat arg and proves neither the
// secret nor the argv reaches the captured log stream, while the "command"
// key survives as the redaction placeholder. It is the end-to-end leak gate
// for the engine coupling: an engine bump that renames the attr, moves the
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
	// expands, and `exec cat` keeps the process alive until manager shutdown
	// so the fast-death Warn path stays out of this test's way.
	deps.cmd = []string{"/bin/sh", "-c", "exec cat", "sh", "--token=" + secret}
	_, mgr, _ := mustRegisterRoutes(t, deps)
	if _, err := mgr.Create(); err != nil {
		t.Fatalf("Create: %v", err)
	}

	var command string
	sawCommandAttr := false
	for _, r := range records.Records() {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "command" {
				command = a.Value.String()
				sawCommandAttr = true
				return false
			}
			return true
		})
	}
	if !sawCommandAttr {
		t.Fatalf("no captured record carries a command attr; log = %q (want the engine's process-start record)", records.Messages())
	}
	if command != "[redacted]" {
		t.Errorf("command attr = %q, want %q (the key survives as a launch marker; the argv value must be withheld)", command, "[redacted]")
	}
	if logContains(records, secret) {
		t.Error("captured log carries the secret-looking chat arg; KIRO_CLI_CHAT_ARGS values must never reach the log stream")
	}
	if logContains(records, "/bin/sh") {
		t.Error("captured log carries the session argv; the full command slice must stay out of the log stream")
	}
}
