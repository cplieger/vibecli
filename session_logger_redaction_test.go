package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/cplieger/slogx/capture"
)

// TestSessionLoggerRedactsCommand pins the credential boundary around the
// per-session logger wired in registerRoutes' factory: web-terminal-engine
// (v3.0.4) logs the session's full argv as the "command" attr when the child
// process starts (Handler.ensureStarted), and deps.cmd carries the operator's
// KIRO_CLI_CHAT_ARGS values — a value-bearing flag there could hold a
// credential from a compose interpolation mistake (CWE-532). The factory
// therefore routes the engine's logger through commandRedactingHandler; this
// test runs a real session with a secret-looking chat arg and proves neither
// the secret nor the argv reaches the captured log stream, while the
// "command" key survives as the redaction placeholder.
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
	if command != commandRedacted {
		t.Errorf("command attr = %q, want %q (the key survives as a launch marker; the argv value must be withheld)", command, commandRedacted)
	}
	if logContains(records, secret) {
		t.Error("captured log carries the secret-looking chat arg; KIRO_CLI_CHAT_ARGS values must never reach the log stream")
	}
	if logContains(records, "/bin/sh") {
		t.Error("captured log carries the session argv; the full command slice must stay out of the log stream")
	}
}

// TestCommandRedactingHandler_redactsPreBoundCommandAttr pins the WithAttrs
// redaction leg: a "command" attr pre-bound via Logger.With never flows
// through Handle's record clone, so WithAttrs must redact it eagerly before
// delegating, and non-command attrs must survive untouched.
func TestCommandRedactingHandler_redactsPreBoundCommandAttr(t *testing.T) {
	const secret = "with-attrs-hunter2-sekret"
	var buf bytes.Buffer
	logger := slog.New(commandRedactingHandler{slog.NewTextHandler(&buf, nil)}).
		With("command", secret, "session", "abc12345")
	logger.Info("process started")

	out := buf.String()
	if !strings.Contains(out, commandRedacted) {
		t.Errorf("log = %q, want the %q placeholder for a pre-bound command attr", out, commandRedacted)
	}
	if strings.Contains(out, secret) {
		t.Errorf("log = %q; a command attr pre-bound via Logger.With must be redacted before it reaches the inner handler", out)
	}
	if !strings.Contains(out, "session=abc12345") {
		t.Errorf("log = %q, want the non-command attr to survive untouched", out)
	}
}

// TestCommandRedactingHandler_redactionSurvivesWithGroup pins the WithGroup
// rewrap: a handler derived via WithGroup must keep redacting subsequent
// records' "command" attrs, or a grouped engine logger would leak the argv.
func TestCommandRedactingHandler_redactionSurvivesWithGroup(t *testing.T) {
	const secret = "grouped-hunter2-sekret"
	var buf bytes.Buffer
	logger := slog.New(commandRedactingHandler{slog.NewTextHandler(&buf, nil)}).
		WithGroup("engine")
	logger.Info("process started", "command", secret)

	out := buf.String()
	if !strings.Contains(out, commandRedacted) {
		t.Errorf("log = %q, want the %q placeholder for a command attr logged under a group", out, commandRedacted)
	}
	if strings.Contains(out, secret) {
		t.Errorf("log = %q; redaction must survive a WithGroup-derived handler or a grouped engine logger leaks the argv", out)
	}
}
