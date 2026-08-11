package main

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

// This file pins what this app decides about retained-history depth, which after
// 2026-08 is deliberately NOTHING: the session factory omits
// terminal.WithScrollbackCapacity so the engine's own default applies, and an
// operator overrides it per deployment through the env var the ENGINE names.
//
// It used to pin a literal wired into registerRoutes (5000, then 20000). That was
// the wrong thing to guard: the depth is a sizing decision shared by this app,
// web-terminal-server and vibekit, so a number here made it three numbers that
// drift, and the test only asserted that someone had typed the same digits twice.
// What is worth guarding is the PLUMBING — that the app adds no opinion of its
// own, that the shared variable actually reaches the ring, and that the one
// adjustment made to an operator's number is the engine's rather than a local
// copy of the threshold.
//
// THE SHAPE OF THESE ASSERTIONS IS LOAD-BEARING. An early version of the literal
// test was VACUOUS: it emitted 2500 lines and asserted oldest == 0, so ANY
// capacity above ~2500 passed. So each case emits PAST the capacity it expects,
// making eviction observable, and asserts committed-oldest EXACTLY. Red-check any
// change by editing the factory and confirming the failure.

// retainedLines drives the production session factory with the given deps,
// emits `emitted` lines, and returns the retention the ring settled on
// (committed - oldest) once enough lines have been committed to make eviction
// observable.
func retainedLines(t *testing.T, scrollback *int, emitted, awaitCommitted int) uint64 {
	t.Helper()
	deps := newTestDeps(true)
	deps.scrollback = scrollback
	deps.cmd = staticCmd("/bin/sh", "-c", fmt.Sprintf(
		`i=1; while [ $i -le %d ]; do echo "line $i"; i=$((i+1)); done; exec cat`, emitted))

	h := newSessionFactory(deps)("scrollback-probe")
	if err := h.StartEager(); err != nil {
		t.Fatalf("StartEager: %v", err)
	}
	t.Cleanup(h.Shutdown)

	deadline := time.Now().Add(60 * time.Second)
	for {
		committed, oldest := h.ScrollbackBounds()
		if committed >= uint64(awaitCommitted) { // #nosec G115 -- test-controlled line counts
			return committed - oldest
		}
		if time.Now().After(deadline) {
			t.Fatalf("scrollback never committed %d lines (committed=%d oldest=%d); the child must emit %d",
				awaitCommitted, committed, oldest, emitted)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestSessionScrollbackUsesTheEngineDefault pins that this app adds no depth of
// its own: with no operator override the ring retains exactly what the engine
// documents. A reintroduced local WithScrollbackCapacity fails here, in either
// direction, without this test naming the number.
func TestSessionScrollbackUsesTheEngineDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("emits >100k lines through a PTY")
	}
	want := uint64(terminal.DefaultScrollbackCapacity) // #nosec G115 -- a positive constant
	// Emit past the ceiling so eviction is observable, and wait until enough
	// lines are evicted that committed-oldest IS the capacity.
	got := retainedLines(t, nil,
		terminal.DefaultScrollbackCapacity+1000,
		terminal.DefaultScrollbackCapacity+400)
	if got != want {
		t.Errorf("retained %d lines with no override, want exactly %d (the engine default must reach the ring untouched)",
			got, want)
	}
}

// TestSessionScrollbackHonoursTheSharedEnvVar pins the override end to end: the
// variable the ENGINE names, read by this app's composition root, reaching the
// ring the session factory builds. The value is small enough to keep the test
// quick and still above the paging floor so the clamp does not rewrite it.
func TestSessionScrollbackHonoursTheSharedEnvVar(t *testing.T) {
	const capacity = 6000
	if capacity <= terminal.MinPagingCapacity {
		t.Fatalf("fixture must stay above the paging floor (%d) or the clamp rewrites it", terminal.MinPagingCapacity)
	}
	t.Setenv(terminal.ScrollbackEnvVar, strconv.Itoa(capacity))
	scrollback := resolveScrollback()
	if scrollback == nil || *scrollback != capacity {
		t.Fatalf("resolveScrollback() = %v, want %d", scrollback, capacity)
	}
	if got := retainedLines(t, scrollback, capacity+500, capacity+200); got != capacity {
		t.Errorf("retained %d lines, want exactly %d from %s", got, capacity, terminal.ScrollbackEnvVar)
	}
}

// TestResolveScrollback pins the operator-facing read of the shared
// retained-history knob: the depth it returns AND what it puts in the log. The
// log half is what nothing else covers, and it is a house rule rather than a
// preference — TRUSTED_PROXIES (count only), KIRO_CLI_CHAT_ARGS (flag count),
// KWEB_LOG_LEVEL, KWEB_LOG_OSC_TEXT and TOOL_CATALOG_REFRESH are all read
// by-name-only because a compose expansion mistake can put a credential on any
// key (CWE-532), and the last two each carry a test saying so. Four properties:
//
//   - absent and blank fall through to the engine default, and do so SILENTLY: a
//     warning on the path every deployment that never set the knob takes is a
//     line on every boot forever;
//   - a malformed value falls through with exactly ONE Warn, which names the key
//     and carries no copy of the raw value in its message or in any attribute;
//   - a value the ENGINE clamps keeps the engine's own warning, which does quote
//     the number — deliberately, because it already parsed as an integer and so
//     cannot be the secret this rule protects;
//   - the returned depth is the engine's verdict, never a local copy of the
//     threshold.
//
// Serial: capture.Default mutates the process-global default logger, and
// t.Setenv forbids t.Parallel anyway.
func TestResolveScrollback(t *testing.T) {
	const token = "s3cr3t-token-abc123"
	tests := []struct {
		name      string
		raw       string
		absent    bool // the variable is not in the environment at all
		want      *int // nil = the option is omitted and the engine default applies
		wantWarns int
		// rawMustStayOut asks for the confidentiality assertion. It is set only
		// for values distinctive enough that finding one in the log PROVES a
		// leak; a bare number occurs in these warnings by design.
		rawMustStayOut bool
	}{
		{name: "absent falls through to the engine default in silence", absent: true, want: nil},
		{name: "blank is not a number and must not disable history", raw: "   ", want: nil},
		{name: "malformed warns by name and falls through", raw: "lots", want: nil, wantWarns: 1, rawMustStayOut: true},
		// The shape that motivates the rule: a compose interpolation that lands a
		// credential on this key must not put it in the log store.
		{name: "a token-shaped value cannot reach the log", raw: token, want: nil, wantWarns: 1, rawMustStayOut: true},
		{name: "a plain depth is honoured", raw: "40000", want: new(40000)},
		// 0 is the operator saying "retain nothing beyond the live screen", and it
		// is the one shallow value the clamp leaves alone: a client cannot page
		// against a server holding no history, so the inverted outcome the clamp
		// exists to prevent cannot arise.
		{name: "zero disables history and is passed through", raw: "0", want: new(0)},
		// The awkward middle: honoured by the ring, too shallow for the engine to
		// offer paging, and the browser's fallback then retains MORE than the
		// operator asked to save. Clamped up by the ENGINE, whose warning quotes
		// the number it was given.
		{name: "below the paging floor clamps up and the engine says so", raw: "2000", want: new(terminal.MinPagingCapacity), wantWarns: 1},
		// No upper bound: an absurd number is how this family spells "never
		// truncate", and the engine's ring allocates only what it fills.
		{name: "an absurd depth is honoured as given", raw: "50000000", want: new(50_000_000)},
		{name: "negative is not reachable via the ring and reads as disabled", raw: "-5", want: new(0), wantWarns: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			records := capture.Default(t)
			// t.Setenv first either way: it records the pre-test value and
			// restores it at cleanup, so the Unsetenv below is safe.
			t.Setenv(terminal.ScrollbackEnvVar, tc.raw)
			if tc.absent {
				if err := os.Unsetenv(terminal.ScrollbackEnvVar); err != nil {
					t.Fatalf("Unsetenv(%s): %v", terminal.ScrollbackEnvVar, err)
				}
			}

			got := resolveScrollback()
			switch {
			case tc.want == nil && got != nil:
				t.Errorf("resolveScrollback() = %d, want unset (the engine default)", *got)
			case tc.want != nil && got == nil:
				t.Errorf("resolveScrollback() = unset, want %d", *tc.want)
			case tc.want != nil && got != nil && *got != *tc.want:
				t.Errorf("resolveScrollback() = %d, want %d", *got, *tc.want)
			}
			if n := records.CountLevel(slog.LevelWarn, ""); n != tc.wantWarns {
				t.Errorf("log = %q, want exactly %d Warn (got %d)", records.Messages(), tc.wantWarns, n)
			}
			if tc.rawMustStayOut && logContains(records, tc.raw) {
				t.Errorf("log = %q carries the raw %s value; a compose expansion mistake can put a credential on this key, so a rejected value must be warned about by NAME only",
					records.Messages(), terminal.ScrollbackEnvVar)
			}
		})
	}
}
