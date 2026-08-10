package main

import (
	"fmt"
	"strconv"
	"testing"
	"time"

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

// TestResolveScrollback covers the env reading itself, including the two shapes
// with counter-intuitive outcomes.
func TestResolveScrollback(t *testing.T) {
	tests := []struct {
		name string
		raw  string // "" means the variable is not set at all
		want *int   // nil = the option is omitted and the engine default applies
	}{
		{name: "unset falls through to the engine default", raw: "", want: nil},
		{name: "blank is not a number and must not disable history", raw: "   ", want: nil},
		{name: "malformed warns and falls through", raw: "lots", want: nil},
		{name: "a plain depth is honoured", raw: "40000", want: new(40000)},
		// 0 is the operator saying "retain nothing beyond the live screen", and it
		// is the one shallow value the clamp leaves alone: a client cannot page
		// against a server holding no history, so the inverted outcome the clamp
		// exists to prevent cannot arise.
		{name: "zero disables history and is passed through", raw: "0", want: new(0)},
		// The awkward middle: honoured by the ring, too shallow for the engine to
		// offer paging, and the browser's fallback then retains MORE than the
		// operator asked to save. Clamped up by the ENGINE, not by this app.
		{name: "below the paging floor clamps up", raw: "2000", want: new(terminal.MinPagingCapacity)},
		// No upper bound: an absurd number is how this family spells "never
		// truncate", and the engine's ring allocates only what it fills.
		{name: "an absurd depth is honoured as given", raw: "50000000", want: new(50_000_000)},
		{name: "negative is not reachable via the ring and reads as disabled", raw: "-5", want: new(0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.raw != "" {
				t.Setenv(terminal.ScrollbackEnvVar, tc.raw)
			} else {
				t.Setenv(terminal.ScrollbackEnvVar, "")
			}
			got := resolveScrollback()
			switch {
			case tc.want == nil && got != nil:
				t.Errorf("resolveScrollback() = %d, want unset (engine default)", *got)
			case tc.want != nil && got == nil:
				t.Errorf("resolveScrollback() = unset, want %d", *tc.want)
			case tc.want != nil && got != nil && *got != *tc.want:
				t.Errorf("resolveScrollback() = %d, want %d", *got, *tc.want)
			}
		})
	}
}
